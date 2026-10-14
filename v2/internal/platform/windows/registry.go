//go:build windows

package windows

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	advapi32          = windows.NewLazySystemDLL("advapi32.dll")
	pRegOpenKeyEx     = advapi32.NewProc("RegOpenKeyExW")
	pRegSaveKeyEx     = advapi32.NewProc("RegSaveKeyExW")
	pRegCloseKey      = advapi32.NewProc("RegCloseKey")
	hkeyLocalMachine  = uintptr(0x80000002)
	hkeyUsers         = uintptr(0x80000003)
	regOptionBackup   = uintptr(0x4) // REG_OPTION_BACKUP_RESTORE: honours SeBackupPrivilege
	regLatestFormat   = uintptr(0x2)
	keyReadAccess     = uintptr(0x20019)
	maxRegValueBytes  = 1 << 20
	maxRegKeysPerDump = 120000
)

// ---- structured registry dumps ----

type regValueDump struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Size       int      `json:"size"`
	Text       string   `json:"text,omitempty"`
	Strings    []string `json:"strings,omitempty"`
	Number     *uint64  `json:"number,omitempty"`
	DataBase64 string   `json:"data_base64,omitempty"`
	Truncated  bool     `json:"truncated,omitempty"`
	Redacted   bool     `json:"redacted,omitempty"`
}

type regKeyDump struct {
	Path         string         `json:"path"`
	LastWriteUTC string         `json:"last_write_utc,omitempty"`
	Values       []regValueDump `json:"values,omitempty"`
	Error        string         `json:"error,omitempty"`
}

type regTarget struct {
	Root      registry.Key
	RootName  string // "HKLM", "HKU\\S-1-5-21-..."
	Path      string
	Recursive bool
	MaxDepth  int // 0: unlimited (bounded by key limit)
	View      uint32
	NameOnly  []string               // when set, only these value names are recorded
	NamesOnly bool                   // record value names, types and sizes but not their data
	Include   func(path string) bool // when set, only keys whose path satisfies it are recorded (subkeys are still traversed)
}

func (t regTarget) display() string { return t.RootName + `\` + t.Path }

var regTypeNames = map[uint32]string{0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN",
	6: "REG_LINK", 7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST", 9: "REG_FULL_RESOURCE_DESCRIPTOR", 10: "REG_RESOURCE_REQUIREMENTS_LIST", 11: "REG_QWORD"}

func utf16Bytes(b []byte) []uint16 {
	n := len(b) / 2
	out := make([]uint16, n)
	for i := 0; i < n; i++ {
		out[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return out
}

func readValue(k registry.Key, name string) (regValueDump, error) {
	size, vt, err := k.GetValue(name, nil)
	if err != nil {
		return regValueDump{}, err
	}
	d := regValueDump{Name: name, Type: regTypeNames[vt], Size: size}
	if d.Type == "" {
		d.Type = fmt.Sprintf("REG_%d", vt)
	}
	read := size
	if read > maxRegValueBytes {
		read, d.Truncated = maxRegValueBytes, true
	}
	buf := make([]byte, size) // GetValue requires the full size
	if size > 0 {
		if _, _, err := k.GetValue(name, buf); err != nil {
			return d, err
		}
	}
	buf = buf[:read]
	switch vt {
	case registry.SZ, registry.EXPAND_SZ:
		d.Text = strings.TrimRight(string(utf16.Decode(utf16Bytes(buf))), "\x00")
	case registry.MULTI_SZ:
		parts := strings.Split(string(utf16.Decode(utf16Bytes(buf))), "\x00")
		for len(parts) > 0 && parts[len(parts)-1] == "" {
			parts = parts[:len(parts)-1]
		}
		d.Strings = parts
	case registry.DWORD:
		if len(buf) >= 4 {
			v := uint64(binary.LittleEndian.Uint32(buf))
			d.Number = &v
		}
	case registry.QWORD:
		if len(buf) >= 8 {
			v := binary.LittleEndian.Uint64(buf)
			d.Number = &v
		}
	}
	if len(buf) > 0 {
		d.DataBase64 = base64.StdEncoding.EncodeToString(buf)
	}
	return d, nil
}

// dumpTarget records the values (and optionally subkeys) of one registry location.
func dumpTarget(t regTarget, w *warnings, out *[]regKeyDump) bool {
	return dumpTargetCtx(context.Background(), t, w, out)
}

// dumpTargetCtx is dumpTarget with cancellation. The key limit applies to each target separately
// and counts every visited key, recorded or not.
func dumpTargetCtx(ctx context.Context, t regTarget, w *warnings, out *[]regKeyDump) bool {
	access := uint32(registry.READ) | t.View
	k, err := registry.OpenKey(t.Root, t.Path, access)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) || errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
			return false
		}
		w.add("%s: %v", t.display(), err)
		return false
	}
	defer k.Close()
	visited := 0
	var walk func(k registry.Key, rel string, depth int)
	walk = func(k registry.Key, rel string, depth int) {
		if ctx.Err() != nil {
			return
		}
		if visited >= maxRegKeysPerDump {
			if visited == maxRegKeysPerDump {
				w.add("%s: key limit (%d) reached; enumeration truncated", t.display(), maxRegKeysPerDump)
				visited++
			}
			return
		}
		visited++
		kd := regKeyDump{Path: t.RootName + `\` + rel}
		record := t.Include == nil || t.Include(kd.Path)
		if info, err := k.Stat(); err == nil {
			kd.LastWriteUTC = info.ModTime().UTC().Format(time.RFC3339Nano)
		}
		var names []string
		var err error
		if record {
			names, err = k.ReadValueNames(-1)
		}
		if err != nil {
			kd.Error = err.Error()
			w.add("%s: list values: %v", kd.Path, err)
		}
		for _, n := range names {
			if len(t.NameOnly) > 0 && !containsFold(t.NameOnly, n) {
				continue
			}
			if t.NamesOnly || sensitiveValueName(n) {
				size, vt, err := k.GetValue(n, nil)
				if err != nil {
					w.add("%s: value %q: %v", kd.Path, n, err)
					continue
				}
				tn := regTypeNames[vt]
				if tn == "" {
					tn = fmt.Sprintf("REG_%d", vt)
				}
				kd.Values = append(kd.Values, regValueDump{Name: n, Type: tn, Size: size, Redacted: true})
				continue
			}
			v, err := readValue(k, n)
			if err != nil {
				w.add("%s: value %q: %v", kd.Path, n, err)
				continue
			}
			kd.Values = append(kd.Values, v)
		}
		if record && len(names) == 0 {
			// default value only
			if v, err := readValue(k, ""); err == nil {
				kd.Values = append(kd.Values, v)
			}
		}
		if record {
			*out = append(*out, kd)
		}
		if !t.Recursive || (t.MaxDepth > 0 && depth >= t.MaxDepth) {
			return
		}
		subs, err := k.ReadSubKeyNames(-1)
		if err != nil {
			w.add("%s: list subkeys: %v", kd.Path, err)
			return
		}
		for _, s := range subs {
			sk, err := registry.OpenKey(k, s, access)
			if err != nil {
				w.add("%s\\%s: %v", kd.Path, s, err)
				continue
			}
			walk(sk, rel+`\`+s, depth+1)
			sk.Close()
		}
	}
	walk(k, t.Path, 0)
	return true
}

// sensitiveValueName flags registry value names that commonly hold reusable secrets (for example the
// plaintext DefaultPassword of an AutoAdminLogon setup). Their data is not written to the package;
// name, type and size are kept so the presence of the secret is still evidence.
func sensitiveValueName(name string) bool {
	l := strings.ToLower(name)
	return strings.Contains(l, "password") || strings.Contains(l, "secret") || strings.Contains(l, "token") || strings.Contains(l, "credential")
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// regSnapshotSource dumps registry locations into one structured document. Locations
// that do not exist are reported as warnings; if none exist the source is not_present.
func regSnapshotSource(id string, m collector.Meta, locator string, targets func() []regTarget) collector.Source {
	m.SourceType = "registry"
	s := jsonSource(id, m, "registry-api-dump", locator, func(ctx context.Context, w *warnings) (any, error) {
		var dumps []regKeyDump
		found := 0
		for _, t := range targets() {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if dumpTargetCtx(ctx, t, w, &dumps) {
				found++
			} else {
				w.add("not present: %s", t.display())
			}
		}
		if found == 0 {
			return nil, fmt.Errorf("%w: no requested registry location exists", collector.ErrNotPresent)
		}
		return map[string]any{"locations_found": found, "keys": dumps}, nil
	})
	s.Detect = func(context.Context) collector.Availability {
		for _, t := range targets() {
			if k, err := registry.OpenKey(t.Root, t.Path, registry.QUERY_VALUE|t.View); err == nil {
				k.Close()
				return collector.Availability{State: collector.Available}
			}
		}
		return collector.Availability{State: collector.NotPresent, Reason: "registry location not found"}
	}
	return s
}

// hklm builds a machine-hive target.
func hklm(path string, recursive bool, maxDepth int) regTarget {
	return regTarget{Root: registry.LOCAL_MACHINE, RootName: "HKLM", Path: path, Recursive: recursive, MaxDepth: maxDepth, View: registry.WOW64_64KEY}
}

// sortedLoadedSIDs keeps target order (and therefore the output) reproducible between runs.
func sortedLoadedSIDs() []string {
	m := loadedUserSIDs()
	out := make([]string, 0, len(m))
	for sid := range m {
		out = append(out, sid)
	}
	sort.Strings(out)
	return out
}

// perLoadedUser builds one target per loaded user hive for the same sub-path.
func perLoadedUser(sub string, recursive bool, maxDepth int) []regTarget {
	var out []regTarget
	for _, sid := range sortedLoadedSIDs() {
		out = append(out, regTarget{Root: registry.USERS, RootName: "HKU", Path: sid + `\` + sub, Recursive: recursive, MaxDepth: maxDepth, View: registry.WOW64_64KEY})
	}
	return out
}

// perLoadedUserClasses targets HKU\<SID>_Classes (UsrClass.dat) sub-paths.
func perLoadedUserClasses(sub string, recursive bool, maxDepth int) []regTarget {
	var out []regTarget
	for _, sid := range sortedLoadedSIDs() {
		out = append(out, regTarget{Root: registry.USERS, RootName: "HKU", Path: sid + `_Classes\` + sub, Recursive: recursive, MaxDepth: maxDepth, View: registry.WOW64_64KEY})
	}
	return out
}

// ---- raw hive acquisition ----

// hiveSource acquires a hive file. Order: shared read, raw NTFS read, then (for
// machine and loaded-user hives) RegSaveKeyEx which yields a consistent hive that is
// NOT byte-identical to the on-disk file and does not include transaction logs.
func hiveSource(id string, m collector.Meta, path string, rootHandle uintptr, subkey string) collector.Source {
	src := fileSource(id, m, path, defaultFileMax)
	src.Method = "hive-copy/direct-raw-or-regsavekeyex"
	direct := src.Open
	src.Open = func(ctx context.Context) (io.ReadCloser, error) {
		rc, err := direct(ctx)
		if err == nil {
			return rc, nil
		}
		if errors.Is(err, collector.ErrNotPresent) || rootHandle == 0 {
			return nil, err
		}
		saved, serr := regSaveKey(ctx, rootHandle, subkey)
		if serr != nil {
			return nil, fmt.Errorf("%w; RegSaveKeyEx fallback also failed: %v", err, serr)
		}
		return saved, nil
	}
	return src
}

type tempFileReader struct {
	*os.File
	path  string
	notes map[string]string
}

func (t *tempFileReader) Close() error {
	err := t.File.Close()
	os.Remove(t.path)
	return err
}
func (t *tempFileReader) AcquisitionMethod() string           { return "regsavekeyex" }
func (t *tempFileReader) AcquisitionNotes() map[string]string { return t.notes }

// regSaveKey exports a live hive with the documented RegSaveKeyEx API into the
// scratch directory, streams it, and deletes the scratch file on close.
func regSaveKey(ctx context.Context, root uintptr, subkey string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !enablePrivilege("SeBackupPrivilege") {
		return nil, fmt.Errorf("%w: SeBackupPrivilege is not held (run elevated)", collector.ErrAccessDenied)
	}
	dir := currentOptions().TempDir
	if dir == "" {
		dir = os.TempDir()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dir, "hive-*.tmp")
	if err != nil {
		return nil, err
	}
	path := tmp.Name()
	tmp.Close()
	os.Remove(path) // RegSaveKeyEx requires that the target does not exist

	sub, err := windows.UTF16PtrFromString(subkey)
	if err != nil {
		return nil, err
	}
	var h uintptr
	if r, _, _ := pRegOpenKeyEx.Call(root, uintptr(unsafe.Pointer(sub)), regOptionBackup, keyReadAccess, uintptr(unsafe.Pointer(&h))); r != 0 {
		return nil, classifyErr(syscall.Errno(r))
	}
	defer pRegCloseKey.Call(h)
	file, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	if r, _, _ := pRegSaveKeyEx.Call(h, uintptr(unsafe.Pointer(file)), 0, regLatestFormat); r != 0 {
		os.Remove(path)
		return nil, classifyErr(syscall.Errno(r))
	}
	f, err := os.Open(path)
	if err != nil {
		os.Remove(path)
		return nil, err
	}
	return &tempFileReader{File: f, path: path, notes: map[string]string{
		"read_mode":   "RegSaveKeyEx of the loaded hive (REG_LATEST_FORMAT)",
		"fidelity":    "consistent export, not byte-identical to the on-disk hive; transaction logs not included",
		"consistency": "live export",
	}}, nil
}

// ---- registry hive sources ----

func registrySources() []collector.Source {
	cfg := windowsDir() + `\System32\config`
	mach := baseMeta("Machine registry hive", "Raw registry hive: complete configuration, accounts, services, USB, execution state", "registry", collector.PrivAdmin, collector.InStdFull,
		"account/sam-hive.md", "execution/shimcache.md", "enumeration/current-version.md", "persistence/registry-services.md", "execution/bam-dam.md")
	var out []collector.Source
	for _, h := range []struct{ file, sub string }{{"SYSTEM", "SYSTEM"}, {"SOFTWARE", "SOFTWARE"}, {"SAM", "SAM"}, {"SECURITY", "SECURITY"}, {"DEFAULT", ""}} {
		mm := mach
		mm.Name = h.file + " hive"
		root := uintptr(0)
		if h.sub != "" {
			root = hkeyLocalMachine
		}
		src := requiresAdmin(hiveSource("hive-"+strings.ToLower(h.file), mm, cfg+`\`+h.file, root, h.sub))
		if h.file == "SAM" || h.file == "SECURITY" {
			// local password hashes, LSA secrets and cached domain credentials: explicit approval required
			src = sensitiveFullOnly(src, "contains local password hashes and LSA secrets; collect only with explicit authorization")
		}
		out = append(out, src)
	}
	logs := mach
	logs.Name = "Machine hive transaction logs and registry transaction files"
	logs.Profiles = collector.InStdFull
	out = append(out, requiresAdmin(walkGroup("hive-logs", logs, cfg+`\*.LOG*`, walkSpec{
		Roots: staticRoots(cfg), MaxDepth: -1, FileMax: 1 << 30,
		Match: func(_, name string) bool {
			n := strings.ToLower(name)
			return strings.Contains(n, ".log") || strings.HasSuffix(n, ".blf") || strings.HasSuffix(n, ".regtrans-ms")
		}})))
	txr := mach
	txr.Name = "Registry transaction (TxR) and RegBack files"
	out = append(out, requiresAdmin(walkGroup("hive-txr-regback", txr, cfg+`\TxR | RegBack`, walkSpec{
		Roots: staticRoots(cfg+`\TxR`, cfg+`\RegBack`), MaxFiles: 200, FileMax: 1 << 30})))
	svc := mach
	svc.Name = "Service account profiles (LocalService, NetworkService, systemprofile)"
	out = append(out, requiresAdmin(walkGroup("hive-service-profiles", svc, windowsDir()+`\ServiceProfiles | System32\config\systemprofile`, walkSpec{
		Roots:    staticRoots(windowsDir()+`\ServiceProfiles\LocalService`, windowsDir()+`\ServiceProfiles\NetworkService`, cfg+`\systemprofile`),
		MaxDepth: -1, MaxFiles: 100, FileMax: 1 << 30, Match: func(_, n string) bool { return strings.HasPrefix(strings.ToLower(n), "ntuser.dat") }})))

	// Per-user hives: NTUSER.DAT* and UsrClass.dat* for every profile.
	userMeta := baseMeta("User registry hives (NTUSER.DAT, UsrClass.dat) with logs", "Per-user raw hives: MRU lists, ShellBags, UserAssist, RDP history, Office TrustRecords, WordWheelQuery, MountPoints2",
		"registry", collector.PrivAdmin, collector.InStdFull, "user-activity/wordwheelquery.md", "file-activity/trustrecords-registry-key.md", "network/terminal-server-client-keys.md", "execution/bam-dam.md")
	out = append(out, requiresAdmin(userHiveGroup("hive-users", userMeta)))
	return out
}

func userHiveGroup(id string, m collector.Meta) collector.Source {
	g := collector.Source{
		ID: id, Kind: "windows.file_group", Locator: `%USERPROFILE%\NTUSER.DAT* | %LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat*`,
		Method: "per-profile-hive-copy", MaxBytes: defaultFileMax, Meta: m,
		Detect: func(context.Context) collector.Availability {
			if len(userProfiles()) == 0 {
				return collector.Availability{State: collector.NotPresent, Reason: "no user profiles found"}
			}
			return collector.Availability{State: collector.Available}
		},
	}
	g.Meta.SourceType = "file"
	g.Expand = func(ctx context.Context) ([]collector.Source, error) {
		var out []collector.Source
		for _, up := range userProfiles() {
			for _, spec := range []struct {
				dir, prefix string
				classes     bool
			}{{up.Path, "ntuser.dat", false}, {filepath.Join(up.Path, `AppData\Local\Microsoft\Windows`), "usrclass.dat", true}} {
				entries, err := os.ReadDir(extended(spec.dir))
				if err != nil {
					continue
				}
				for _, e := range entries {
					if e.IsDir() || !strings.HasPrefix(strings.ToLower(e.Name()), spec.prefix) {
						continue
					}
					p := filepath.Join(spec.dir, e.Name())
					cm := collector.Meta{Name: up.Name + `: ` + e.Name(), Category: "registry"}
					isMain := strings.EqualFold(e.Name(), "NTUSER.DAT") || strings.EqualFold(e.Name(), "UsrClass.dat")
					if isMain && up.Loaded && up.SID != "" {
						sub := up.SID
						if spec.classes {
							sub += "_Classes"
						}
						out = append(out, hiveSource(id+"-"+short(p), cm, p, hkeyUsers, sub))
					} else {
						out = append(out, fileSource(id+"-"+short(p), cm, p, defaultFileMax))
					}
				}
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("%w: no user hive files found", collector.ErrNotPresent)
		}
		return out, nil
	}
	return g
}
