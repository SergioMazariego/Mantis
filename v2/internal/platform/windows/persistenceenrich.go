//go:build windows

package windows

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// persistence-enriched resolves, for every autostart entry it can read, the executable that would
// run and records what a live Autoruns scan shows next to it: file size and times, MD5/SHA-1/SHA-256,
// Authenticode status, company, description, product and file version. The raw registry values and
// task files stay in the other persistence sources; this document links each entry to its image.

var (
	versionDLL         = windows.NewLazySystemDLL("version.dll")
	pGetFileVersionLen = versionDLL.NewProc("GetFileVersionInfoSizeW")
	pGetFileVersionInf = versionDLL.NewProc("GetFileVersionInfoW")
	pVerQueryValue     = versionDLL.NewProc("VerQueryValueW")
)

const (
	maxEnrichedPaths = 20000
	maxTaskFiles     = 6000
)

type enrichEntry struct {
	Category     string `json:"category"`
	Location     string `json:"location"`
	Entry        string `json:"entry"`
	Profile      string `json:"profile"`
	LaunchString string `json:"launch_string"`
	ImagePath    string `json:"image_path,omitempty"`
}

type enrichedImage struct {
	Path             string `json:"path"`
	Exists           bool   `json:"exists"`
	SizeBytes        int64  `json:"size_bytes,omitempty"`
	ModifiedUTC      string `json:"modified_utc,omitempty"`
	MD5              string `json:"md5,omitempty"`
	SHA1             string `json:"sha1,omitempty"`
	SHA256           string `json:"sha256,omitempty"`
	Authenticode     string `json:"authenticode,omitempty"`
	AuthenticodeCode string `json:"authenticode_result,omitempty"`
	Company          string `json:"company,omitempty"`
	Description      string `json:"description,omitempty"`
	ProductName      string `json:"product_name,omitempty"`
	FileVersion      string `json:"file_version,omitempty"`
	FileVersionFixed string `json:"file_version_numeric,omitempty"`
	OriginalName     string `json:"original_filename,omitempty"`
	Error            string `json:"error,omitempty"`
}

var exeExtPattern = regexp.MustCompile(`(?i)\.(exe|dll|sys|com|scr|bat|cmd|cpl|ocx|drv|ax)\b`)

// resolveExecutable extracts the file that a launch string runs: quoted path, first path ending in
// a known extension, or the first token; environment variables, \SystemRoot\, \??\ and system32\
// prefixes are normalized; a bare file name is looked up in the system directories.
func resolveExecutable(launch string) string {
	s := strings.TrimSpace(launch)
	if s == "" {
		return ""
	}
	s = expandEnv(s)
	var p string
	if strings.HasPrefix(s, `"`) {
		if end := strings.Index(s[1:], `"`); end >= 0 {
			p = s[1 : 1+end]
		} else {
			p = s[1:]
		}
	} else if loc := exeExtPattern.FindStringIndex(s); loc != nil {
		p = s[:loc[1]]
	} else if i := strings.IndexAny(s, " \t,"); i > 0 {
		p = s[:i]
	} else {
		p = s
	}
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, `\??\`)
	win := windowsDir()
	lower := strings.ToLower(p)
	switch {
	case strings.HasPrefix(lower, `\systemroot\`):
		p = win + p[len(`\systemroot`):]
	case strings.HasPrefix(lower, `system32\`) || strings.HasPrefix(lower, `syswow64\`):
		p = win + `\` + p
	}
	if p != "" && !strings.ContainsAny(p, `\/`) { // bare name: look in the system directories
		for _, d := range []string{win + `\System32`, win, win + `\SysWOW64`} {
			if _, err := os.Stat(filepath.Join(d, p)); err == nil {
				return filepath.Join(d, p)
			}
		}
		if !strings.Contains(p, ".") { // names without an extension are usually .exe or .dll
			for _, ext := range []string{".exe", ".dll"} {
				if _, err := os.Stat(filepath.Join(win, `System32`, p+ext)); err == nil {
					return filepath.Join(win, `System32`, p+ext)
				}
			}
		}
	}
	return p
}

// fileVersionStrings reads the string table of a file's version resource.
func fileVersionStrings(path string) (company, desc, product, version, original string) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	var handle uint32
	size, _, _ := pGetFileVersionLen.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&handle)))
	if size == 0 {
		return
	}
	buf := make([]byte, size)
	if r, _, _ := pGetFileVersionInf.Call(uintptr(unsafe.Pointer(p)), 0, size, uintptr(unsafe.Pointer(&buf[0]))); r == 0 {
		return
	}
	base := uintptr(unsafe.Pointer(&buf[0]))
	// VerQueryValue returns pointers into buf: translate them back to offsets so no raw pointer is dereferenced
	locate := func(sub string) (off, n int, ok bool) {
		q, _ := windows.UTF16PtrFromString(sub)
		var ptr uintptr
		var cnt uint32
		if r, _, _ := pVerQueryValue.Call(base, uintptr(unsafe.Pointer(q)), uintptr(unsafe.Pointer(&ptr)), uintptr(unsafe.Pointer(&cnt))); r == 0 || ptr < base {
			return 0, 0, false
		}
		off = int(ptr - base)
		return off, int(cnt), off >= 0 && off < len(buf)
	}
	query := func(sub string) string {
		off, n, ok := locate(sub)
		if !ok || n == 0 {
			return ""
		}
		var u []uint16
		for i := off; i+1 < len(buf); i += 2 {
			c := uint16(buf[i]) | uint16(buf[i+1])<<8
			if c == 0 {
				break
			}
			u = append(u, c)
		}
		return string(utf16.Decode(u))
	}
	// the translation table gives the language and code page of the string block
	var langs []string
	if off, n, ok := locate(`\VarFileInfo\Translation`); ok && n >= 4 && off+n <= len(buf) {
		for i := off; i+3 < off+n; i += 4 {
			lang := uint16(buf[i]) | uint16(buf[i+1])<<8
			page := uint16(buf[i+2]) | uint16(buf[i+3])<<8
			langs = append(langs, fmt.Sprintf("%04x%04x", lang, page))
		}
	}
	langs = append(langs, "040904b0", "040904e4", "000004b0")
	for _, l := range langs {
		if c := query(`\StringFileInfo\` + l + `\CompanyName`); c != "" || query(`\StringFileInfo\`+l+`\FileDescription`) != "" {
			return c, query(`\StringFileInfo\` + l + `\FileDescription`), query(`\StringFileInfo\` + l + `\ProductName`),
				query(`\StringFileInfo\` + l + `\FileVersion`), query(`\StringFileInfo\` + l + `\OriginalFilename`)
		}
	}
	return
}

type imageEnricher struct {
	seen  map[string]*enrichedImage
	total int64
}

func (e *imageEnricher) describe(ctx context.Context, path string) *enrichedImage {
	key := strings.ToLower(path)
	if v, ok := e.seen[key]; ok {
		return v
	}
	img := &enrichedImage{Path: path}
	e.seen[key] = img
	f, err := directOpen(path)
	if err != nil {
		img.Error = "open: " + err.Error()
		return img
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		img.Error = "not a file"
		return img
	}
	img.Exists, img.SizeBytes, img.ModifiedUTC = true, st.Size(), st.ModTime().UTC().Format(time.RFC3339Nano)
	if st.Size() > maxHashFileBytes || e.total+st.Size() > maxHashTotalBytes {
		img.Error = "not hashed: file exceeds the per-file or total hashing budget"
	} else {
		e.total += st.Size()
		hm, hs1, hs256 := md5.New(), sha1.New(), sha256.New()
		if _, err := io.Copy(io.MultiWriter(hm, hs1, hs256), &ctxReader{ctx, f}); err != nil {
			img.Error = "hash: " + err.Error()
		} else {
			img.MD5, img.SHA1, img.SHA256 = hex.EncodeToString(hm.Sum(nil)), hex.EncodeToString(hs1.Sum(nil)), hex.EncodeToString(hs256.Sum(nil))
		}
	}
	img.Authenticode, img.AuthenticodeCode = verifySignature(path)
	img.Company, img.Description, img.ProductName, img.FileVersion, img.OriginalName = fileVersionStrings(path)
	img.FileVersionFixed = fixedFileVersion(path)
	return img
}

// regStrings reads every value of a key as text (expanded strings are left as stored; the resolver expands them).
func regStrings(root registry.Key, path string, view uint32) map[string][]string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|view)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return nil
	}
	out := map[string][]string{}
	for _, n := range names {
		if s, typ, err := k.GetStringValue(n); err == nil && (typ == registry.SZ || typ == registry.EXPAND_SZ) {
			out[n] = []string{s}
		} else if ss, _, err := k.GetStringsValue(n); err == nil {
			out[n] = ss
		}
	}
	return out
}

func regSubKeys(root registry.Key, path string, view uint32) []string {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|view)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	sort.Strings(names)
	return names
}

func utf16OrUTF8(b []byte) string {
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		u := make([]uint16, (len(b)-2)/2)
		for i := range u {
			u[i] = uint16(b[2+2*i]) | uint16(b[3+2*i])<<8
		}
		return string(utf16.Decode(u))
	}
	return strings.TrimPrefix(string(b), "\xef\xbb\xbf")
}

var taskCommandPattern = regexp.MustCompile(`(?is)<Command>\s*([^<]+?)\s*</Command>`)
var taskComHandlerPattern = regexp.MustCompile(`(?is)<ComHandler>\s*<ClassId>\s*(\{[^<]+?\})\s*</ClassId>`)

func collectEnrichEntries(ctx context.Context, w *warnings) []enrichEntry {
	var out []enrichEntry
	add := func(cat, loc, entry, profile, launch string) {
		if strings.TrimSpace(launch) != "" {
			out = append(out, enrichEntry{Category: cat, Location: loc, Entry: entry, Profile: profile, LaunchString: launch})
		}
	}
	win := windowsDir()
	hk := func(root registry.Key, rootName, path string, view uint32, f func(loc string, vals map[string][]string)) {
		if vals := regStrings(root, path, view); vals != nil {
			f(rootName+`\`+path, vals)
		}
	}
	views := []struct {
		v    uint32
		wow  string
		name string
	}{{registry.WOW64_64KEY, "", "64"}, {registry.WOW64_32KEY, `WOW6432Node\`, "32"}}

	// Run keys: machine (both views) and loaded users
	for _, rk := range []string{`Software\Microsoft\Windows\CurrentVersion\Run`, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`} {
		for _, v := range views {
			hk(registry.LOCAL_MACHINE, "HKLM", rk, v.v, func(loc string, vals map[string][]string) {
				for n, ss := range vals {
					add("logon", loc, n, "System-wide", strings.Join(ss, " "))
				}
			})
		}
		for _, sid := range sortedLoadedSIDs() {
			hk(registry.USERS, "HKU", sid+`\`+rk, registry.WOW64_64KEY, func(loc string, vals map[string][]string) {
				for n, ss := range vals {
					add("logon", loc, n, sid, strings.Join(ss, " "))
				}
			})
		}
	}
	// Winlogon, AppInit, LSA, KnownDLLs, codecs, print monitors
	hk(registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, registry.WOW64_64KEY, func(loc string, vals map[string][]string) {
		for _, n := range []string{"Shell", "Userinit", "Taskman", "VMApplet", "AlternateShell"} {
			for _, s := range lookupValue(vals, n) {
				for _, part := range strings.Split(s, ",") {
					add("winlogon", loc, n, "System-wide", part)
				}
			}
		}
	})
	for _, v := range views {
		hk(registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`, v.v, func(loc string, vals map[string][]string) {
			for _, s := range lookupValue(vals, "AppInit_DLLs") {
				for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
					add("appinit", loc, "AppInit_DLLs", "System-wide", part)
				}
			}
		})
		hk(registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32`, v.v, func(loc string, vals map[string][]string) {
			for n, ss := range vals {
				launch := strings.Join(ss, " ")
				if v.wow != "" && !strings.ContainsAny(launch, `\/`) { // 32-bit view: bare names live in SysWOW64
					if p := filepath.Join(win, "SysWOW64", strings.TrimSpace(launch)); fileExists(p) {
						launch = p
					}
				}
				add("codecs", loc, n, "System-wide", launch)
			}
		})
	}
	hk(registry.LOCAL_MACHINE, "HKLM", `SYSTEM\CurrentControlSet\Control\Lsa`, registry.WOW64_64KEY, func(loc string, vals map[string][]string) {
		for _, n := range []string{"Authentication Packages", "Notification Packages", "Security Packages"} {
			for _, s := range lookupValue(vals, n) {
				for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\x00' }) {
					if !strings.Contains(part, ".") {
						part += ".dll"
					}
					add("lsa", loc, n, "System-wide", filepath.Join(win, "System32", part))
				}
			}
		}
	})
	hk(registry.LOCAL_MACHINE, "HKLM", `SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`, registry.WOW64_64KEY, func(loc string, vals map[string][]string) {
		for n, ss := range vals {
			if n == "DllDirectory" || n == "DllDirectory32" {
				continue
			}
			for _, s := range ss {
				add("known_dlls", loc, n, "System-wide", filepath.Join(win, "System32", s))
			}
		}
	})
	for _, name := range regSubKeys(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Print\Monitors`, registry.WOW64_64KEY) {
		hk(registry.LOCAL_MACHINE, "HKLM", `SYSTEM\CurrentControlSet\Control\Print\Monitors\`+name, registry.WOW64_64KEY, func(loc string, vals map[string][]string) {
			for _, s := range lookupValue(vals, "Driver") {
				add("print_monitors", loc, name, "System-wide", filepath.Join(win, "System32", s))
			}
		})
	}
	// Services and drivers: image path and, for svchost-hosted services, the service DLL
	const svcRoot = `SYSTEM\CurrentControlSet\Services`
	for _, name := range regSubKeys(registry.LOCAL_MACHINE, svcRoot, registry.WOW64_64KEY) {
		if ctx.Err() != nil {
			return out
		}
		vals := regStrings(registry.LOCAL_MACHINE, svcRoot+`\`+name, registry.WOW64_64KEY)
		img := lookupValue(vals, "ImagePath")
		if len(img) == 0 {
			continue
		}
		cat := "services"
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, svcRoot+`\`+name, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
			if t, _, err := k.GetIntegerValue("Type"); err == nil && (t == 1 || t == 2 || t == 8) {
				cat = "drivers"
			}
			k.Close()
		}
		loc := `HKLM\` + svcRoot
		add(cat, loc, name, "System-wide", img[0])
		if p := regStrings(registry.LOCAL_MACHINE, svcRoot+`\`+name+`\Parameters`, registry.WOW64_64KEY); p != nil {
			for _, d := range lookupValue(p, "ServiceDll") {
				add(cat, loc, name+" (ServiceDll)", "System-wide", d)
			}
		}
	}
	collectHandlerEntries(add)
	collectProviderEntries(add)
	// Scheduled tasks: the commands in the task XML
	tasksDir := win + `\System32\Tasks`
	count := 0
	filepath.WalkDir(extended(tasksDir), func(path string, d os.DirEntry, err error) error {
		if err != nil || ctx.Err() != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if count++; count > maxTaskFiles {
			w.add("scheduled task enumeration stopped after %d files", maxTaskFiles)
			return filepath.SkipAll
		}
		data, err := os.ReadFile(path)
		if err != nil || len(data) > 4<<20 {
			return nil
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(path, extended(tasksDir)), `\`)
		xml := utf16OrUTF8(data)
		for _, m := range taskCommandPattern.FindAllStringSubmatch(xml, -1) {
			add("scheduled_tasks", "Task Scheduler", `\`+rel, "System-wide", m[1])
		}
		// COM-handler tasks run the in-process server registered for their class
		for _, m := range taskComHandlerPattern.FindAllStringSubmatch(xml, -1) {
			if s := clsidServer(strings.TrimSpace(m[1])); s != "" {
				add("scheduled_tasks", "Task Scheduler", `\`+rel, "System-wide", s)
			}
		}
		return nil
	})
	return out
}

func persistenceEnriched(ctx context.Context, w *warnings) (any, error) {
	entries := collectEnrichEntries(ctx, w)
	enr := &imageEnricher{seen: map[string]*enrichedImage{}}
	for i := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entries[i].ImagePath = resolveExecutable(entries[i].LaunchString)
		if entries[i].ImagePath == "" {
			continue
		}
		if len(enr.seen) >= maxEnrichedPaths {
			w.add("enrichment stopped after %d distinct image paths", maxEnrichedPaths)
			break
		}
		enr.describe(ctx, entries[i].ImagePath)
	}
	images := make([]*enrichedImage, 0, len(enr.seen))
	for _, v := range enr.seen {
		images = append(images, v)
	}
	sort.Slice(images, func(i, j int) bool { return strings.ToLower(images[i].Path) < strings.ToLower(images[j].Path) })
	missing := 0
	for _, im := range images {
		if !im.Exists {
			missing++
		}
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: no autostart entries could be read", collector.ErrNotPresent)
	}
	return map[string]any{
		"note":    "each entry links to the image it launches; hashes, Authenticode, company, description and version are read from the file on disk at collection time (not from the raw registry data kept in the other persistence sources)",
		"entries": entries, "images": images, "entry_count": len(entries), "image_count": len(images), "images_missing": missing,
	}, nil
}

func persistenceEnrichedSource() collector.Source {
	m := baseMeta("Autostart entries with image details", "Run/RunOnce, Winlogon, AppInit, LSA, KnownDLLs, codecs, print monitors, services/drivers (incl. ServiceDll) and scheduled-task commands, each resolved to its executable with size, times, MD5/SHA-1/SHA-256, Authenticode, company, description and version",
		"persistence", collector.PrivUser, collector.InStdFull)
	m.SideEffects = "reads executable files to hash them (updates last-access times on volumes where that is enabled)"
	return withDetect(jsonSource("persistence-enriched", m, "registry+file-hash+wintrust+version", "api://persistence-enriched", persistenceEnriched), available)
}

var _ = errors.New // keep the import used by future error wrapping
