//go:build windows

package windows

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// CLSID-based autostart points (shell extensions, credential providers, DirectShow filters, protocol
// handlers), Winsock catalogs, Active Setup, GPO extensions, network providers and file-association
// commands. Each entry is resolved to the server DLL or command it ends up running.

var guidPattern = regexp.MustCompile(`(?i)^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$`)

// clsidServer returns the in-process or local server registered for a CLSID (64-bit view, then 32-bit).
func clsidServer(clsid string) string {
	for _, view := range []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY} {
		for _, sub := range []string{`InprocServer32`, `LocalServer32`, `InprocHandler32`} {
			if v := regStrings(registry.LOCAL_MACHINE, `SOFTWARE\Classes\CLSID\`+clsid+`\`+sub, view); v != nil {
				if d := v[""]; len(d) > 0 && strings.TrimSpace(d[0]) != "" {
					return d[0]
				}
			}
		}
	}
	return ""
}

type handlerKey struct {
	category string
	path     string // under HKLM, machine hive form (SOFTWARE\...)
	hkcu     bool   // also read the same path under every loaded user (Software\...)
}

var handlerKeys = []handlerKey{
	{"explorer", `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects`, false},
	{"explorer", `SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad`, false},
	{"explorer", `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler`, false},
	{"explorer", `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks`, false},
	{"explorer", `SOFTWARE\Classes\*\ShellEx\ContextMenuHandlers`, false},
	{"explorer", `SOFTWARE\Classes\*\ShellEx\PropertySheetHandlers`, false},
	{"explorer", `SOFTWARE\Classes\AllFileSystemObjects\ShellEx\ContextMenuHandlers`, false},
	{"explorer", `SOFTWARE\Classes\AllFileSystemObjects\ShellEx\PropertySheetHandlers`, false},
	{"explorer", `SOFTWARE\Classes\Directory\ShellEx\ContextMenuHandlers`, false},
	{"explorer", `SOFTWARE\Classes\Directory\ShellEx\CopyHookHandlers`, false},
	{"explorer", `SOFTWARE\Classes\Directory\ShellEx\PropertySheetHandlers`, false},
	{"explorer", `SOFTWARE\Classes\Directory\ShellEx\DragDropHandlers`, false},
	{"explorer", `SOFTWARE\Classes\Directory\Background\ShellEx\ContextMenuHandlers`, false},
	{"explorer", `SOFTWARE\Classes\Folder\ShellEx\ContextMenuHandlers`, false},
	{"explorer", `SOFTWARE\Classes\Folder\ShellEx\DragDropHandlers`, false},
	{"explorer", `SOFTWARE\Classes\Folder\ShellEx\ExtShellFolderViews`, false},
	{"explorer", `SOFTWARE\Classes\Drive\ShellEx\ContextMenuHandlers`, false},
	{"explorer", `SOFTWARE\Classes\Protocols\Handler`, false},
	{"internet_explorer", `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`, false},
	{"internet_explorer", `SOFTWARE\Microsoft\Internet Explorer\UrlSearchHooks`, true},
	{"winlogon", `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers`, false},
	{"winlogon", `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters`, false},
	{"winlogon", `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\PLAP Providers`, false},
	{"codecs", `SOFTWARE\Classes\CLSID\{083863F1-70DE-11d0-BD40-00A0C911CE86}\Instance`, false},
	{"codecs", `SOFTWARE\Classes\CLSID\{7ED96837-96F0-4812-B211-F13C24117ED3}\Instance`, false},
	{"codecs", `SOFTWARE\Classes\CLSID\{AC757296-3522-4E11-9862-C17BE5A1767E}\Instance`, false},
	{"codecs", `SOFTWARE\Classes\CLSID\{DA4E3DA0-D07D-11d0-BD50-00A0C911CE86}\Instance`, false},
	{"codecs", `SOFTWARE\Classes\CLSID\{33D9A760-90C8-11d0-BD43-00A0C911CE86}\Instance`, false},
	{"codecs", `SOFTWARE\Classes\CLSID\{33D9A761-90C8-11d0-BD43-00A0C911CE86}\Instance`, false},
}

// collectHandlerEntries enumerates the handler keys above and the other CLSID/command based locations.
func collectHandlerEntries(add func(cat, loc, entry, profile, launch string)) {
	win := windowsDir()
	views := []struct {
		v      uint32
		prefix string
	}{{registry.WOW64_64KEY, ""}, {registry.WOW64_32KEY, `Wow6432Node\`}}
	locate := func(path, prefix string) string {
		if prefix != "" && strings.HasPrefix(strings.ToUpper(path), `SOFTWARE\`) {
			return `HKLM\SOFTWARE\` + prefix + path[len(`SOFTWARE\`):]
		}
		return `HKLM\` + path
	}
	// a handler subkey names its CLSID, or carries it as the default value, a "CLSID" value or any GUID-valued entry
	resolveHandler := func(root registry.Key, base, sub string, view uint32) (string, string) {
		if guidPattern.MatchString(sub) {
			if s := clsidServer(sub); s != "" {
				return sub, s
			}
		}
		vals := regStrings(root, base+`\`+sub, view)
		for _, name := range []string{"", "CLSID"} {
			if d := vals[name]; len(d) > 0 && guidPattern.MatchString(strings.TrimSpace(d[0])) {
				if s := clsidServer(strings.TrimSpace(d[0])); s != "" {
					return strings.TrimSpace(d[0]), s
				}
			}
		}
		for _, ds := range vals {
			for _, d := range ds {
				if guidPattern.MatchString(strings.TrimSpace(d)) {
					if s := clsidServer(strings.TrimSpace(d)); s != "" {
						return strings.TrimSpace(d), s
					}
				}
			}
		}
		return "", ""
	}
	for _, hk := range handlerKeys {
		for _, v := range views {
			loc := locate(hk.path, v.prefix)
			for _, sub := range regSubKeys(registry.LOCAL_MACHINE, hk.path, v.v) {
				if guid, srv := resolveHandler(registry.LOCAL_MACHINE, hk.path, sub, v.v); srv != "" {
					add(hk.category, loc, sub+" "+guid, "System-wide", srv)
				}
			}
			// values of the key itself: the data (or the value name) is the CLSID
			for n, ds := range regStrings(registry.LOCAL_MACHINE, hk.path, v.v) {
				for _, c := range append([]string{n}, ds...) {
					if c = strings.TrimSpace(c); guidPattern.MatchString(c) {
						if s := clsidServer(c); s != "" {
							add(hk.category, loc, n+" "+c, "System-wide", s)
						}
					}
				}
			}
		}
		if hk.hkcu {
			rel := `Software\` + hk.path[len(`SOFTWARE\`):]
			for _, sid := range sortedLoadedSIDs() {
				base := sid + `\` + rel
				for n, ds := range regStrings(registry.USERS, base, registry.WOW64_64KEY) {
					for _, c := range append([]string{n}, ds...) {
						if c = strings.TrimSpace(c); guidPattern.MatchString(c) {
							if s := clsidServer(c); s != "" {
								add(hk.category, `HKU\`+base, n+" "+c, sid, s)
							}
						}
					}
				}
				for _, sub := range regSubKeys(registry.USERS, base, registry.WOW64_64KEY) {
					if guid, srv := resolveHandler(registry.USERS, base, sub, registry.WOW64_64KEY); srv != "" {
						add(hk.category, `HKU\`+base, sub+" "+guid, sid, srv)
					}
				}
			}
		}
	}
	// DirectShow filter instances carry the filter CLSID in a "CLSID" value: handled above through resolveHandler.

	// Group Policy client-side extensions: DllName; Active Setup: StubPath
	for _, v := range views {
		gp := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GpExtensions`
		for _, sub := range regSubKeys(registry.LOCAL_MACHINE, gp, v.v) {
			if d := regStrings(registry.LOCAL_MACHINE, gp+`\`+sub, v.v)["DllName"]; len(d) > 0 {
				add("winlogon", locate(gp, v.prefix), sub, "System-wide", d[0])
			}
		}
		as := `SOFTWARE\Microsoft\Active Setup\Installed Components`
		for _, sub := range regSubKeys(registry.LOCAL_MACHINE, as, v.v) {
			if d := regStrings(registry.LOCAL_MACHINE, as+`\`+sub, v.v)["StubPath"]; len(d) > 0 {
				add("logon", locate(as, v.prefix), sub, "System-wide", d[0])
			}
		}
	}
	// Winsock catalogs: the protocol entries embed the provider path in PackedCatalogItem; namespaces use LibraryPath
	ws := `SYSTEM\CurrentControlSet\Services\WinSock2\Parameters`
	for _, cat := range []string{`Protocol_Catalog9\Catalog_Entries`, `Protocol_Catalog9\Catalog_Entries64`} {
		base := ws + `\` + cat
		for _, sub := range regSubKeys(registry.LOCAL_MACHINE, base, registry.WOW64_64KEY) {
			k, err := registry.OpenKey(registry.LOCAL_MACHINE, base+`\`+sub, registry.QUERY_VALUE|registry.WOW64_64KEY)
			if err != nil {
				continue
			}
			if b, _, err := k.GetBinaryValue("PackedCatalogItem"); err == nil {
				if i := strings.IndexByte(string(b), 0); i > 0 {
					add("winsock", `HKLM\`+base, sub, "System-wide", string(b[:i]))
				}
			}
			k.Close()
		}
	}
	for _, cat := range []string{`NameSpace_Catalog5\Catalog_Entries`, `NameSpace_Catalog5\Catalog_Entries64`} {
		base := ws + `\` + cat
		for _, sub := range regSubKeys(registry.LOCAL_MACHINE, base, registry.WOW64_64KEY) {
			if d := regStrings(registry.LOCAL_MACHINE, base+`\`+sub, registry.WOW64_64KEY)["LibraryPath"]; len(d) > 0 {
				add("winsock", `HKLM\`+base, sub, "System-wide", d[0])
			}
		}
	}
	// Network providers: Order\ProviderOrder lists service names, each with a ProviderPath
	if order := regStrings(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\NetworkProvider\Order`, registry.WOW64_64KEY)["ProviderOrder"]; len(order) > 0 {
		for _, p := range strings.Split(order[0], ",") {
			if p = strings.TrimSpace(p); p == "" {
				continue
			}
			if d := regStrings(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+p+`\NetworkProvider`, registry.WOW64_64KEY)["ProviderPath"]; len(d) > 0 {
				add("network_providers", `HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order`, p, "System-wide", d[0])
			}
		}
	}
	// file-association commands that decide what runs when an executable type is opened
	for _, class := range []string{"exefile", "cmdfile", "batfile", "comfile", "piffile", "scrfile", "htmlfile"} {
		path := `SOFTWARE\Classes\` + class + `\Shell\Open\Command`
		if d := regStrings(registry.LOCAL_MACHINE, path, registry.WOW64_64KEY)[""]; len(d) > 0 {
			add("image_hijacks", `HKLM\`+path+`\(Default)`, class, "System-wide", d[0])
		}
	}
	// KnownDLLs also list the 32-bit directory
	if d := regStrings(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`, registry.WOW64_64KEY); d != nil {
		for n, ss := range d {
			if n == "DllDirectory" || n == "DllDirectory32" || len(ss) == 0 {
				continue
			}
			if p := filepath.Join(win, "SysWOW64", ss[0]); fileExists(p) {
				add("known_dlls", `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDlls (32-bit)`, n, "System-wide", p)
			}
		}
	}
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// fixedFileVersion returns the numeric file version from VS_FIXEDFILEINFO (what Autoruns shows), which can
// differ from the FileVersion string in the string table after servicing updates.
func fixedFileVersion(path string) string {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	var handle uint32
	size, _, _ := pGetFileVersionLen.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&handle)))
	if size == 0 {
		return ""
	}
	buf := make([]byte, size)
	if r, _, _ := pGetFileVersionInf.Call(uintptr(unsafe.Pointer(p)), 0, size, uintptr(unsafe.Pointer(&buf[0]))); r == 0 {
		return ""
	}
	base := uintptr(unsafe.Pointer(&buf[0]))
	q, _ := windows.UTF16PtrFromString(`\`)
	var ptr uintptr
	var n uint32
	if r, _, _ := pVerQueryValue.Call(base, uintptr(unsafe.Pointer(q)), uintptr(unsafe.Pointer(&ptr)), uintptr(unsafe.Pointer(&n))); r == 0 || ptr < base || n < 20 {
		return ""
	}
	off := int(ptr - base)
	if off < 0 || off+20 > len(buf) {
		return ""
	}
	if binary.LittleEndian.Uint32(buf[off:]) != 0xFEEF04BD { // VS_FIXEDFILEINFO signature
		return ""
	}
	ms, ls := binary.LittleEndian.Uint32(buf[off+8:]), binary.LittleEndian.Uint32(buf[off+12:])
	return fmt.Sprintf("%d.%d.%d.%d", ms>>16, ms&0xFFFF, ls>>16, ls&0xFFFF)
}
