//go:build windows

package windows

import (
	"os"
	"regexp"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Per-entry details that Autoruns shows and the raw registry dumps hold elsewhere: the time of the key (or
// task file), the enabled state and the description of the service or task.

var pSHLoadIndirectString = windows.NewLazySystemDLL("shlwapi.dll").NewProc("SHLoadIndirectString")

// indirectString resolves "@file.dll,-123" resource references (as used by service and task descriptions).
func indirectString(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "$(") && strings.HasSuffix(s, ")") {
		s = s[2 : len(s)-1]
	}
	if !strings.HasPrefix(s, "@") {
		return s
	}
	src, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return ""
	}
	out := make([]uint16, 1024)
	if r, _, _ := pSHLoadIndirectString.Call(uintptr(unsafe.Pointer(src)), uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)), 0); r != 0 {
		// "@oem1.inf,%key%;Default text": the string table of an INF is not loadable, the default text is
		if i := strings.LastIndex(s, ";"); i >= 0 {
			return strings.TrimSpace(s[i+1:])
		}
		return ""
	}
	return windows.UTF16ToString(out)
}

// splitRegistryLocation turns "HKLM\path" or "HKU\sid\path" into a root key and a path.
func splitRegistryLocation(loc string) (registry.Key, string, bool) {
	switch {
	case strings.HasPrefix(loc, `HKLM\`):
		return registry.LOCAL_MACHINE, loc[len(`HKLM\`):], true
	case strings.HasPrefix(loc, `HKU\`):
		return registry.USERS, loc[len(`HKU\`):], true
	}
	return 0, "", false
}

func keyTimeUTC(root registry.Key, path string) string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	st, err := k.Stat()
	if err != nil {
		return ""
	}
	return st.ModTime().UTC().Format(time.RFC3339Nano)
}

var (
	taskSettingsPattern    = regexp.MustCompile(`(?is)<Settings>(.*?)</Settings>`)
	taskDisabledPattern    = regexp.MustCompile(`(?is)<Enabled>\s*false\s*</Enabled>`)
	taskDescriptionPattern = regexp.MustCompile(`(?is)<RegistrationInfo>.*?<Description>\s*([^<]*?)\s*</Description>`)
)

// startupApproved reports whether Explorer's StartupApproved list marks a Run entry as disabled.
func startupApproved(root registry.Key, base, name string) (known, disabled bool) {
	k, err := registry.OpenKey(root, base, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return false, false
	}
	defer k.Close()
	b, _, err := k.GetBinaryValue(name)
	if err != nil || len(b) == 0 {
		return false, false
	}
	return true, b[0]&1 == 1 // 02/06 enabled, 03/07 disabled
}

// annotateEntries fills key_time_utc, enabled and the descriptions for the entries it understands.
func annotateEntries(entries []enrichEntry) {
	tasksDir := windowsDir() + `\System32\Tasks`
	for i := range entries {
		e := &entries[i]
		e.Enabled = "enabled"
		switch e.Category {
		case "scheduled_tasks":
			file := extended(tasksDir + e.Entry)
			if st, err := os.Stat(file); err == nil {
				e.KeyTimeUTC = st.ModTime().UTC().Format(time.RFC3339Nano)
			}
			if data, err := os.ReadFile(file); err == nil && len(data) < 4<<20 {
				xml := utf16OrUTF8(data)
				if m := taskSettingsPattern.FindStringSubmatch(xml); m != nil && taskDisabledPattern.MatchString(m[1]) {
					e.Enabled = "disabled"
				}
				if m := taskDescriptionPattern.FindStringSubmatch(xml); m != nil {
					e.EntryDescription = strings.TrimSpace(m[1]) // shown verbatim, like Autoruns
				}
			}
		case "services", "drivers":
			name := strings.TrimSuffix(e.Entry, " (ServiceDll)")
			path := `SYSTEM\CurrentControlSet\Services\` + name
			e.KeyTimeUTC = keyTimeUTC(registry.LOCAL_MACHINE, path)
			if k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
				if start, _, err := k.GetIntegerValue("Start"); err == nil && start == 4 {
					e.Enabled = "disabled"
				}
				var display, desc string
				if d, _, err := k.GetStringValue("DisplayName"); err == nil {
					display = indirectString(d)
				}
				if d, _, err := k.GetStringValue("Description"); err == nil {
					desc = indirectString(d)
				}
				// Autoruns shows "<display name>: <description>" for services and drivers
				switch {
				case display != "" && desc != "":
					e.EntryDescription = display + ": " + desc
				case display != "":
					e.EntryDescription = display
				default:
					e.EntryDescription = desc
				}
				k.Close()
			}
		case "network_providers":
			// the provider's display name comes from its service key
			if v := regStrings(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+e.Entry+`\NetworkProvider`, registry.WOW64_64KEY); v != nil {
				if n := lookupValue(v, "Name"); len(n) > 0 {
					e.EntryDescription = indirectString(n[0])
				}
			}
			e.KeyTimeUTC = keyTimeUTC(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+e.Entry)
		default:
			root, path, ok := splitRegistryLocation(e.Location)
			if !ok {
				break // folders and other non-registry locations
			}
			// handler entries are "<subkey> <guid>": the subkey carries the time; otherwise the key itself
			first := e.Entry
			if i := strings.Index(first, " "); i > 0 {
				first = first[:i]
			}
			if t := keyTimeUTC(root, path+`\`+first); t != "" && first != "" {
				e.KeyTimeUTC = t
			} else {
				e.KeyTimeUTC = keyTimeUTC(root, path)
			}
			if e.Category == "logon" {
				base, name := "", e.Entry
				switch {
				case root == registry.LOCAL_MACHINE && strings.Contains(path, `WOW6432Node`):
					base = `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32`
				case root == registry.LOCAL_MACHINE:
					base = `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`
				case root == registry.USERS:
					if i := strings.Index(path, `\`); i > 0 {
						base = path[:i] + `\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`
					}
				}
				if base != "" {
					if known, dis := startupApproved(root, base, name); known && dis {
						e.Enabled = "disabled"
					}
				}
			}
		}
	}
}
