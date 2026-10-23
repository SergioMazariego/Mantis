//go:build windows

package windows

import (
	"strings"
	"testing"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
)

func TestSecretValueNamesAreRedactedButExecutionPathsAreNot(t *testing.T) {
	for name, want := range map[string]bool{
		"DefaultPassword":                           true,
		"AutoLogonToken":                            true,
		"ClientSecret":                              true,
		"CredentialProvider":                        true,
		`C:\Tools\tokenizer.exe`:                    false, // AppCompatFlags store: value name is the executable path
		`\Device\HarddiskVolume3\x\secret-sync.exe`: false, // BAM: value name is the device path
		"Microsoft.Token.Broker_8wekyb3d8bbwe/App":  false,
		"Version": false,
	} {
		if got := sensitiveValueName(name); got != want {
			t.Errorf("sensitiveValueName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestSecretHiveFilesAreRecognized(t *testing.T) {
	for name, want := range map[string]bool{
		"SAM": true, "SECURITY": true, "SAM.LOG1": true, "security.LOG2": true, "SAM{a8a8c5e5-1}.TM.blf": true,
		"SYSTEM.LOG1": false, "SOFTWARE": false, "DEFAULT.LOG1": false, "SAMPLE.LOG": false, "SECURITYHEALTH.LOG": false,
	} {
		if got := isSecretHiveFile(name); got != want {
			t.Errorf("isSecretHiveFile(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestWow6432PathAndDNSTypeNames(t *testing.T) {
	if got := wow6432Path(`Software\Microsoft\Windows\CurrentVersion\Run`); got != `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run` {
		t.Errorf("wow6432Path = %s", got)
	}
	if got := wow6432Path(`SYSTEM\x`); got != `SYSTEM\x` {
		t.Errorf("non-software paths stay unchanged, got %s", got)
	}
	for typ, want := range map[uint16]string{1: "A", 28: "AAAA", 5: "CNAME", 12: "PTR", 65: ""} {
		if got := dnsTypeName(typ); got != want {
			t.Errorf("dnsTypeName(%d) = %q, want %q", typ, got, want)
		}
	}
}

func TestJSONSourcesDeclareTheirDataVersion(t *testing.T) {
	src := jsonSource("processes-detailed", collector.Meta{Category: "processes"}, "m", "api://x", nil)
	if src.Meta.DataVersion != 2 {
		t.Errorf("processes-detailed must declare data version 2, got %d", src.Meta.DataVersion)
	}
	if other := jsonSource("system-os", collector.Meta{Category: "system"}, "m", "api://x", nil); other.Meta.DataVersion != 1 {
		t.Errorf("unlisted sources are version 1, got %d", other.Meta.DataVersion)
	}
}

func TestRemotePathsAreNeverOpened(t *testing.T) {
	for p, want := range map[string]bool{
		`\\attacker\share\x.exe`: true, `"\\attacker@SSL\DavWWWRoot\x.dll"`: true, `\\?\UNC\host\s\x.exe`: true, `//host/s/x`: true,
		`\Device\Mup\host\s\x.exe`: true, `C:\Windows\System32\cmd.exe`: false, `\\?\C:\Windows\notepad.exe`: false,
	} {
		if got := isRemotePath(p); got != want {
			t.Errorf("isRemotePath(%q) = %v, want %v", p, got, want)
		}
	}
	enr := &imageEnricher{seen: map[string]*enrichedImage{}}
	if img := enr.describe(t.Context(), `\\mantis-fixture.invalid\s\x.exe`); img.Exists || img.Error == "" {
		t.Errorf("a UNC image must be recorded as not read: %+v", img)
	}
}

func TestSystemDirJoinKeepsAbsoluteAndSkipsEmpty(t *testing.T) {
	win := `C:\Windows`
	for in, want := range map[string]string{"ssp.dll": `C:\Windows\System32\ssp.dll`, `C:\x\ssp.dll`: `C:\x\ssp.dll`, `""`: "", "  ": "", `%windir%\x.dll`: `%windir%\x.dll`} {
		if got := inSystemDir(win, "System32", in); got != want {
			t.Errorf("inSystemDir(%q) = %q, want %q", in, got, want)
		}
	}
	if accountExpiry(0xFFFFFFFF) != "never" || accountExpiry(0) != "" {
		t.Error("TIMEQ_FOREVER must read as never, 0 as unset")
	}
}

func TestMachineEntriesDoNotResolveUserVariablesIntoTheCollectorsProfile(t *testing.T) {
	got := expandForEntry(`%APPDATA%\upd.exe /x %SystemRoot%\y`, "System-wide")
	if !strings.HasPrefix(got, `%APPDATA%\upd.exe`) || strings.Contains(got, "%SystemRoot%") {
		t.Errorf("machine entry: user variable must stay unresolved, machine variable resolved: %q", got)
	}
}

func TestSecretHiveLogsAreSensitiveAndFullOnly(t *testing.T) {
	var found bool
	for _, s := range registrySources() {
		if s.ID != "hive-secret-logs" {
			continue
		}
		found = true
		if !s.Meta.Sensitive || s.Meta.Profiles.Has(collector.ProfileStandard) || s.Meta.Profiles.Has(collector.ProfileQuick) || !s.Meta.Profiles.Has(collector.ProfileFull) {
			t.Errorf("hive-secret-logs must be sensitive and Full only: %+v", s.Meta)
		}
	}
	if !found {
		t.Error("hive-secret-logs is not registered")
	}
}
