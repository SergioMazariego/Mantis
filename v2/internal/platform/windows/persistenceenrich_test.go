//go:build windows

package windows

import (
	"os"
	"strings"
	"testing"
)

func TestResolveExecutableHandlesCommonLaunchStrings(t *testing.T) {
	win := windowsDir()
	cases := []struct{ in, want string }{
		{`"C:\Program Files\App\app.exe" -silent`, `C:\Program Files\App\app.exe`},
		{`C:\Tools\runner.exe /a /b`, `C:\Tools\runner.exe`},
		{`\SystemRoot\System32\drivers\x.sys`, win + `\System32\drivers\x.sys`},
		{`system32\drivers\y.sys`, win + `\system32\drivers\y.sys`},
		{`\??\C:\Windows\System32\drivers\z.sys`, `C:\Windows\System32\drivers\z.sys`},
		{`C:\Windows\System32\rundll32.exe C:\x\y.dll,Func`, `C:\Windows\System32\rundll32.exe`},
		{`C:\Windows\system32\svchost.exe -k netsvcs -p`, `C:\Windows\system32\svchost.exe`},
		{``, ``},
	}
	for _, c := range cases {
		if got := resolveExecutable(c.in); !strings.EqualFold(got, c.want) {
			t.Errorf("resolveExecutable(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := resolveExecutable(`cmd.exe /c echo hi`); !strings.HasSuffix(strings.ToLower(got), `\cmd.exe`) {
		t.Errorf("a bare name must resolve to a system directory, got %q", got)
	}
}

func TestUTF16OrUTF8DecodesTaskFiles(t *testing.T) {
	utf16le := []byte{0xFF, 0xFE, '<', 0, 'a', 0, '>', 0}
	if got := utf16OrUTF8(utf16le); got != "<a>" {
		t.Errorf("UTF-16LE task file decoded as %q", got)
	}
	if got := utf16OrUTF8([]byte("\xef\xbb\xbf<b>")); got != "<b>" {
		t.Errorf("UTF-8 BOM not stripped: %q", got)
	}
	m := taskCommandPattern.FindStringSubmatch("<Exec>\n <Command>" + `C:\x\y.exe` + "</Command></Exec>")
	if len(m) != 3 || m[1] != `C:\x\y.exe` {
		t.Errorf("task command not extracted: %v", m)
	}
}

func TestLookupValueIgnoresCase(t *testing.T) {
	m := map[string][]string{"ServiceDLL": {`C:\x.dll`}, "": {"default"}}
	if got := lookupValue(m, "ServiceDll"); len(got) != 1 || got[0] != `C:\x.dll` {
		t.Errorf("case-insensitive lookup failed: %v", got)
	}
	if got := lookupValue(m, ""); len(got) != 1 || got[0] != "default" {
		t.Errorf("default value lookup failed: %v", got)
	}
	if lookupValue(m, "missing") != nil {
		t.Error("a missing value must return nil")
	}
}

func TestRundll32TargetFindsTheDLL(t *testing.T) {
	cases := []struct{ in, want string }{
		{`C:\Windows\System32\rundll32.exe C:\x\y.dll,Func arg`, `C:\x\y.dll`},
		{`"C:\Windows\System32\rundll32.exe" "C:\Program Files\a b\z.dll",Run`, `C:\Program Files\a b\z.dll`},
		{`rundll32.exe C:\x\y.dll`, `C:\x\y.dll`},
		{`C:\Windows\System32\notepad.exe C:\x\y.dll`, ``},
	}
	for _, c := range cases {
		if got := rundll32Target(c.in); got != c.want {
			t.Errorf("rundll32Target(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLaunchTargetCoversRundll32AndRegsvr32(t *testing.T) {
	win := windowsDir()
	cases := []struct{ launch, image, want string }{
		{`C:\Windows\System32\rundll32.exe C:\x\y.dll,Func`, `C:\Windows\System32\rundll32.exe`, `C:\x\y.dll`},
		{`C:\Windows\System32\regsvr32.exe /s /n /i:/UserInstall C:\x\themeui.dll`, `C:\Windows\System32\regsvr32.exe`, `C:\x\themeui.dll`},
		{`C:\Windows\System32\regsvr32.exe /s thing.ocx`, `C:\Windows\System32\regsvr32.exe`, win + `\System32\thing.ocx`},
		{`C:\Windows\System32\notepad.exe a.dll`, `C:\Windows\System32\notepad.exe`, ``},
	}
	for _, c := range cases {
		if got := launchTarget(c.launch, c.image); !strings.EqualFold(got, c.want) {
			t.Errorf("launchTarget(%q) = %q, want %q", c.launch, got, c.want)
		}
	}
}

func TestTaskPatternKeepsTheArguments(t *testing.T) {
	m := taskCommandPattern.FindStringSubmatch("<Exec><Command>%windir%" + `\system32\rundll32.exe` + "</Command>\n<Arguments>Startupscan.dll,SusRunTask</Arguments></Exec>")
	if len(m) != 3 || m[2] != "Startupscan.dll,SusRunTask" {
		t.Errorf("task arguments not captured: %v", m)
	}
}

func TestIndirectStringPassesPlainTextThrough(t *testing.T) {
	if got := indirectString("plain text"); got != "plain text" {
		t.Errorf("plain text changed: %q", got)
	}
	if got := indirectString("$(plain)"); got != "plain" {
		t.Errorf("task wrapper not removed: %q", got)
	}
}

func TestPEDetailsOfASystemBinary(t *testing.T) {
	path := windowsDir() + `\System32\kernel32.dll`
	st, _, signer := verifySignatureDetail(path)
	if !strings.HasPrefix(st, "valid") {
		t.Fatalf("kernel32.dll should verify (embedded or catalog), got %q", st)
	}
	if !strings.Contains(strings.ToLower(signer), "microsoft") {
		t.Errorf("signer name missing or unexpected: %q", signer)
	}
	sha1h, sha256h := peHashes(path)
	if len(sha1h) != 40 || len(sha256h) != 64 {
		t.Errorf("Authenticode hashes have the wrong length: %q %q", sha1h, sha256h)
	}
	if h := importHash(path); len(h) != 32 {
		t.Errorf("import hash must be 32 hex characters, got %q", h)
	}
	if h := importHash(os.Args[0]); len(h) != 32 {
		t.Errorf("import hash of the test binary must be 32 hex characters, got %q", h)
	}
}
