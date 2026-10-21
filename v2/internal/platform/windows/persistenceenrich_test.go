//go:build windows

package windows

import (
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
	if len(m) != 2 || m[1] != `C:\x\y.exe` {
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
