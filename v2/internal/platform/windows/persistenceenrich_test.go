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
