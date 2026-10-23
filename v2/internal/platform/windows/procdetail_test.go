//go:build windows

package windows

import (
	"encoding/binary"
	"reflect"
	"testing"
	"unicode/utf16"
	"unsafe"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
)

func TestProtectionNameDecodesTypeAndSigner(t *testing.T) {
	// PS_PROTECTION: type in bits 0-2 (1 PPL, 2 PP), signer in bits 4-7 (1 Authenticode ... 4 Lsa, 5 Windows, 6 WinTcb, 7 WinSystem, 8 App)
	for b, want := range map[byte]string{0x00: "", 0x11: "PPL-Authenticode", 0x31: "PPL-Antimalware", 0x41: "PPL-Lsa", 0x51: "PPL-Windows",
		0x61: "PPL-WinTcb", 0x62: "PP-WinTcb", 0x71: "PPL-WinSystem", 0x81: "PPL-App", 0xf1: "PPL-Unknown"} {
		if got := protectionName(b); got != want {
			t.Errorf("protectionName(%#x) = %q, want %q", b, got, want)
		}
	}
}

func TestResolveParentsFlagsExitedAndReusedPIDs(t *testing.T) {
	procs := []procRecord{
		{PID: 100, ParentPID: 0, Name: "root.exe", CreatedUTC: "2026-10-01T10:00:00Z"},
		{PID: 200, ParentPID: 100, Name: "child.exe", CreatedUTC: "2026-10-01T10:05:00Z"},
		{PID: 300, ParentPID: 999, Name: "orphan.exe", CreatedUTC: "2026-10-01T10:06:00Z"},
		{PID: 400, ParentPID: 500, Name: "victim.exe", CreatedUTC: "2026-10-01T10:07:00Z"},
		{PID: 500, ParentPID: 100, Name: "newer.exe", CreatedUTC: "2026-10-01T11:00:00Z"}, // took PID 500 after the child was created
		{PID: 600, ParentPID: 100, Name: "noclock.exe"},                                   // creation time unknown
	}
	resolveParents(procs)
	got := map[uint32][2]string{}
	for _, p := range procs {
		got[p.PID] = [2]string{p.ParentState, p.ParentName}
	}
	want := map[uint32][2]string{100: {"", ""}, 200: {"running", "root.exe"}, 300: {"exited", ""}, 400: {"pid-reused", ""}, 500: {"running", "root.exe"}, 600: {"unverified", ""}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parent resolution wrong:\n got %v\nwant %v", got, want)
	}
}

func utf16Block(vars ...string) []byte {
	var u []uint16
	for _, v := range vars {
		u = append(u, utf16.Encode([]rune(v))...)
		u = append(u, 0)
	}
	u = append(u, 0)
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func TestSplitEnvironmentReadsDoubleNulTerminatedBlock(t *testing.T) {
	got := splitEnvironment(append(utf16Block("PATH=C:\\Windows", "=C:=C:\\Users", "TOKEN=abc=def"), 0x41, 0)) // bytes after the terminator are ignored
	want := []string{"PATH=C:\\Windows", "=C:=C:\\Users", "TOKEN=abc=def"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("environment split wrong: %q", got)
	}
	if n := len(splitEnvironment(nil)); n != 0 {
		t.Errorf("an empty block has no variables, got %d", n)
	}
}

func TestSamePathIgnoresCaseAndExtendedPrefix(t *testing.T) {
	if same, ok := samePath(`\\?\C:\Windows\System32\cmd.exe`, `c:\windows\system32\CMD.EXE`); !same || !ok {
		t.Error("extended prefix and case must not make a difference")
	}
	if same, ok := samePath(`C:\a.exe`, `C:\b.exe`); same || !ok {
		t.Error("different files must not match")
	}
	if same, ok := samePath(`\SystemRoot\System32\smss.exe`, windowsDir()+`\System32\smss.exe`); !same || !ok {
		t.Error(`\SystemRoot paths (smss.exe) must not read as a mismatch`)
	}
	if _, ok := samePath(`relative\x.exe`, `C:\x.exe`); ok {
		t.Error("a PEB path that is not a drive path is inconclusive")
	}
}

func TestHandleFlagsNameTheAccessAnInvestigatorLooksFor(t *testing.T) {
	got := handleFlags("Process", 0x1fffff, "lsass.exe")
	for _, want := range []string{"memory-read", "memory-write", "create-thread", "dup-handle", "lsass-memory-read"} {
		found := false
		for _, g := range got {
			found = found || g == want
		}
		if !found {
			t.Errorf("flag %s missing from %v", want, got)
		}
	}
	if f := handleFlags("Process", 0x1000, "lsass.exe"); len(f) != 0 {
		t.Errorf("a query-only handle is not suspicious: %v", f)
	}
	if f := handleFlags("Thread", 0x10, "x.exe"); len(f) != 1 || f[0] != "set-context" {
		t.Errorf("thread SET_CONTEXT must be flagged: %v", f)
	}
	if got := decodeAccess(0x1410, processAccessNames); !reflect.DeepEqual(got, []string{"VM_READ", "QUERY_INFORMATION", "QUERY_LIMITED_INFORMATION"}) {
		t.Errorf("process access decode wrong: %v", got)
	}
}

func TestParseObjectTypesReadsNamesAndIndexes(t *testing.T) {
	buf := make([]byte, 1024)
	base := uintptr(unsafe.Pointer(&buf[0]))
	binary.LittleEndian.PutUint32(buf, 2)
	off := 8
	for i, name := range []string{"Process", "File"} {
		u := utf16.Encode([]rune(name))
		nameOff := off + 104
		for j, c := range u {
			binary.LittleEndian.PutUint16(buf[nameOff+2*j:], c)
		}
		binary.LittleEndian.PutUint16(buf[off:], uint16(len(u)*2))
		binary.LittleEndian.PutUint16(buf[off+2:], uint16(len(u)*2+2))
		binary.LittleEndian.PutUint64(buf[off+8:], uint64(base)+uint64(nameOff))
		buf[off+90] = byte(7 + 28*i) // TypeIndex
		off = (nameOff + len(u)*2 + 2 + 7) &^ 7
	}
	got, err := parseObjectTypes(buf[:off], base)
	if err != nil || !reflect.DeepEqual(got, []objectType{{Index: 7, Name: "Process"}, {Index: 35, Name: "File"}}) {
		t.Fatalf("object types wrong: %v %v", got, err)
	}
	if _, err := parseObjectTypes(buf[:off-200], base); err == nil {
		t.Error("a truncated table must be an error, not an out-of-range read")
	}
}

func TestMemoryProtectionAndRegionNames(t *testing.T) {
	for p, want := range map[uint32]string{0x40: "RWX", 0x20: "RX", 0x04: "RW", 0x120: "RX+guard", 0x02: "R", 0: ""} {
		if got := protectName(p); got != want {
			t.Errorf("protectName(%#x) = %q, want %q", p, got, want)
		}
	}
	if !isExecutable(0x20) || !isExecutable(0x40) || !isExecutable(0x80) || isExecutable(0x04) || isExecutable(0x02) {
		t.Error("executable protection detection wrong")
	}
	if regionType(memImage) != "image" || regionType(memMapped) != "mapped" || regionType(memPrivate) != "private" {
		t.Error("region type names wrong")
	}
}

func TestSystemFileHandlesAreRecognizedAsNoise(t *testing.T) {
	for name, want := range map[string]bool{
		`\Device\HarddiskVolume3\Windows\System32\kernel32.dll`: true,
		`\Device\Afd\Endpoint`:                                         true,
		`\Device\NamedPipe\mojo.123.456`:                               false,
		`\Device\HarddiskVolume3\Users\x\AppData\Local\Temp\evil.exe`:  false,
		`\Device\HarddiskVolume3\ProgramData\Windows Defender\scan.db`: false,
	} {
		if got := isSystemFile(name); got != want {
			t.Errorf("isSystemFile(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestNewProcessSourcesAreRegisteredWithTheRightProfiles(t *testing.T) {
	byID := map[string]collector.Source{}
	for _, s := range processSources() {
		byID[s.ID] = s
	}
	cases := []struct {
		id        string
		std, full bool
		sensitive bool
	}{
		{"processes-memory-map", true, true, false},
		{"processes-module-images", true, true, false},
		{"processes-handles", false, true, false},
		{"processes-environment", false, true, true},
	}
	for _, c := range cases {
		s, ok := byID[c.id]
		if !ok {
			t.Errorf("source %s is not registered", c.id)
			continue
		}
		if s.Meta.Profiles.Has(collector.ProfileStandard) != c.std || s.Meta.Profiles.Has(collector.ProfileFull) != c.full || s.Meta.Sensitive != c.sensitive {
			t.Errorf("%s: wrong profile or sensitivity: %+v", c.id, s.Meta)
		}
		if s.Meta.Profiles.Has(collector.ProfileQuick) {
			t.Errorf("%s must not be part of Quick Triage", c.id)
		}
	}
}
