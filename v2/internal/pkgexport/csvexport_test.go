package pkgexport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeDoc(t *testing.T, dir, rel, body string) Artifact {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	return Artifact{Destination: rel, SHA256: hex.EncodeToString(sum[:])}
}

func readCSV(t *testing.T, path string) [][]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte("\xEF\xBB\xBF")) {
		t.Fatal("CSV must start with a UTF-8 BOM")
	}
	recs, err := csv.NewReader(bytes.NewReader(raw[3:])).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func TestCSVViewsTraceEveryRowToItsSource(t *testing.T) {
	dir := t.TempDir()
	procs := writeDoc(t, dir, "processes/processes-detailed.json", `{"schema":"mantis.snapshot/1","data":{"processes":[
		{"pid":4321,"parent_pid":700,"name":"ping.exe","command_line":"ping -n 1 127.0.0.1","image":{"sha256":"abc","signer":"Microsoft Windows"},
		 "privileges_enabled":["SeChangeNotifyPrivilege","SeDebugPrivilege"],
		 "modules":[{"name":"ntdll.dll","path":"C:\\Windows\\System32\\ntdll.dll","base":"0x7ff0","size":2048},{"name":"kernel32.dll","path":"C:\\Windows\\System32\\kernel32.dll","base":"0x7ff1","size":1024}]},
		{"pid":18446744073709551615,"name":"=cmd|' /C calc'!A0","command_line":"line1\nline2"}]}}`)
	procs.ID, procs.Method = "processes-detailed", "toolhelp+ntquery+wintrust"
	reg := writeDoc(t, dir, "usb/usb-device-history.json", `{"data":{"keys":[{"path":"HKLM\\SYSTEM\\USBSTOR\\Disk","last_write_utc":"2026-10-01T10:00:00Z",
		"values":[{"name":"FriendlyName","type":"REG_SZ","size":20,"text":"Kingston"},{"name":"HardwareID","type":"REG_MULTI_SZ","size":40,"strings":["USBSTOR\\Disk","GenDisk"]}]}]}}`)
	reg.ID, reg.Method = "usb-device-history", "registry-api-dump"
	raw := Artifact{ID: "hive-system", Destination: "registry/C/Windows/System32/config/SYSTEM", Method: "regsavekeyex"} // not JSON: never read

	derived, err := writeCSVViews(context.Background(), dir, []Artifact{procs, reg, raw})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Derived{}
	for _, d := range derived {
		byName[d.Path] = d
	}
	for _, want := range []string{"csv/processes.csv", "csv/process_modules.csv", "csv/registry_values.csv"} {
		if _, ok := byName[want]; !ok {
			t.Fatalf("%s not written; got %v", want, derived)
		}
	}
	if len(derived) != 3 {
		t.Errorf("views without a source artifact must not be written: %v", derived)
	}

	p := readCSV(t, filepath.Join(dir, "csv", "processes.csv"))
	if len(p) != 3 || byName["csv/processes.csv"].Rows != 2 {
		t.Fatalf("expected header + 2 rows, got %d", len(p))
	}
	col := func(rec []string, name string) string {
		for i, h := range p[0] {
			if h == name {
				return rec[i]
			}
		}
		t.Fatalf("column %s missing", name)
		return ""
	}
	ping, evil := p[1], p[2]
	if col(ping, "source_artifact_id") != "processes-detailed" || col(ping, "source_sha256") != procs.SHA256 || col(ping, "source_pointer") != "data.processes[0]" {
		t.Errorf("provenance columns wrong: %v", ping[:3])
	}
	if col(ping, "image_signer") != "Microsoft Windows" || col(ping, "privileges_enabled") != "SeChangeNotifyPrivilege; SeDebugPrivilege" {
		t.Errorf("nested and list columns wrong: %v", ping)
	}
	if col(evil, "pid") != "18446744073709551615" {
		t.Errorf("64-bit numbers must stay exact, got %s", col(evil, "pid"))
	}
	if !strings.HasPrefix(col(evil, "name"), "'=") {
		t.Errorf("a formula-looking cell must be neutralized, got %q", col(evil, "name"))
	}
	if col(evil, "command_line") != `line1\nline2` {
		t.Errorf("line breaks must be escaped, got %q", col(evil, "command_line"))
	}

	m := readCSV(t, filepath.Join(dir, "csv", "process_modules.csv"))
	if len(m) != 3 || m[2][2] != "data.processes[0].modules[1]" || m[2][3] != "4321" || m[2][4] != "ping.exe" || m[2][6] != `C:\Windows\System32\kernel32.dll` {
		t.Errorf("exploded rows wrong: %v", m)
	}
	r := readCSV(t, filepath.Join(dir, "csv", "registry_values.csv"))
	if len(r) != 3 || r[2][3] != `HKLM\SYSTEM\USBSTOR\Disk` || r[2][9] != `USBSTOR\Disk; GenDisk` {
		t.Errorf("registry values wrong: %v", r)
	}

	// the recorded hash and size are those of the file on disk
	raw2, _ := os.ReadFile(filepath.Join(dir, "csv", "processes.csv"))
	sum := sha256.Sum256(raw2)
	if d := byName["csv/processes.csv"]; d.SHA256 != hex.EncodeToString(sum[:]) || d.SizeBytes != int64(len(raw2)) || d.FromArtifacts[0] != "processes-detailed" {
		t.Errorf("derived record does not match the file: %+v", d)
	}
}

func TestNeutralizeOnlyTouchesFormulaPrefixesAndLineBreaks(t *testing.T) {
	for in, want := range map[string]string{
		"=SUM(A1)": "'=SUM(A1)", "+1": "'+1", "-cmd": "'-cmd", "@x": "'@x", "\tx": "'\tx",
		"C:\\a.exe": "C:\\a.exe", "a\r\nb": `a\nb`, "": "",
	} {
		if got := neutralize(in); got != want {
			t.Errorf("neutralize(%q) = %q, want %q", in, got, want)
		}
	}
}
