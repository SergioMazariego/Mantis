//go:build windows

package windows

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func keeps(t *testing.T, f FileFilter, path string) bool {
	t.Helper()
	f, err := NormalizeFileFilter(f)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return f.keep(path, info)
}

func TestFileFilterMatchesByExtensionAndByContentSignature(t *testing.T) {
	dir := t.TempDir()
	exe := writeFile(t, dir, "dropper.EXE", []byte("MZ\x90\x00"))
	renamed := writeFile(t, dir, "payload.tmp", []byte("MZ\x90\x00\x03"))
	script := writeFile(t, dir, "run.ps1", []byte("Write-Host x"))
	text := writeFile(t, dir, "notes.txt", []byte("hello"))
	zipped := writeFile(t, dir, "data.bin", []byte("PK\x03\x04rest"))

	byType := FileFilter{Types: []string{"executable", "script"}}
	for path, want := range map[string]bool{exe: true, renamed: true, script: true, text: false, zipped: false} {
		if got := keeps(t, byType, path); got != want {
			t.Errorf("types executable,script on %s: got %v want %v", filepath.Base(path), got, want)
		}
	}
	byExt := FileFilter{Extensions: []string{"TMP", ".txt"}}
	for path, want := range map[string]bool{renamed: true, text: true, exe: false, script: false} {
		if got := keeps(t, byExt, path); got != want {
			t.Errorf("extensions tmp,txt on %s: got %v want %v", filepath.Base(path), got, want)
		}
	}
	if !keeps(t, FileFilter{}, text) {
		t.Error("an empty filter must keep everything")
	}
}

func TestFileFilterSizeAndAgeAreAnded(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "a.exe", make([]byte, 2048))
	if keeps(t, FileFilter{Types: []string{"executable"}, MaxFileBytes: 1024}, p) {
		t.Error("a file over the size limit must be left out")
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	if keeps(t, FileFilter{ModifiedSince: time.Now().Add(-24 * time.Hour)}, p) {
		t.Error("a file older than the window must be left out")
	}
	if !keeps(t, FileFilter{ModifiedSince: time.Now().Add(-72 * time.Hour), MaxFileBytes: 4096}, p) {
		t.Error("a file inside both limits must be kept")
	}
}

func TestNormalizeFileFilterRejectsUnknownTypesAndBadExtensions(t *testing.T) {
	for _, bad := range []FileFilter{{Types: []string{"malware"}}, {Extensions: []string{"a/b"}}, {Extensions: []string{"*.exe"}}} {
		if _, err := NormalizeFileFilter(bad); err == nil {
			t.Errorf("%+v must be rejected", bad)
		}
	}
	f, err := NormalizeFileFilter(FileFilter{Extensions: []string{"EXE", ".exe", " dll "}})
	if err != nil || len(f.Extensions) != 2 || f.Extensions[0] != ".exe" || f.Extensions[1] != ".dll" {
		t.Errorf("extensions must be lower-cased, dotted and de-duplicated: %v %v", f.Extensions, err)
	}
}

func TestOpenFileRecordsSourceCreationAccessAndModificationTimes(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "ConsoleHost_history.txt", []byte("Get-Process"))
	want := time.Date(2024, 3, 5, 10, 20, 30, 0, time.UTC)
	if err := os.Chtimes(p, want.Add(time.Hour), want); err != nil {
		t.Fatal(err)
	}
	r, err := openFile(t.Context(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	n := r.AcquisitionNotes()
	for _, k := range []string{"source_created_utc", "source_accessed_utc", "source_modified_utc"} {
		if n[k] == "" {
			t.Errorf("%s missing from the acquisition notes: %v", k, n)
		}
	}
	if got, _ := time.Parse(time.RFC3339Nano, n["source_modified_utc"]); !got.Equal(want) {
		t.Errorf("modified time %s, want %s", n["source_modified_utc"], want)
	}
}
