//go:build windows

package windows

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"golang.org/x/sys/windows"
)

func TestDestForPreservesOriginalPaths(t *testing.T) {
	cases := map[string]string{
		`C:\Windows\System32\config\SYSTEM`: "registry/C/Windows/System32/config/SYSTEM",
		`d:\Profiles\a b\NTUSER.DAT`:        "registry/D/Profiles/a b/NTUSER.DAT",
	}
	for in, want := range cases {
		if got := destFor("registry", in); got != want {
			t.Errorf("destFor(%q) = %q, want %q", in, got, want)
		}
	}
	if drive, rest, ok := splitDrive(`C:\x\y`); !ok || drive != "C" || rest != `x\y` {
		t.Errorf("splitDrive: %q %q %v", drive, rest, ok)
	}
	if got := stripStream(`C:\Data\a\f.exe:Zone.Identifier`); got != `C:\Data\a\f.exe` {
		t.Errorf("stripStream: %q", got)
	}
	if got := stripStream(`C:\Data\a\f.exe`); got != `C:\Data\a\f.exe` {
		t.Errorf("stripStream must keep plain paths: %q", got)
	}
	if got := channelFileName("Microsoft-Windows-PowerShell/Operational"); got != "Microsoft-Windows-PowerShell%4Operational.evtx" {
		t.Errorf("channelFileName: %q", got)
	}
}

func TestClassifyErrKeepsForensicallyDistinctOutcomes(t *testing.T) {
	cases := []struct {
		err  error
		want error
	}{
		{syscall.ERROR_FILE_NOT_FOUND, collector.ErrNotPresent},
		{syscall.ERROR_PATH_NOT_FOUND, collector.ErrNotPresent},
		{windows.ERROR_ACCESS_DENIED, collector.ErrAccessDenied},
		{windows.ERROR_SHARING_VIOLATION, collector.ErrLocked},
		{windows.ERROR_NOT_SUPPORTED, collector.ErrNotSupported},
	}
	for _, tc := range cases {
		if got := classifyErr(tc.err); !errors.Is(got, tc.want) || !errors.Is(got, tc.err) {
			t.Errorf("classifyErr(%v) = %v, want typed %v with the cause kept", tc.err, got, tc.want)
		}
	}
	if classifyErr(nil) != nil {
		t.Error("nil must stay nil")
	}
}

func TestFileSourcePreservesBytesAndReportsMethod(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.bin")
	want := []byte("raw\x00bytes\xff preserved exactly")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	src := fileSource("t-file", collector.Meta{Name: "test", Category: "execution"}, path, 0)
	if src.Detect(context.Background()).State != collector.Available {
		t.Fatal("existing file must be available")
	}
	rc, err := src.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil || string(got) != string(want) {
		t.Fatalf("bytes not preserved: %q %v", got, err)
	}
	mr, ok := rc.(collector.MethodReporter)
	if !ok || mr.AcquisitionMethod() != "win32-shared-read" {
		t.Fatalf("method not reported: %v", rc)
	}
	if !strings.HasSuffix(src.Meta.DestPath, "/artifact.bin") || !strings.HasPrefix(src.Meta.DestPath, "execution/") {
		t.Fatalf("destination does not preserve the source path: %s", src.Meta.DestPath)
	}
	missing := fileSource("t-missing", collector.Meta{Category: "execution"}, filepath.Join(dir, "nope.bin"), 0)
	if missing.Detect(context.Background()).State != collector.NotPresent {
		t.Fatal("missing file must be not_present")
	}
	if _, err := missing.Open(context.Background()); !errors.Is(err, collector.ErrNotPresent) {
		t.Fatalf("missing file must open as not_present, got %v", err)
	}
}

func TestWalkGroupExpandsMatchesAndReportsTruncation(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"a.pf", "b.pf", "c.txt", filepath.Join("sub", "d.pf")} {
		p := filepath.Join(dir, f)
		os.MkdirAll(filepath.Dir(p), 0o700)
		os.WriteFile(p, []byte(f), 0o600)
	}
	g := walkGroup("t-walk", collector.Meta{Name: "walk", Category: "execution"}, dir, walkSpec{
		Roots: staticRoots(dir), MaxFiles: 2, Match: func(_, n string) bool { return strings.HasSuffix(n, ".pf") }})
	kids, err := g.Expand(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var files, gaps int
	for _, k := range kids {
		if k.Kind == "windows.collection_gap" {
			gaps++
		} else {
			files++
		}
	}
	if files != 2 || gaps != 1 {
		t.Fatalf("expected 2 files plus an explicit truncation gap, got %d files, %d gaps", files, gaps)
	}
	none := walkGroup("t-none", collector.Meta{Category: "execution"}, dir, walkSpec{Roots: staticRoots(dir), Match: func(_, n string) bool { return n == "nothing" }})
	if _, err := none.Expand(context.Background()); !errors.Is(err, collector.ErrNotPresent) {
		t.Fatalf("no matches must be reported as not_present, got %v", err)
	}
}

func TestJSONSourceRecordsWarningsAsPartialAcquisition(t *testing.T) {
	src := jsonSource("t-json", collector.Meta{Category: "system"}, "test", "api://x", func(_ context.Context, w *warnings) (any, error) {
		w.add("one problem")
		return map[string]int{"n": 1}, nil
	})
	rc, err := src.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(rc)
	if !strings.Contains(string(data), `"warnings"`) || !strings.Contains(string(data), "one problem") {
		t.Fatalf("warnings missing from the document: %s", data)
	}
	notes := rc.(collector.NotesReporter).AcquisitionNotes()
	if notes["warnings"] != "1" {
		t.Fatalf("warning count must reach the manifest notes: %v", notes)
	}
	item := collector.ItemResult{Notes: notes}
	_ = item // Classify needs a ready result; covered by collector tests
}

func TestCatalogInvariants(t *testing.T) {
	srcs := Sources()
	if len(srcs) < 60 {
		t.Fatalf("catalog unexpectedly small: %d sources", len(srcs))
	}
	known := map[string]bool{}
	for _, c := range categoryOrder {
		known[c] = true
	}
	ids := map[string]bool{}
	for _, s := range srcs {
		if ids[s.ID] {
			t.Errorf("duplicate source id %s", s.ID)
		}
		ids[s.ID] = true
		if !known[s.Meta.Category] {
			t.Errorf("%s: unknown category %q", s.ID, s.Meta.Category)
		}
		if s.Open == nil && s.Expand == nil {
			t.Errorf("%s: neither Open nor Expand", s.ID)
		}
		if s.Meta.Sensitive && (s.Meta.Profiles.Has(collector.ProfileQuick) || s.Meta.Profiles.Has(collector.ProfileStandard)) {
			t.Errorf("%s: sensitive sources must not belong to Quick or Standard", s.ID)
		}
		if strings.HasPrefix(s.ID, "browser-") {
			low := strings.ToLower(s.Locator + " " + s.Meta.Description)
			for _, bad := range []string{"login data", "cookies", "key4.db", "logins.json"} {
				if strings.Contains(low, bad) && !strings.Contains(low, "exclu") {
					t.Errorf("%s mentions %q without declaring the exclusion", s.ID, bad)
				}
			}
		}
	}
	for _, p := range []collector.Profile{collector.ProfileQuick, collector.ProfileStandard, collector.ProfileFull} {
		if len(collector.SelectProfile(srcs, p, false)) == 0 {
			t.Errorf("profile %s selects nothing", p)
		}
	}
	quick := len(collector.SelectProfile(srcs, collector.ProfileQuick, false))
	full := len(collector.SelectProfile(srcs, collector.ProfileFull, false))
	if quick >= full {
		t.Errorf("quick (%d) must be a strict subset of full (%d)", quick, full)
	}
	for _, id := range []string{"process-snapshot", "tcp-connections", "autorun-registry", "disk-inventory", "userassist", "powershell-history", "system-temp", "prefetch", "user-recent"} {
		if !ids[id] {
			t.Errorf("v1-parity collector %s disappeared from the registry", id)
		}
	}
}
