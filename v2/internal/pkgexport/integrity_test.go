package pkgexport

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
)

func TestSanitizeComponentNeverSplitsACharacter(t *testing.T) {
	long := "a" + strings.Repeat("中", 60) // 1 + 180 bytes: a byte cut at 150 would land inside a character
	got := SanitizeComponent(long)
	if !utf8.ValidString(got) || len(got) > 150 {
		t.Fatalf("truncated name must be valid UTF-8 within 150 bytes: %q (%d bytes)", got, len(got))
	}
	// two host names that only differ after the limit collapse to one name: the second must get its own destination
	used := map[string]bool{}
	mk := func(name, sha string) collector.ItemResult {
		it := collector.ItemResult{SourceID: "x", Meta: collector.Meta{DestPath: "users/" + name}}
		it.Result.Blob.SHA256 = sha
		return it
	}
	d1 := uniqueDest("users", mk("a"+strings.Repeat("中", 49)+"乙x", "1111111111"), used)
	d2 := uniqueDest("users", mk("a"+strings.Repeat("中", 49)+"丙x", "2222222222"), used)
	if d1 == d2 || !utf8.ValidString(d2) {
		t.Errorf("colliding names must get distinct, valid destinations: %q %q", d1, d2)
	}
}

func TestCrossCheckTiesTheManifestToTheDisk(t *testing.T) {
	entries := []checkEntry{{"manifest.json", "m"}, {"processes/p.json", "aaa"}, {"csv/processes.csv", "ccc"}, {"leftover/old.bin", "zzz"}}
	arts := []Artifact{
		{ID: "p", Destination: "processes/p.json", SHA256: "aaa"},
		{ID: "q", Destination: "processes/q.json", SHA256: "bbb"}, // in the manifest, not on disk
		{ID: "gap"}, // not acquired: no destination, nothing to check
	}
	derived := []Derived{{Path: "csv/processes.csv", SHA256: "different"}}
	problems := strings.Join(crossCheck(entries, arts, derived), "\n")
	for _, want := range []string{"processes/q.json: artifact q in the manifest but missing", "csv/processes.csv: derived file digest on disk differs",
		"leftover/old.bin: file in the package that the manifest does not account for"} {
		if !strings.Contains(problems, want) {
			t.Errorf("missing problem %q in:\n%s", want, problems)
		}
	}
	if strings.Contains(problems, "processes/p.json") || strings.Contains(problems, "manifest.json") {
		t.Errorf("consistent files must not be reported:\n%s", problems)
	}
}
