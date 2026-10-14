//go:build linux

package linux

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCatalogIsLazyAndLeavesZimbraOptional(t *testing.T) {
	catalog := Sources()
	seen := map[string]bool{}
	for _, source := range catalog {
		seen[source.ID] = true
		if source.Open == nil && source.Expand == nil {
			t.Fatalf("source %q cannot be collected", source.ID)
		}
	}
	for _, id := range []string{"zimbra-audit", "shell-history-home", "journal-persistent", "cron-config", "network-interfaces"} {
		if !seen[id] {
			t.Errorf("expected optional source %q in catalog", id)
		}
	}
}

func TestFileTreeGroupSkipsSymlinksAndReportsLimit(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "one.log"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "two.log"), []byte("fixture-two"), 0600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.log")
	if err := os.WriteFile(outside, []byte("must-not-follow"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link.log")); err != nil {
		t.Skipf("symlink fixture unavailable: %v", err)
	}
	source := fileTreeGroup("fixture", "linux.test", root, 1, allRegularFiles)
	children, err := source.Expand(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(children) != 2 || children[1].ID != "fixture-enumeration-gap" {
		t.Fatalf("expected one file and explicit limit gap, got %#v", children)
	}
	reader, err := children[0].Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	closeErr := reader.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("read fixture: %v, close: %v", err, closeErr)
	}
	if string(data) != "fixture" {
		t.Fatalf("unexpected fixture content: %q", data)
	}
	if children[1].Open == nil {
		t.Fatal("enumeration gap has no explicit error source")
	}
	if _, err := children[1].Open(context.Background()); err == nil {
		t.Fatalf("expected explicit enumeration-limit error, got %v", err)
	}
}
