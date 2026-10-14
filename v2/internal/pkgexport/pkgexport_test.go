package pkgexport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"github.com/SergioMazariego/Mantis/v2/internal/evidence"
	"github.com/SergioMazariego/Mantis/v2/internal/ingest"
)

func blobFor(data string) (evidence.Blob, string) {
	sum := sha256.Sum256([]byte(data))
	h := hex.EncodeToString(sum[:])
	return evidence.Blob{SHA256: h, SizeBytes: int64(len(data))}, h
}

func item(id, dest, data string, meta collector.Meta) collector.ItemResult {
	blob, _ := blobFor(data)
	meta.DestPath = dest
	return collector.ItemResult{SourceID: id, Result: ingest.Result{Ready: true, Blob: blob}, Meta: meta, Locator: "src://" + id,
		Method: "test-method", AcquiredAt: time.Now().UTC()}
}

func opener(blobs map[string]string) func(context.Context, string) (io.ReadCloser, error) {
	return func(_ context.Context, sha string) (io.ReadCloser, error) {
		data, ok := blobs[sha]
		if !ok {
			return nil, errors.New("blob missing")
		}
		return io.NopCloser(strings.NewReader(data)), nil
	}
}

func TestWritePackageRecordsEveryStatusAndVerifies(t *testing.T) {
	dir := t.TempDir()
	_, shaA := blobFor("alpha")
	_, shaB := blobFor("beta")
	items := []collector.ItemResult{
		item("a", "registry/C/Windows/System32/config/SYSTEM", "alpha", collector.Meta{Category: "registry", Name: "SYSTEM hive", SourcePath: `C:\Windows\System32\config\SYSTEM`}),
		item("b", "registry/C/Windows/System32/config/SYSTEM", "beta", collector.Meta{Category: "registry"}), // colliding destination
		{SourceID: "gone", Err: collector.ErrNotPresent, Meta: collector.Meta{Category: "browsers"}},
		{SourceID: "denied", Err: collector.ErrAccessDenied, Meta: collector.Meta{Category: "security"}},
		item("empty", "system/empty.txt", "", collector.Meta{Category: "system"}),
	}
	sum, err := Write(context.Background(), Options{Dir: dir, CaseID: "case-1", HostID: "host-1", ToolVersion: "test", Profile: "custom",
		Privilege: "user", StartedAt: time.Now().Add(-time.Second), FinishedAt: time.Now(), Items: items,
		Open: opener(map[string]string{shaA: "alpha", shaB: "beta", func() string { _, h := blobFor(""); return h }(): ""})})
	if err != nil || !sum.Verified {
		t.Fatalf("write: %v %+v", err, sum)
	}
	for _, name := range []string{"manifest.json", "acquisition-report.json", "acquisition-errors.json", "checksums.sha256", "verification.json", "README-PACKAGE.txt"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
	var man manifest
	if err := json.Unmarshal(raw, &man); err != nil || man.Schema != ManifestSchema || len(man.Artifacts) != 5 {
		t.Fatalf("manifest: %v %+v", err, man)
	}
	statuses := map[string]string{}
	dests := map[string]bool{}
	for _, a := range man.Artifacts {
		statuses[a.ID] = a.Status
		if a.Status == "not_present" || a.Status == "access_denied" {
			if a.SHA256 != "" || a.Destination != "" {
				t.Errorf("%s: gaps must not carry a hash or destination: %+v", a.ID, a)
			}
		}
		if a.Destination != "" {
			if dests[strings.ToLower(a.Destination)] {
				t.Errorf("duplicate destination %s", a.Destination)
			}
			dests[strings.ToLower(a.Destination)] = true
		}
	}
	want := map[string]string{"a": "collected", "b": "collected", "gone": "not_present", "denied": "access_denied", "empty": "empty"}
	for id, st := range want {
		if statuses[id] != st {
			t.Errorf("%s: status %q, want %q", id, statuses[id], st)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "registry", "C", "Windows", "System32", "config", "SYSTEM"))
	if err != nil || string(data) != "alpha" {
		t.Fatalf("raw bytes not preserved: %q %v", data, err)
	}
}

func TestVerificationDetectsTamperingAndStrayFiles(t *testing.T) {
	dir := t.TempDir()
	_, sha := blobFor("payload")
	items := []collector.ItemResult{item("x", "system/x.bin", "payload", collector.Meta{Category: "system"})}
	if _, err := Write(context.Background(), Options{Dir: dir, CaseID: "c", HostID: "h", StartedAt: time.Now(), FinishedAt: time.Now(), Items: items, Open: opener(map[string]string{sha: "payload"})}); err != nil {
		t.Fatal(err)
	}
	checks, err := writeChecksums(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if problems := verify(context.Background(), dir, checks); len(problems) != 0 {
		t.Fatalf("clean package reported problems: %v", problems)
	}
	os.WriteFile(filepath.Join(dir, "system", "x.bin"), []byte("tampered"), 0o644)
	os.WriteFile(filepath.Join(dir, "stray.txt"), []byte("new"), 0o644)
	problems := verify(context.Background(), dir, checks)
	if len(problems) != 2 {
		t.Fatalf("expected tamper + stray detection, got %v", problems)
	}
}

func TestExportRejectsBlobWithWrongDigest(t *testing.T) {
	dir := t.TempDir()
	blob, sha := blobFor("expected")
	items := []collector.ItemResult{{SourceID: "bad", Result: ingest.Result{Ready: true, Blob: blob}, Meta: collector.Meta{Category: "system", DestPath: "system/bad.bin"}}}
	sum, err := Write(context.Background(), Options{Dir: dir, CaseID: "c", HostID: "h", StartedAt: time.Now(), FinishedAt: time.Now(), Items: items,
		Open: opener(map[string]string{sha: "something else"})})
	if err != nil {
		t.Fatalf("export of one bad blob must be reported, not abort the package: %v", err)
	}
	if sum.ByStatus["failed"] != 1 {
		t.Fatalf("digest mismatch must surface as failed: %+v", sum.ByStatus)
	}
	if _, err := os.Stat(filepath.Join(dir, "system", "bad.bin")); err == nil {
		t.Fatal("corrupt export left a file behind")
	}
	if bytes.Contains([]byte(strings.Join(sum.VerifyErrors, ",")), []byte("partial")) {
		t.Fatal("partial file leaked")
	}
}

func TestSanitizePathBlocksTraversalAndReservedNames(t *testing.T) {
	cases := map[string]string{
		"../../etc/passwd":      "_/_/etc/passwd",
		`registry\C:\x\y.dat`:   "registry/C_/x/y.dat",
		"browsers/CON/file.txt": "browsers/_CON/file.txt",
		"a//b/./c":              "a/b/c",
		"trailing. /x":          "trailing/x",
	}
	for in, want := range cases {
		if got := SanitizePath(in); got != want {
			t.Errorf("SanitizePath(%q) = %q, want %q", in, got, want)
		}
	}
}
