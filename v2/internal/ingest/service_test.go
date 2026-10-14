package ingest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SergioMazariego/Mantis/v2/internal/acquisition"
	"github.com/SergioMazariego/Mantis/v2/internal/auth"
	"github.com/SergioMazariego/Mantis/v2/internal/casecore"
	"github.com/SergioMazariego/Mantis/v2/internal/evidence"
	"github.com/SergioMazariego/Mantis/v2/internal/storage/sqlite"
)

func setup(t *testing.T) (*Service, *sqlite.Store, casecore.Scope, *auth.Authorizer, string) {
	t.Helper()
	tenant, _ := casecore.NewTenantID("tenant")
	caseID, _ := casecore.NewCaseID("case")
	actor, _ := casecore.NewActorID("lead")
	scope, err := casecore.NewScope(tenant, caseID, actor)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "cases.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.BootstrapCase(context.Background(), scope, "Case"); err != nil {
		t.Fatal(err)
	}
	authorizer, err := auth.NewAuthorizer(db)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "blobs")
	blobs, err := evidence.OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(context.Background(), authorizer, blobs, db)
	if err != nil {
		t.Fatal(err)
	}
	return service, db, scope, authorizer, root
}

func request(id string, budget int64) Request {
	return Request{ID: id, AssetID: "host-1", PlanDigest: strings.Repeat("a", 64),
		SourceKind: "windows.evtx", SourceLocator: "Security",
		SourceClock: acquisition.SourceClock{Status: "UNKNOWN", Description: "source offset unavailable"},
		Method:      "native-copy-v1", MaxBytes: budget}
}

func TestCollectAndReadAuditsCustody(t *testing.T) {
	service, db, scope, authorizer, _ := setup(t)
	ctx := context.Background()
	payload := []byte("synthetic event bytes")
	result, err := service.CollectOne(ctx, scope, request("acq-1", 1024), bytes.NewReader(payload))
	if err != nil || result.Status != acquisition.StatusCompleted {
		t.Fatalf("collect: %+v, %v", result, err)
	}
	if !result.Ready {
		t.Fatal("successful ingest not marked ready")
	}
	readCase, err := authorizer.Authorize(ctx, scope, auth.ActionReadCase)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := db.GetManifest(ctx, readCase, scope, "acq-1")
	if err != nil || len(manifest.Outputs) != 1 || manifest.Outputs[0].EvidenceSHA256 != result.Blob.SHA256 {
		t.Fatalf("manifest: %+v, %v", manifest, err)
	}
	file, err := service.OpenVerified(ctx, scope, result.Blob.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(file)
	file.Close()
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("read: %q, %v", got, err)
	}
	events, err := db.VerifyCustody(ctx, readCase, scope)
	if err != nil || len(events) != 2 || events[0].Action != sqlite.CustodyIngest || events[1].Action != sqlite.CustodyAccess {
		t.Fatalf("custody: %+v, %v", events, err)
	}
}

func TestFailedBudgetRecordsFailureWithoutSuccess(t *testing.T) {
	service, db, scope, authorizer, _ := setup(t)
	ctx := context.Background()
	result, err := service.CollectOne(ctx, scope, request("acq-failed", 3), bytes.NewBufferString("1234"))
	if !errors.Is(err, evidence.ErrTooLarge) || result.Status != acquisition.StatusFailed || result.Blob.SHA256 != "" {
		t.Fatalf("failed result: %+v, %v", result, err)
	}
	readCase, _ := authorizer.Authorize(ctx, scope, auth.ActionReadCase)
	manifest, err := db.GetManifest(ctx, readCase, scope, "acq-failed")
	if err != nil || manifest.Status != acquisition.StatusFailed || len(manifest.Outputs) != 0 || len(manifest.Errors) != 1 {
		t.Fatalf("false success: %+v, %v", manifest, err)
	}
	events, err := db.VerifyCustody(ctx, readCase, scope)
	if err != nil || len(events) != 0 {
		t.Fatalf("custody for failed capture: %+v, %v", events, err)
	}
}

func TestInvalidMetadataRejectedBeforeBlobWrite(t *testing.T) {
	service, _, scope, _, _ := setup(t)
	request := request("../bad", 1024)
	if _, err := service.CollectOne(context.Background(), scope, request, bytes.NewBufferString("bytes")); !errors.Is(err, acquisition.ErrInvalidManifest) {
		t.Fatalf("invalid request: %v", err)
	}
}

func TestStartupQuarantinesUnknownOrphanBlob(t *testing.T) {
	service, db, scope, authorizer, _ := setup(t)
	ctx := context.Background()
	grant, err := authorizer.Authorize(ctx, scope, auth.ActionIngestEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.StartIntent(ctx, grant, scope, "interrupted"); err != nil {
		t.Fatal(err)
	}
	blob, err := service.blobs.Put(ctx, grant, scope, bytes.NewBufferString("orphan bytes"), 1024)
	if err != nil {
		t.Fatal(err)
	}
	// Crash point: CAS published but the digest was not journaled.
	restarted, err := New(ctx, authorizer, service.blobs, db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.OpenVerified(ctx, scope, blob.SHA256); !errors.Is(err, sqlite.ErrIncompleteEvidence) {
		t.Fatalf("orphan exposed: %v", err)
	}
	if err := service.blobs.VerifyForRecovery(ctx, scope, blob.SHA256); err != nil {
		t.Fatalf("orphan lost: %v", err)
	}
	pending, err := db.ListPendingIntents(ctx)
	if err != nil || len(pending) != 1 || pending[0].State != sqlite.IntentRecoveryRequired {
		t.Fatalf("recovery state: %+v, %v", pending, err)
	}
}

func TestStartupCompletesFullyCommittedInterruptedIngest(t *testing.T) {
	service, db, scope, authorizer, _ := setup(t)
	ctx := context.Background()
	grant, err := authorizer.Authorize(ctx, scope, auth.ActionIngestEvidence)
	if err != nil {
		t.Fatal(err)
	}
	req := request("interrupted", 1024)
	if err := db.StartIntent(ctx, grant, scope, req.ID); err != nil {
		t.Fatal(err)
	}
	blob, err := service.blobs.Put(ctx, grant, scope, bytes.NewBufferString("captured bytes"), req.MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	m := acquisition.Manifest{Version: 1, Kind: "acquisition-manifest", ID: req.ID,
		CaseID: scope.CaseID().String(), AssetID: req.AssetID, PlanDigest: req.PlanDigest,
		StartedAt: "2026-01-01T00:00:00Z", CompletedAt: "2026-01-01T00:00:01Z",
		Status: acquisition.StatusCompleted, SourceKind: req.SourceKind,
		SourceLocator: req.SourceLocator, SourceClock: req.SourceClock, Method: req.Method,
		Outputs: []acquisition.Output{{EvidenceSHA256: blob.SHA256, SizeBytes: blob.SizeBytes, SourceLocator: req.SourceLocator}}}
	if _, err := db.PutManifest(ctx, grant, scope, m); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AppendCustody(ctx, grant, scope, blob.SHA256, sqlite.CustodyIngest,
		sqlite.CustodyDetails{AcquisitionID: req.ID}); err != nil {
		t.Fatal(err)
	}
	// Crash point: all components exist, but no journal transition was recorded.
	restarted, err := New(ctx, authorizer, service.blobs, db)
	if err != nil {
		t.Fatal(err)
	}
	file, err := restarted.OpenVerified(ctx, scope, blob.SHA256)
	if err != nil {
		t.Fatalf("complete evidence still quarantined: %v", err)
	}
	file.Close()
	pending, err := db.ListPendingIntents(ctx)
	if err != nil || len(pending) != 0 {
		t.Fatalf("recovery did not finish: %+v, %v", pending, err)
	}
}

func TestStartupQuarantinesPreviouslyCompleteCorruptBlob(t *testing.T) {
	service, db, scope, authorizer, root := setup(t)
	ctx := context.Background()
	result, err := service.CollectOne(ctx, scope, request("acq-corrupt", 1024), bytes.NewBufferString("original bytes"))
	if err != nil || !result.Ready {
		t.Fatalf("initial ingest: %+v, %v", result, err)
	}
	digest := result.Blob.SHA256
	path := filepath.Join(root, "tenants", "tenant", "cases", "case", "blobs", "sha256", digest[:2], digest[2:4], digest)
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(ctx, authorizer, service.blobs, db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.OpenVerified(ctx, scope, digest); !errors.Is(err, sqlite.ErrIncompleteEvidence) {
		t.Fatalf("corrupt blob exposed: %v", err)
	}
	pending, err := db.ListPendingIntents(ctx)
	if err != nil || len(pending) != 1 || pending[0].State != sqlite.IntentRecoveryRequired {
		t.Fatalf("corruption not journaled: %+v, %v", pending, err)
	}
}
