package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SergioMazariego/Mantis/v2/internal/acquisition"
	"github.com/SergioMazariego/Mantis/v2/internal/auth"
)

func TestIntentStateRequiresAllComponents(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "cases.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	scope := ids(t, "tenant", "case", "lead")
	if err := s.BootstrapCase(ctx, scope, "Case"); err != nil {
		t.Fatal(err)
	}
	write := grant(t, s, scope, auth.ActionIngestEvidence)
	read := grant(t, s, scope, auth.ActionReadEvidence)
	digest := strings.Repeat("b", 64)
	if err := s.StartIntent(ctx, write, scope, "acq-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.HasCompleteBlob(ctx, read, scope, digest); !errors.Is(err, ErrIncompleteEvidence) {
		t.Fatalf("prepared exposed: %v", err)
	}
	if err := s.AdvanceIntent(ctx, write, scope, "acq-1", IntentCustodyCommitted, digest, strings.Repeat("c", 64), ""); !errors.Is(err, ErrIncompleteEvidence) {
		t.Fatalf("premature completion: %v", err)
	}
	if err := s.AdvanceIntent(ctx, write, scope, "acq-1", IntentBlobVerified, digest, "", ""); err != nil {
		t.Fatal(err)
	}
	m := sampleManifest(acquisition.StatusCompleted)
	manifestSHA, err := s.PutManifest(ctx, write, scope, m)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AdvanceIntent(ctx, write, scope, "acq-1", IntentMetadataCommitted, digest, manifestSHA, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.HasCompleteBlob(ctx, read, scope, digest); !errors.Is(err, ErrIncompleteEvidence) {
		t.Fatalf("no custody exposed: %v", err)
	}
	if _, err := s.AppendCustody(ctx, write, scope, digest, CustodyIngest, CustodyDetails{AcquisitionID: "acq-1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AdvanceIntent(ctx, write, scope, "acq-1", IntentCustodyCommitted, digest, manifestSHA, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.HasCompleteBlob(ctx, read, scope, digest); err != nil {
		t.Fatalf("complete blocked: %v", err)
	}
	if err := s.VerifyIntentChain(ctx, "tenant", "case", "acq-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE ingest_intent_events SET state='changed'`); err == nil {
		t.Fatal("intent update accepted")
	}
	if _, err := s.db.Exec(`DELETE FROM ingest_intent_events`); err == nil {
		t.Fatal("intent delete accepted")
	}
}

func TestIntentHashDetectsPrivilegedTamper(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "cases.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	scope := ids(t, "tenant", "case", "lead")
	if err := s.BootstrapCase(ctx, scope, "Case"); err != nil {
		t.Fatal(err)
	}
	if err := s.StartIntent(ctx, grant(t, s, scope, auth.ActionIngestEvidence), scope, "acq-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER intent_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE ingest_intent_events SET reason='forged' WHERE acquisition_id='acq-1'`); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyIntentChain(ctx, "tenant", "case", "acq-1"); !errors.Is(err, ErrIntentIntegrity) {
		t.Fatalf("tamper undetected: %v", err)
	}
}
