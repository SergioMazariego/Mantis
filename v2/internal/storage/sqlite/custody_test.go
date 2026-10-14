package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SergioMazariego/Mantis/v2/internal/auth"
)

func TestCustodyChainAndAuthorization(t *testing.T) {
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
	digest := strings.Repeat("a", 64)
	write := grant(t, s, scope, auth.ActionIngestEvidence)
	read := grant(t, s, scope, auth.ActionReadEvidence)
	first, err := s.AppendCustody(ctx, write, scope, digest, CustodyIngest, CustodyDetails{AcquisitionID: "acq-1"})
	if err != nil || first.Number != 1 || first.PreviousHash != "" {
		t.Fatalf("first event: %+v, %v", first, err)
	}
	second, err := s.AppendCustody(ctx, read, scope, digest, CustodyAccess, CustodyDetails{Reason: "analysis"})
	if err != nil || second.Number != 2 || second.PreviousHash != first.Hash {
		t.Fatalf("second event: %+v, %v", second, err)
	}
	if _, err := s.AppendCustody(ctx, read, scope, digest, CustodyTransfer, CustodyDetails{}); !errors.Is(err, auth.ErrDenied) {
		t.Fatalf("read grant transfer: %v", err)
	}
	if _, err := s.AppendCustody(ctx, write, scope, digest, CustodyTransfer, CustodyDetails{}); !errors.Is(err, ErrInvalidCustody) {
		t.Fatalf("transfer without parties: %v", err)
	}
	if _, err := s.AppendCustody(ctx, write, scope, "bad", CustodyVerify, CustodyDetails{}); !errors.Is(err, ErrInvalidCustody) {
		t.Fatalf("bad digest: %v", err)
	}
	if _, err := s.AppendCustody(ctx, write, scope, digest, CustodyIngest, CustodyDetails{Reason: strings.Repeat("x", 4097)}); !errors.Is(err, ErrInvalidCustody) {
		t.Fatalf("unbounded detail accepted: %v", err)
	}
	events, err := s.VerifyCustody(ctx, grant(t, s, scope, auth.ActionReadCase), scope)
	if err != nil || len(events) != 2 || events[0].Hash != first.Hash || events[1].Hash != second.Hash {
		t.Fatalf("verify custody: %+v, %v", events, err)
	}
	if _, err := s.db.Exec(`UPDATE custody_events SET action='changed' WHERE event_no=1`); err == nil {
		t.Fatal("custody update accepted")
	}
	if _, err := s.db.Exec(`DELETE FROM custody_events WHERE event_no=1`); err == nil {
		t.Fatal("custody delete accepted")
	}
	other := ids(t, "tenant", "other", "lead")
	if _, err := s.VerifyCustody(ctx, grant(t, s, scope, auth.ActionReadCase), other); !errors.Is(err, auth.ErrDenied) {
		t.Fatalf("cross-case verify: %v", err)
	}
	audit, err := s.VerifyAudit(ctx, grant(t, s, scope, auth.ActionReadCase), scope)
	if err != nil || len(audit) != 3 {
		t.Fatalf("custody audit: %d, %v", len(audit), err)
	}
}

func TestCustodyRollsBackOnAuditFailure(t *testing.T) {
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
	if _, err := s.db.Exec(`CREATE TRIGGER reject_custody_audit BEFORE INSERT ON audit_events
		BEGIN SELECT RAISE(ABORT, 'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendCustody(ctx, grant(t, s, scope, auth.ActionIngestEvidence), scope,
		strings.Repeat("b", 64), CustodyIngest, CustodyDetails{}); err == nil {
		t.Fatal("custody write without audit succeeded")
	}
	events, err := s.VerifyCustody(ctx, grant(t, s, scope, auth.ActionReadCase), scope)
	if err != nil || len(events) != 0 {
		t.Fatalf("custody survived rollback: %+v, %v", events, err)
	}
}
