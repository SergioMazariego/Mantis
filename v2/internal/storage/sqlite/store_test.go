package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/SergioMazariego/Mantis/v2/internal/auth"
	"github.com/SergioMazariego/Mantis/v2/internal/casecore"
)

func ids(t *testing.T, tenant, caseID, actor string) casecore.Scope {
	t.Helper()
	tid, err := casecore.NewTenantID(tenant)
	if err != nil {
		t.Fatal(err)
	}
	cid, err := casecore.NewCaseID(caseID)
	if err != nil {
		t.Fatal(err)
	}
	aid, err := casecore.NewActorID(actor)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := casecore.NewScope(tid, cid, aid)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func grant(t *testing.T, s *Store, scope casecore.Scope, action auth.Action) auth.Grant {
	t.Helper()
	a, err := auth.NewAuthorizer(s)
	if err != nil {
		t.Fatal(err)
	}
	g, err := a.Authorize(context.Background(), scope, action)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestMembershipPersistsAndCasesRemainScoped(t *testing.T) {
	file := filepath.Join(t.TempDir(), "cases.sqlite")
	s, err := Open(file)
	if err != nil {
		t.Fatal(err)
	}
	leadA := ids(t, "tenant-a", "case-1", "lead")
	leadB := ids(t, "tenant-b", "case-1", "lead")
	ctx := context.Background()
	if err := s.BootstrapCase(ctx, leadA, "A"); err != nil {
		t.Fatal(err)
	}
	if err := s.BootstrapCase(ctx, leadB, "B"); err != nil {
		t.Fatal(err)
	}
	member, err := casecore.NewActorID("analyst")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetMembership(ctx, grant(t, s, leadA, auth.ActionManageMembership), leadA, member, auth.RoleInvestigator, true); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	analystA := ids(t, "tenant-a", "case-1", "analyst")
	a, err := auth.NewAuthorizer(s)
	if err != nil {
		t.Fatal(err)
	}
	read, err := a.Authorize(ctx, analystA, auth.ActionReadCase)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCase(ctx, read, analystA)
	if err != nil || got.Title != "A" {
		t.Fatalf("persisted case: %+v, %v", got, err)
	}
	if _, err := a.Authorize(ctx, ids(t, "tenant-b", "case-1", "analyst"), auth.ActionReadCase); !errors.Is(err, auth.ErrDenied) {
		t.Fatalf("cross-tenant access: %v", err)
	}
	if _, err := a.Authorize(ctx, ids(t, "tenant-a", "case-2", "analyst"), auth.ActionReadCase); !errors.Is(err, auth.ErrDenied) {
		t.Fatalf("cross-case access: %v", err)
	}
	if _, err := s.GetCase(ctx, read, leadB); !errors.Is(err, auth.ErrDenied) {
		t.Fatalf("grant reused across tenant: %v", err)
	}
}

func TestRevocationInvalidatesOldGrantAndAuditIsAppendOnly(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "cases.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	lead := ids(t, "tenant", "case", "lead")
	if err := s.BootstrapCase(ctx, lead, "Case"); err != nil {
		t.Fatal(err)
	}
	member, _ := casecore.NewActorID("analyst")
	manage := grant(t, s, lead, auth.ActionManageMembership)
	if err := s.SetMembership(ctx, manage, lead, member, auth.RoleInvestigator, true); err != nil {
		t.Fatal(err)
	}
	analyst := ids(t, "tenant", "case", "analyst")
	oldRead := grant(t, s, analyst, auth.ActionReadCase)
	if err := s.SetMembership(ctx, manage, lead, member, auth.RoleInvestigator, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetCase(ctx, oldRead, analyst); !errors.Is(err, ErrCaseNotFound) {
		t.Fatalf("revoked grant read: %v", err)
	}
	if _, err := s.VerifyAudit(ctx, oldRead, analyst); !errors.Is(err, ErrCaseNotFound) {
		t.Fatalf("revoked grant audit read: %v", err)
	}
	events, err := s.VerifyAudit(ctx, grant(t, s, lead, auth.ActionReadCase), lead)
	if err != nil || len(events) != 3 {
		t.Fatalf("audit events: %d, %v", len(events), err)
	}
	if _, err := s.db.Exec(`UPDATE audit_events SET operation='changed' WHERE event_no=2`); err == nil {
		t.Fatal("audit update was accepted")
	}
	if _, err := s.db.Exec(`DELETE FROM audit_events WHERE event_no=2`); err == nil {
		t.Fatal("audit deletion was accepted")
	}
	if _, err := s.VerifyAudit(ctx, grant(t, s, lead, auth.ActionReadCase), lead); err != nil {
		t.Fatalf("audit changed after rejected edit: %v", err)
	}
}

func TestMembershipChangeRollsBackWhenAuditFails(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "cases.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	lead := ids(t, "tenant", "case", "lead")
	if err := s.BootstrapCase(ctx, lead, "Case"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER reject_audit BEFORE INSERT ON audit_events
		BEGIN SELECT RAISE(ABORT, 'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	member, _ := casecore.NewActorID("analyst")
	if err := s.SetMembership(ctx, grant(t, s, lead, auth.ActionManageMembership), lead, member, auth.RoleInvestigator, true); err == nil {
		t.Fatal("write succeeded without audit")
	}
	if _, err := s.LookupMembership(ctx, lead.TenantID(), lead.CaseID(), member); !errors.Is(err, auth.ErrMembershipNotFound) {
		t.Fatalf("membership survived rollback: %v", err)
	}
}
