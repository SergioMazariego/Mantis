package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/SergioMazariego/Mantis/v2/internal/casecore"
)

type membershipReaderFunc func(context.Context, casecore.TenantID, casecore.CaseID, casecore.ActorID) (Membership, error)

func (f membershipReaderFunc) LookupMembership(ctx context.Context, tenant casecore.TenantID, caseID casecore.CaseID, actor casecore.ActorID) (Membership, error) {
	return f(ctx, tenant, caseID, actor)
}

func testScope(t *testing.T, tenant, caseID, actor string) casecore.Scope {
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

func member(scope casecore.Scope, role Role) Membership {
	return Membership{TenantID: scope.TenantID(), CaseID: scope.CaseID(), ActorID: scope.ActorID(), Role: role, Active: true}
}

func authorizer(t *testing.T, lookup membershipReaderFunc) *Authorizer {
	t.Helper()
	a, err := NewAuthorizer(lookup)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestGrantBoundToTenantCaseActorAndAction(t *testing.T) {
	scope := testScope(t, "tenant-a", "case-a", "analyst-a")
	a := authorizer(t, func(_ context.Context, _ casecore.TenantID, _ casecore.CaseID, _ casecore.ActorID) (Membership, error) {
		return member(scope, RoleInvestigator), nil
	})
	grant, err := a.Authorize(context.Background(), scope, ActionReadEvidence)
	if err != nil || !grant.Allows(scope, ActionReadEvidence) {
		t.Fatalf("expected scoped read grant: %v", err)
	}
	for _, other := range []casecore.Scope{
		testScope(t, "tenant-b", "case-a", "analyst-a"),
		testScope(t, "tenant-a", "case-b", "analyst-a"),
		testScope(t, "tenant-a", "case-a", "analyst-b"),
	} {
		if grant.Allows(other, ActionReadEvidence) {
			t.Fatalf("grant escaped scope: %+v", other)
		}
	}
	if grant.Allows(scope, ActionExportEvidence) || (Grant{}).Allows(scope, ActionReadEvidence) {
		t.Fatal("grant escaped action or zero grant was accepted")
	}
}

func TestDenyCrossCaseAndCrossTenant(t *testing.T) {
	allowed := testScope(t, "tenant-a", "case-a", "analyst-a")
	a := authorizer(t, func(_ context.Context, tenant casecore.TenantID, caseID casecore.CaseID, actor casecore.ActorID) (Membership, error) {
		if tenant == allowed.TenantID() && caseID == allowed.CaseID() && actor == allowed.ActorID() {
			return member(allowed, RoleInvestigator), nil
		}
		return Membership{}, ErrMembershipNotFound
	})
	for _, scope := range []casecore.Scope{
		testScope(t, "tenant-a", "case-b", "analyst-a"),
		testScope(t, "tenant-b", "case-a", "analyst-a"),
		testScope(t, "tenant-a", "case-a", "analyst-b"),
	} {
		grant, err := a.Authorize(context.Background(), scope, ActionReadEvidence)
		if !errors.Is(err, ErrDenied) || grant.Allows(scope, ActionReadEvidence) {
			t.Fatalf("unauthorized scope granted: %+v, %v", scope, err)
		}
	}
}

func TestDenyForgedOrInactiveMembership(t *testing.T) {
	scope := testScope(t, "tenant-a", "case-a", "analyst-a")
	wrong := testScope(t, "tenant-a", "case-b", "analyst-a")
	for _, membership := range []Membership{member(wrong, RoleAdministrator), {TenantID: scope.TenantID(), CaseID: scope.CaseID(), ActorID: scope.ActorID(), Role: RoleAdministrator}} {
		a := authorizer(t, func(context.Context, casecore.TenantID, casecore.CaseID, casecore.ActorID) (Membership, error) {
			return membership, nil
		})
		if _, err := a.Authorize(context.Background(), scope, ActionReadCase); !errors.Is(err, ErrDenied) {
			t.Fatalf("accepted forged or inactive membership: %v", err)
		}
	}
}

func TestRoleMatrixAndUnknownAction(t *testing.T) {
	scope := testScope(t, "tenant-a", "case-a", "analyst-a")
	tests := []struct {
		role    Role
		action  Action
		allowed bool
	}{
		{RoleAdministrator, ActionManageMembership, true},
		{RoleInvestigator, ActionDraftFinding, true},
		{RoleInvestigator, ActionApproveFinding, false},
		{RoleReviewer, ActionApproveFinding, true},
		{RoleReviewer, ActionDispatchCollection, false},
		{RoleCollectorOperator, ActionDispatchCollection, true},
		{RoleCollectorOperator, ActionIngestEvidence, true},
		{RoleReadOnlyAuditor, ActionReadEvidence, true},
		{RoleReadOnlyAuditor, ActionIngestEvidence, false},
		{RoleReadOnlyAuditor, ActionExportEvidence, false},
		{Role("UNKNOWN"), ActionReadCase, false},
		{RoleAdministrator, Action("shell.execute"), false},
	}
	for _, tc := range tests {
		a := authorizer(t, func(context.Context, casecore.TenantID, casecore.CaseID, casecore.ActorID) (Membership, error) {
			return member(scope, tc.role), nil
		})
		grant, err := a.Authorize(context.Background(), scope, tc.action)
		if tc.allowed && (err != nil || !grant.Allows(scope, tc.action)) {
			t.Errorf("%s %s should pass: %v", tc.role, tc.action, err)
		}
		if !tc.allowed && (!errors.Is(err, ErrDenied) || grant.Allows(scope, tc.action)) {
			t.Errorf("%s %s should fail: %v", tc.role, tc.action, err)
		}
	}
}

func TestFailClosedOnStoreFailureAndInvalidInput(t *testing.T) {
	scope := testScope(t, "tenant-a", "case-a", "analyst-a")
	a := authorizer(t, func(context.Context, casecore.TenantID, casecore.CaseID, casecore.ActorID) (Membership, error) {
		return Membership{}, errors.New("database offline")
	})
	if _, err := a.Authorize(context.Background(), scope, ActionReadCase); !errors.Is(err, ErrAuthorizationUnavailable) {
		t.Fatalf("store failure: %v", err)
	}
	if _, err := a.Authorize(context.Background(), casecore.Scope{}, ActionReadCase); !errors.Is(err, ErrDenied) {
		t.Fatalf("zero scope: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.Authorize(ctx, scope, ActionReadCase); !errors.Is(err, ErrAuthorizationUnavailable) {
		t.Fatalf("canceled context: %v", err)
	}
	if _, err := NewAuthorizer(nil); !errors.Is(err, ErrAuthorizationUnavailable) {
		t.Fatalf("nil store: %v", err)
	}
	var typedNil *nilReader
	if _, err := NewAuthorizer(typedNil); !errors.Is(err, ErrAuthorizationUnavailable) {
		t.Fatalf("typed nil store: %v", err)
	}
}

type nilReader struct{}

func (*nilReader) LookupMembership(context.Context, casecore.TenantID, casecore.CaseID, casecore.ActorID) (Membership, error) {
	panic("typed nil reader must be rejected before lookup")
}
