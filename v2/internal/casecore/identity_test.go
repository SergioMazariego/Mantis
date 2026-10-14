package casecore

import (
	"errors"
	"testing"
)

func TestScopeRequiresAllValidatedIdentities(t *testing.T) {
	tenant, err := NewTenantID("local")
	if err != nil {
		t.Fatal(err)
	}
	caseID, err := NewCaseID("case-001")
	if err != nil {
		t.Fatal(err)
	}
	actor, err := NewActorID("analyst-001")
	if err != nil {
		t.Fatal(err)
	}
	scope, err := NewScope(tenant, caseID, actor)
	if err != nil {
		t.Fatal(err)
	}
	if scope.TenantID() != tenant || scope.CaseID() != caseID || scope.ActorID() != actor {
		t.Fatal("scope lost identity")
	}
	if _, err := NewScope(tenant, CaseID{}, actor); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("zero case accepted: %v", err)
	}
}

func TestIDsRejectPathsAndControlCharacters(t *testing.T) {
	for _, value := range []string{"", "../case", "case/other", "case\\other", "case\nother", ".hidden", "a b"} {
		if _, err := NewCaseID(value); !errors.Is(err, ErrInvalidID) {
			t.Errorf("accepted %q: %v", value, err)
		}
	}
}
