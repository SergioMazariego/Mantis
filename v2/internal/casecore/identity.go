// Package casecore defines identifiers and request scope shared by v2 modules.
// It does not make authorization decisions; callers must still enforce policy.
package casecore

import (
	"errors"
	"fmt"
)

var ErrInvalidID = errors.New("invalid case scope identifier")

type TenantID struct{ value string }
type CaseID struct{ value string }
type ActorID struct{ value string }

type Scope struct {
	tenant TenantID
	caseID CaseID
	actor  ActorID
}

func validID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		first := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		later := first || c == '.' || c == '_' || c == ':' || c == '-'
		if i == 0 && !first || i > 0 && !later {
			return false
		}
	}
	return true
}

func NewTenantID(value string) (TenantID, error) {
	if !validID(value) {
		return TenantID{}, fmt.Errorf("tenant ID: %w", ErrInvalidID)
	}
	return TenantID{value}, nil
}
func NewCaseID(value string) (CaseID, error) {
	if !validID(value) {
		return CaseID{}, fmt.Errorf("case ID: %w", ErrInvalidID)
	}
	return CaseID{value}, nil
}
func NewActorID(value string) (ActorID, error) {
	if !validID(value) {
		return ActorID{}, fmt.Errorf("actor ID: %w", ErrInvalidID)
	}
	return ActorID{value}, nil
}
func (id TenantID) String() string { return id.value }
func (id CaseID) String() string   { return id.value }
func (id ActorID) String() string  { return id.value }

func NewScope(tenant TenantID, caseID CaseID, actor ActorID) (Scope, error) {
	if tenant.value == "" || caseID.value == "" || actor.value == "" {
		return Scope{}, ErrInvalidID
	}
	return Scope{tenant: tenant, caseID: caseID, actor: actor}, nil
}
func (scope Scope) TenantID() TenantID { return scope.tenant }
func (scope Scope) CaseID() CaseID     { return scope.caseID }
func (scope Scope) ActorID() ActorID   { return scope.actor }

// Valid rejects a zero-value or otherwise incomplete scope at service boundaries.
func (scope Scope) Valid() bool {
	return validID(scope.tenant.value) && validID(scope.caseID.value) && validID(scope.actor.value)
}
