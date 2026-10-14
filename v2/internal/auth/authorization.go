// Package auth enforces case membership and coarse case roles in the backend.
// Capability policy and action-specific approvals are separate, later gates.
package auth

import (
	"context"
	"errors"
	"reflect"

	"github.com/SergioMazariego/Mantis/v2/internal/casecore"
)

var (
	ErrDenied                   = errors.New("case access denied")
	ErrAuthorizationUnavailable = errors.New("case authorization unavailable")
	ErrMembershipNotFound       = errors.New("case membership not found")
)

type Role string

const (
	RoleAdministrator     Role = "ADMINISTRATOR"
	RoleCaseLead          Role = "CASE_LEAD"
	RoleInvestigator      Role = "INVESTIGATOR"
	RoleReviewer          Role = "REVIEWER"
	RoleCollectorOperator Role = "COLLECTOR_OPERATOR"
	RoleReadOnlyAuditor   Role = "READ_ONLY_AUDITOR"
)

func (role Role) Valid() bool {
	switch role {
	case RoleAdministrator, RoleCaseLead, RoleInvestigator, RoleReviewer,
		RoleCollectorOperator, RoleReadOnlyAuditor:
		return true
	default:
		return false
	}
}

type Action string

const (
	ActionReadCase           Action = "case.read"
	ActionReadEvidence       Action = "evidence.read"
	ActionIngestEvidence     Action = "evidence.ingest"
	ActionWriteNotes         Action = "case.notes.write"
	ActionManageHypotheses   Action = "hypothesis.manage"
	ActionDraftFinding       Action = "finding.draft"
	ActionApproveFinding     Action = "finding.approve"
	ActionRequestCollection  Action = "collection.request"
	ActionDispatchCollection Action = "collection.dispatch"
	ActionManageMembership   Action = "case.membership.manage"
	ActionExportEvidence     Action = "evidence.export"
)

// Membership is the case-scoped record returned by a trusted backend store.
// The authorizer verifies every returned identity rather than trusting the lookup.
type Membership struct {
	TenantID casecore.TenantID
	CaseID   casecore.CaseID
	ActorID  casecore.ActorID
	Role     Role
	Active   bool
}

type MembershipReader interface {
	LookupMembership(context.Context, casecore.TenantID, casecore.CaseID, casecore.ActorID) (Membership, error)
}

type Authorizer struct {
	reader MembershipReader
}

func NewAuthorizer(reader MembershipReader) (*Authorizer, error) {
	if reader == nil {
		return nil, ErrAuthorizationUnavailable
	}
	v := reflect.ValueOf(reader)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if v.IsNil() {
			return nil, ErrAuthorizationUnavailable
		}
	}
	return &Authorizer{reader: reader}, nil
}

// Grant can only be issued by Authorize. It is for one backend operation and
// must not be cached across requests or membership changes. A repository must
// check Allows for its exact scope and action before accessing case data.
type Grant struct {
	scope  casecore.Scope
	action Action
}

func (grant Grant) Allows(scope casecore.Scope, action Action) bool {
	return grant.scope.Valid() && scope.Valid() && grant.scope == scope && grant.action == action
}

func (a *Authorizer) Authorize(ctx context.Context, scope casecore.Scope, action Action) (Grant, error) {
	if !scope.Valid() || ctx == nil || !knownAction(action) {
		return Grant{}, ErrDenied
	}
	if ctx.Err() != nil {
		return Grant{}, ErrAuthorizationUnavailable
	}
	if a == nil || a.reader == nil {
		return Grant{}, ErrAuthorizationUnavailable
	}
	membership, err := a.reader.LookupMembership(ctx, scope.TenantID(), scope.CaseID(), scope.ActorID())
	if errors.Is(err, ErrMembershipNotFound) {
		return Grant{}, ErrDenied
	}
	if err != nil {
		return Grant{}, ErrAuthorizationUnavailable
	}
	if !membership.Active || membership.TenantID != scope.TenantID() ||
		membership.CaseID != scope.CaseID() || membership.ActorID != scope.ActorID() ||
		!roleAllows(membership.Role, action) {
		return Grant{}, ErrDenied
	}
	return Grant{scope: scope, action: action}, nil
}

func knownAction(action Action) bool {
	switch action {
	case ActionReadCase, ActionReadEvidence, ActionIngestEvidence, ActionWriteNotes, ActionManageHypotheses,
		ActionDraftFinding, ActionApproveFinding, ActionRequestCollection,
		ActionDispatchCollection, ActionManageMembership, ActionExportEvidence:
		return true
	default:
		return false
	}
}

func roleAllows(role Role, action Action) bool {
	switch role {
	case RoleAdministrator, RoleCaseLead:
		return true
	case RoleInvestigator:
		switch action {
		case ActionReadCase, ActionReadEvidence, ActionIngestEvidence, ActionWriteNotes, ActionManageHypotheses,
			ActionDraftFinding, ActionRequestCollection:
			return true
		}
	case RoleReviewer:
		switch action {
		case ActionReadCase, ActionReadEvidence, ActionWriteNotes,
			ActionApproveFinding, ActionExportEvidence:
			return true
		}
	case RoleCollectorOperator:
		switch action {
		case ActionReadCase, ActionReadEvidence, ActionIngestEvidence, ActionRequestCollection, ActionDispatchCollection:
			return true
		}
	case RoleReadOnlyAuditor:
		return action == ActionReadCase || action == ActionReadEvidence
	}
	return false
}

// RoleAllows is the shared coarse role rule for adapters that recheck current
// membership inside a write transaction after an operation grant was issued.
func RoleAllows(role Role, action Action) bool { return roleAllows(role, action) }
