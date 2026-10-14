package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/SergioMazariego/Mantis/v2/internal/auth"
	"github.com/SergioMazariego/Mantis/v2/internal/casecore"
)

var (
	ErrInvalidCustody   = errors.New("invalid custody event")
	ErrCustodyIntegrity = errors.New("custody chain integrity failure")
)

type CustodyAction string

const (
	CustodyCapture  CustodyAction = "CAPTURE"
	CustodyTransfer CustodyAction = "TRANSFER"
	CustodyIngest   CustodyAction = "INGEST"
	CustodyVerify   CustodyAction = "VERIFY"
	CustodyAccess   CustodyAction = "ACCESS"
)

type CustodyDetails struct {
	AcquisitionID string `json:"acquisition_id"`
	From          string `json:"from"`
	To            string `json:"to"`
	Reason        string `json:"reason"`
}

type CustodyEvent struct {
	Number         int64
	EvidenceSHA256 string
	Action         CustodyAction
	ActorID        string
	OccurredAt     string
	Details        CustodyDetails
	PreviousHash   string
	Hash           string
}

type custodyPayload struct {
	Version        int            `json:"version"`
	TenantID       string         `json:"tenant_id"`
	CaseID         string         `json:"case_id"`
	Number         int64          `json:"number"`
	EvidenceSHA256 string         `json:"evidence_sha256"`
	Action         CustodyAction  `json:"action"`
	ActorID        string         `json:"actor_id"`
	OccurredAt     string         `json:"occurred_at"`
	Details        CustodyDetails `json:"details"`
	PreviousHash   string         `json:"previous_hash"`
}

func custodyDigest(payload custodyPayload) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, ch := range value {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return false
		}
	}
	return true
}

func custodyAllowed(action CustodyAction) bool {
	switch action {
	case CustodyCapture, CustodyTransfer, CustodyIngest, CustodyVerify, CustodyAccess:
		return true
	default:
		return false
	}
}

// AppendCustody journals one attested case event; it does not itself perform
// acquisition or transfer. A future signed endpoint receipt must back CAPTURE.
func (s *Store) AppendCustody(ctx context.Context, grant auth.Grant, scope casecore.Scope,
	evidenceSHA256 string, action CustodyAction, details CustodyDetails) (CustodyEvent, error) {
	needed := auth.ActionIngestEvidence
	if action == CustodyAccess {
		needed = auth.ActionReadEvidence
	}
	if !grant.Allows(scope, needed) {
		return CustodyEvent{}, auth.ErrDenied
	}
	if !validSHA256(evidenceSHA256) || !custodyAllowed(action) {
		return CustodyEvent{}, ErrInvalidCustody
	}
	if action == CustodyTransfer && (details.From == "" || details.To == "" || details.Reason == "") {
		return CustodyEvent{}, ErrInvalidCustody
	}
	if details.AcquisitionID != "" && !validRecordID(details.AcquisitionID) {
		return CustodyEvent{}, ErrInvalidCustody
	}
	if len(details.AcquisitionID) > 128 || len(details.From) > 256 || len(details.To) > 256 || len(details.Reason) > 4096 {
		return CustodyEvent{}, ErrInvalidCustody
	}
	detailBytes, err := json.Marshal(details)
	if err != nil {
		return CustodyEvent{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CustodyEvent{}, err
	}
	defer tx.Rollback()
	var role string
	var active int
	err = tx.QueryRowContext(ctx, `SELECT role,active FROM case_memberships WHERE tenant_id=? AND case_id=? AND actor_id=?`,
		scope.TenantID().String(), scope.CaseID().String(), scope.ActorID().String()).Scan(&role, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return CustodyEvent{}, auth.ErrDenied
	}
	if err != nil {
		return CustodyEvent{}, err
	}
	if active != 1 || !auth.RoleAllows(auth.Role(role), needed) {
		return CustodyEvent{}, auth.ErrDenied
	}
	var previous CustodyEvent
	err = tx.QueryRowContext(ctx, `SELECT event_no,event_hash FROM custody_events
		WHERE tenant_id=? AND case_id=? ORDER BY event_no DESC LIMIT 1`,
		scope.TenantID().String(), scope.CaseID().String()).Scan(&previous.Number, &previous.Hash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return CustodyEvent{}, err
	}
	payload := custodyPayload{Version: 1, TenantID: scope.TenantID().String(), CaseID: scope.CaseID().String(),
		Number: previous.Number + 1, EvidenceSHA256: evidenceSHA256, Action: action,
		ActorID: scope.ActorID().String(), OccurredAt: time.Now().UTC().Format(time.RFC3339Nano),
		Details: details, PreviousHash: previous.Hash}
	digest, err := custodyDigest(payload)
	if err != nil {
		return CustodyEvent{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO custody_events
		(tenant_id,case_id,event_no,evidence_sha256,action,actor_id,occurred_at,details_json,previous_hash,event_hash)
		VALUES(?,?,?,?,?,?,?,?,?,?)`, payload.TenantID, payload.CaseID, payload.Number, payload.EvidenceSHA256,
		string(action), payload.ActorID, payload.OccurredAt, detailBytes, payload.PreviousHash, digest)
	if err != nil {
		return CustodyEvent{}, err
	}
	if err := appendAudit(ctx, tx, scope, "custody."+string(action), evidenceSHA256); err != nil {
		return CustodyEvent{}, err
	}
	if err := tx.Commit(); err != nil {
		return CustodyEvent{}, err
	}
	return CustodyEvent{payload.Number, evidenceSHA256, action, payload.ActorID,
		payload.OccurredAt, details, payload.PreviousHash, digest}, nil
}

// VerifyCustody checks every recorded event in one authorized case. Callers
// should also verify the case audit chain for a complete journal check.
func (s *Store) VerifyCustody(ctx context.Context, grant auth.Grant, scope casecore.Scope) ([]CustodyEvent, error) {
	if !grant.Allows(scope, auth.ActionReadCase) {
		return nil, auth.ErrDenied
	}
	if _, err := s.GetCase(ctx, grant, scope); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT event_no,evidence_sha256,action,actor_id,occurred_at,
		details_json,previous_hash,event_hash FROM custody_events
		WHERE tenant_id=? AND case_id=? ORDER BY event_no`, scope.TenantID().String(), scope.CaseID().String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []CustodyEvent
	previous := ""
	for rows.Next() {
		var event CustodyEvent
		var details []byte
		if err := rows.Scan(&event.Number, &event.EvidenceSHA256, &event.Action, &event.ActorID,
			&event.OccurredAt, &details, &event.PreviousHash, &event.Hash); err != nil {
			return nil, err
		}
		if event.Number != int64(len(events)+1) || event.PreviousHash != previous ||
			!validSHA256(event.EvidenceSHA256) || !custodyAllowed(event.Action) {
			return nil, ErrCustodyIntegrity
		}
		if err := json.Unmarshal(details, &event.Details); err != nil {
			return nil, ErrCustodyIntegrity
		}
		canonical, err := json.Marshal(event.Details)
		if err != nil || string(canonical) != string(details) {
			return nil, ErrCustodyIntegrity
		}
		expected, err := custodyDigest(custodyPayload{1, scope.TenantID().String(), scope.CaseID().String(),
			event.Number, event.EvidenceSHA256, event.Action, event.ActorID, event.OccurredAt,
			event.Details, event.PreviousHash})
		if err != nil {
			return nil, err
		}
		if event.Hash != expected {
			return nil, fmt.Errorf("event %d: %w", event.Number, ErrCustodyIntegrity)
		}
		previous = event.Hash
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}
