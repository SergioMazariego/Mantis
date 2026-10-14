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

var ErrAuditIntegrity = errors.New("audit chain integrity failure")

type AuditEvent struct {
	Number       int64
	ActorID      string
	Operation    string
	TargetID     string
	OccurredAt   string
	PreviousHash string
	Hash         string
}

type auditPayload struct {
	Version      int    `json:"version"`
	TenantID     string `json:"tenant_id"`
	CaseID       string `json:"case_id"`
	Number       int64  `json:"number"`
	ActorID      string `json:"actor_id"`
	Operation    string `json:"operation"`
	TargetID     string `json:"target_id"`
	OccurredAt   string `json:"occurred_at"`
	PreviousHash string `json:"previous_hash"`
}

func auditHash(payload auditPayload) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func appendAudit(ctx context.Context, tx *sql.Tx, scope casecore.Scope, operation, target string) error {
	var previous AuditEvent
	err := tx.QueryRowContext(ctx, `SELECT event_no,event_hash FROM audit_events
		WHERE tenant_id=? AND case_id=? ORDER BY event_no DESC LIMIT 1`,
		scope.TenantID().String(), scope.CaseID().String()).Scan(&previous.Number, &previous.Hash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	number := previous.Number + 1
	when := time.Now().UTC().Format(time.RFC3339Nano)
	payload := auditPayload{1, scope.TenantID().String(), scope.CaseID().String(), number,
		scope.ActorID().String(), operation, target, when, previous.Hash}
	hash, err := auditHash(payload)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events
		(tenant_id,case_id,event_no,actor_id,operation,target_id,occurred_at,previous_hash,event_hash)
		VALUES(?,?,?,?,?,?,?,?,?)`, payload.TenantID, payload.CaseID, number, payload.ActorID,
		operation, target, when, previous.Hash, hash)
	return err
}

// VerifyAudit checks ordering and the hash chain for one authorized case.
// A later managed deployment must externally anchor the latest hash to detect
// an attacker who can replace the entire database.
func (s *Store) VerifyAudit(ctx context.Context, grant auth.Grant, scope casecore.Scope) ([]AuditEvent, error) {
	if !grant.Allows(scope, auth.ActionReadCase) {
		return nil, auth.ErrDenied
	}
	if _, err := s.GetCase(ctx, grant, scope); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT event_no,actor_id,operation,target_id,occurred_at,previous_hash,event_hash
		FROM audit_events WHERE tenant_id=? AND case_id=? ORDER BY event_no`,
		scope.TenantID().String(), scope.CaseID().String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []AuditEvent
	previous := ""
	for rows.Next() {
		var event AuditEvent
		if err := rows.Scan(&event.Number, &event.ActorID, &event.Operation, &event.TargetID,
			&event.OccurredAt, &event.PreviousHash, &event.Hash); err != nil {
			return nil, err
		}
		if event.Number != int64(len(events)+1) || event.PreviousHash != previous {
			return nil, ErrAuditIntegrity
		}
		expected, err := auditHash(auditPayload{1, scope.TenantID().String(), scope.CaseID().String(),
			event.Number, event.ActorID, event.Operation, event.TargetID, event.OccurredAt, event.PreviousHash})
		if err != nil {
			return nil, err
		}
		if event.Hash != expected {
			return nil, fmt.Errorf("event %d: %w", event.Number, ErrAuditIntegrity)
		}
		previous = event.Hash
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, ErrAuditIntegrity
	}
	return events, nil
}
