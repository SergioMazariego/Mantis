package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/SergioMazariego/Mantis/v2/internal/acquisition"
	"github.com/SergioMazariego/Mantis/v2/internal/auth"
	"github.com/SergioMazariego/Mantis/v2/internal/casecore"
)

var (
	ErrInvalidIntent      = errors.New("invalid ingest intent transition")
	ErrIncompleteEvidence = errors.New("evidence ingest is not complete")
	ErrIntentIntegrity    = errors.New("ingest intent integrity failure")
)

type IntentState string

const (
	IntentPrepared          IntentState = "PREPARED"
	IntentBlobVerified      IntentState = "BLOB_VERIFIED"
	IntentMetadataCommitted IntentState = "METADATA_COMMITTED"
	IntentCustodyCommitted  IntentState = "CUSTODY_COMMITTED"
	IntentRecoveryRequired  IntentState = "RECOVERY_REQUIRED"
)

type IngestIntent struct {
	TenantID       string
	CaseID         string
	AcquisitionID  string
	ActorID        string
	State          IntentState
	EvidenceSHA256 string
	ManifestSHA256 string
	Reason         string
	Number         int64
	Hash           string
}

type intentPayload struct {
	Version        int         `json:"version"`
	TenantID       string      `json:"tenant_id"`
	CaseID         string      `json:"case_id"`
	AcquisitionID  string      `json:"acquisition_id"`
	Number         int64       `json:"number"`
	ActorID        string      `json:"actor_id"`
	State          IntentState `json:"state"`
	EvidenceSHA256 string      `json:"evidence_sha256"`
	ManifestSHA256 string      `json:"manifest_sha256"`
	Reason         string      `json:"reason"`
	OccurredAt     string      `json:"occurred_at"`
	PreviousHash   string      `json:"previous_hash"`
}

func intentDigest(p intentPayload) (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func latestIntentTx(ctx context.Context, tx *sql.Tx, scope casecore.Scope, acquisitionID string) (IngestIntent, error) {
	var intent IngestIntent
	intent.TenantID = scope.TenantID().String()
	intent.CaseID = scope.CaseID().String()
	intent.AcquisitionID = acquisitionID
	err := tx.QueryRowContext(ctx, `SELECT event_no,actor_id,state,evidence_sha256,manifest_sha256,reason,event_hash
		FROM ingest_intent_events WHERE tenant_id=? AND case_id=? AND acquisition_id=?
		ORDER BY event_no DESC LIMIT 1`, intent.TenantID, intent.CaseID, acquisitionID).Scan(
		&intent.Number, &intent.ActorID, &intent.State, &intent.EvidenceSHA256, &intent.ManifestSHA256, &intent.Reason, &intent.Hash)
	return intent, err
}

func appendIntentTx(ctx context.Context, tx *sql.Tx, scope casecore.Scope, acquisitionID string,
	state IntentState, blobSHA, manifestSHA, reason string) (IngestIntent, error) {
	previous, err := latestIntentTx(ctx, tx, scope, acquisitionID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return IngestIntent{}, err
	}
	if state == IntentPrepared {
		if err == nil || blobSHA != "" || manifestSHA != "" {
			return IngestIntent{}, ErrInvalidIntent
		}
	} else {
		if errors.Is(err, sql.ErrNoRows) || previous.State == IntentCustodyCommitted && state != IntentRecoveryRequired {
			return IngestIntent{}, ErrInvalidIntent
		}
		if previous.EvidenceSHA256 != "" && previous.EvidenceSHA256 != blobSHA {
			return IngestIntent{}, ErrInvalidIntent
		}
		if previous.ManifestSHA256 != "" && previous.ManifestSHA256 != manifestSHA {
			return IngestIntent{}, ErrInvalidIntent
		}
		switch state {
		case IntentBlobVerified:
			if previous.State != IntentPrepared || !validSHA256(blobSHA) || manifestSHA != "" {
				return IngestIntent{}, ErrInvalidIntent
			}
		case IntentMetadataCommitted:
			if previous.State != IntentBlobVerified || !validSHA256(blobSHA) || !validSHA256(manifestSHA) {
				return IngestIntent{}, ErrInvalidIntent
			}
		case IntentCustodyCommitted:
			if previous.State != IntentMetadataCommitted && previous.State != IntentRecoveryRequired {
				return IngestIntent{}, ErrInvalidIntent
			}
			if !validSHA256(blobSHA) || !validSHA256(manifestSHA) {
				return IngestIntent{}, ErrInvalidIntent
			}
		case IntentRecoveryRequired:
			if strings.TrimSpace(reason) == "" || len(reason) > 256 || previous.State == IntentRecoveryRequired && previous.Reason == reason {
				return IngestIntent{}, ErrInvalidIntent
			}
		default:
			return IngestIntent{}, ErrInvalidIntent
		}
	}
	p := intentPayload{Version: 1, TenantID: scope.TenantID().String(), CaseID: scope.CaseID().String(),
		AcquisitionID: acquisitionID, Number: previous.Number + 1, ActorID: scope.ActorID().String(), State: state,
		EvidenceSHA256: blobSHA, ManifestSHA256: manifestSHA, Reason: reason,
		OccurredAt: time.Now().UTC().Format(time.RFC3339Nano), PreviousHash: previous.Hash}
	digest, err := intentDigest(p)
	if err != nil {
		return IngestIntent{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO ingest_intent_events
		(tenant_id,case_id,acquisition_id,event_no,actor_id,state,evidence_sha256,manifest_sha256,reason,occurred_at,previous_hash,event_hash)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, p.TenantID, p.CaseID, p.AcquisitionID, p.Number, p.ActorID, string(state),
		blobSHA, manifestSHA, reason, p.OccurredAt, p.PreviousHash, digest)
	if err != nil {
		return IngestIntent{}, err
	}
	if err := appendAudit(ctx, tx, scope, "ingest."+string(state), acquisitionID); err != nil {
		return IngestIntent{}, err
	}
	return IngestIntent{p.TenantID, p.CaseID, acquisitionID, p.ActorID, state, blobSHA, manifestSHA, reason, p.Number, digest}, nil
}

func (s *Store) StartIntent(ctx context.Context, grant auth.Grant, scope casecore.Scope, acquisitionID string) error {
	if !grant.Allows(scope, auth.ActionIngestEvidence) {
		return auth.ErrDenied
	}
	if !validRecordID(acquisitionID) {
		return ErrInvalidIntent
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.currentRole(ctx, tx, scope, auth.ActionIngestEvidence); err != nil {
		return err
	}
	if _, err := appendIntentTx(ctx, tx, scope, acquisitionID, IntentPrepared, "", "", ""); err != nil {
		return err
	}
	return tx.Commit()
}

// AdvanceIntent enforces the normal ingest sequence and checks referenced
// metadata before completion. Recovery transitions use ReconcileIntent.
func (s *Store) AdvanceIntent(ctx context.Context, grant auth.Grant, scope casecore.Scope,
	acquisitionID string, state IntentState, blobSHA, manifestSHA, reason string) error {
	if !grant.Allows(scope, auth.ActionIngestEvidence) {
		return auth.ErrDenied
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.currentRole(ctx, tx, scope, auth.ActionIngestEvidence); err != nil {
		return err
	}
	if state == IntentMetadataCommitted || state == IntentCustodyCommitted {
		if err := verifyIntentReferencesTx(ctx, tx, scope, acquisitionID, blobSHA, manifestSHA, state == IntentCustodyCommitted); err != nil {
			return err
		}
	}
	if _, err := appendIntentTx(ctx, tx, scope, acquisitionID, state, blobSHA, manifestSHA, reason); err != nil {
		return err
	}
	return tx.Commit()
}

func verifyIntentReferencesTx(ctx context.Context, tx *sql.Tx, scope casecore.Scope, acquisitionID, blobSHA, manifestSHA string, requireCustody bool) error {
	var raw []byte
	var stored string
	err := tx.QueryRowContext(ctx, `SELECT manifest_json,manifest_sha256 FROM acquisition_manifests
		WHERE tenant_id=? AND case_id=? AND acquisition_id=?`, scope.TenantID().String(), scope.CaseID().String(), acquisitionID).Scan(&raw, &stored)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrIncompleteEvidence
	}
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if stored != manifestSHA || stored != hex.EncodeToString(sum[:]) {
		return ErrIntentIntegrity
	}
	var manifest acquisition.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return ErrIntentIntegrity
	}
	canonical, _, err := manifest.CanonicalBytes()
	if err != nil || string(canonical) != string(raw) || manifest.ID != acquisitionID || manifest.CaseID != scope.CaseID().String() || manifest.Status != acquisition.StatusCompleted {
		return ErrIntentIntegrity
	}
	listed := false
	for _, output := range manifest.Outputs {
		if output.EvidenceSHA256 == blobSHA {
			listed = true
			break
		}
	}
	if !listed {
		return ErrIntentIntegrity
	}
	if !requireCustody {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT details_json FROM custody_events WHERE tenant_id=? AND case_id=? AND evidence_sha256=? AND action='INGEST'`, scope.TenantID().String(), scope.CaseID().String(), blobSHA)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var rawDetails []byte
		if err := rows.Scan(&rawDetails); err != nil {
			return err
		}
		var details CustodyDetails
		if json.Unmarshal(rawDetails, &details) == nil && details.AcquisitionID == acquisitionID {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return ErrIncompleteEvidence
}

// HasCompleteBlob checks the latest intent state for the exact case and hash.
// Unfinished and quarantined bytes are never presented as complete evidence.
func (s *Store) HasCompleteBlob(ctx context.Context, grant auth.Grant, scope casecore.Scope, digest string) error {
	if !grant.Allows(scope, auth.ActionReadEvidence) {
		return auth.ErrDenied
	}
	if !validSHA256(digest) {
		return ErrInvalidIntent
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.currentRole(ctx, tx, scope, auth.ActionReadEvidence); err != nil {
		return err
	}
	var acquisitionID, manifestSHA string
	err = tx.QueryRowContext(ctx, `SELECT e.acquisition_id,e.manifest_sha256 FROM ingest_intent_events e WHERE e.tenant_id=? AND e.case_id=?
		AND e.evidence_sha256=? AND e.state=? AND e.event_no=(SELECT MAX(x.event_no)
		FROM ingest_intent_events x WHERE x.tenant_id=e.tenant_id AND x.case_id=e.case_id
		AND x.acquisition_id=e.acquisition_id) LIMIT 1`, scope.TenantID().String(), scope.CaseID().String(), digest, string(IntentCustodyCommitted)).Scan(&acquisitionID, &manifestSHA)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrIncompleteEvidence
	}
	if err != nil {
		return err
	}
	if err := verifyIntentReferencesTx(ctx, tx, scope, acquisitionID, digest, manifestSHA, true); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.VerifyIntentChain(ctx, scope.TenantID().String(), scope.CaseID().String(), acquisitionID)
}

// ListPendingIntents is a trusted startup-maintenance API, never an end-user
// query. It returns all nonterminal case-local operations for reconciliation.
func (s *Store) ListPendingIntents(ctx context.Context) ([]IngestIntent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT e.tenant_id,e.case_id,e.acquisition_id,e.actor_id,e.state,
		e.evidence_sha256,e.manifest_sha256,e.reason,e.event_no,e.event_hash
		FROM ingest_intent_events e WHERE e.event_no=(SELECT MAX(x.event_no)
		FROM ingest_intent_events x WHERE x.tenant_id=e.tenant_id AND x.case_id=e.case_id
		AND x.acquisition_id=e.acquisition_id) AND e.state<>?`, string(IntentCustodyCommitted))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var intents []IngestIntent
	for rows.Next() {
		var item IngestIntent
		if err := rows.Scan(&item.TenantID, &item.CaseID, &item.AcquisitionID, &item.ActorID, &item.State,
			&item.EvidenceSHA256, &item.ManifestSHA256, &item.Reason, &item.Number, &item.Hash); err != nil {
			return nil, err
		}
		intents = append(intents, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, intent := range intents {
		if err := s.VerifyIntentChain(ctx, intent.TenantID, intent.CaseID, intent.AcquisitionID); err != nil {
			return nil, err
		}
	}
	return intents, nil
}

// ListCompleteIntents supports startup integrity checks on evidence that was
// previously complete but may have been corrupted or removed on disk.
func (s *Store) ListCompleteIntents(ctx context.Context) ([]IngestIntent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT e.tenant_id,e.case_id,e.acquisition_id,e.actor_id,e.state,
		e.evidence_sha256,e.manifest_sha256,e.reason,e.event_no,e.event_hash
		FROM ingest_intent_events e WHERE e.event_no=(SELECT MAX(x.event_no)
		FROM ingest_intent_events x WHERE x.tenant_id=e.tenant_id AND x.case_id=e.case_id
		AND x.acquisition_id=e.acquisition_id) AND e.state=?`, string(IntentCustodyCommitted))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var intents []IngestIntent
	for rows.Next() {
		var item IngestIntent
		if err := rows.Scan(&item.TenantID, &item.CaseID, &item.AcquisitionID, &item.ActorID, &item.State,
			&item.EvidenceSHA256, &item.ManifestSHA256, &item.Reason, &item.Number, &item.Hash); err != nil {
			return nil, err
		}
		intents = append(intents, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, intent := range intents {
		if err := s.VerifyIntentChain(ctx, intent.TenantID, intent.CaseID, intent.AcquisitionID); err != nil {
			return nil, err
		}
	}
	return intents, nil
}

// VerifyIntentChain validates the append-only record for one acquisition.
// It is trusted maintenance code; caller-facing reads use HasCompleteBlob.
func (s *Store) VerifyIntentChain(ctx context.Context, tenantID, caseID, acquisitionID string) error {
	rows, err := s.db.QueryContext(ctx, `SELECT event_no,actor_id,state,evidence_sha256,
		manifest_sha256,reason,occurred_at,previous_hash,event_hash FROM ingest_intent_events
		WHERE tenant_id=? AND case_id=? AND acquisition_id=? ORDER BY event_no`, tenantID, caseID, acquisitionID)
	if err != nil {
		return err
	}
	defer rows.Close()
	var number int64
	previousHash := ""
	previousState := IntentState("")
	for rows.Next() {
		var p intentPayload
		var storedHash string
		if err := rows.Scan(&p.Number, &p.ActorID, &p.State, &p.EvidenceSHA256,
			&p.ManifestSHA256, &p.Reason, &p.OccurredAt, &p.PreviousHash, &storedHash); err != nil {
			return err
		}
		p.Version = 1
		p.TenantID = tenantID
		p.CaseID = caseID
		p.AcquisitionID = acquisitionID
		number++
		if p.Number != number || p.PreviousHash != previousHash || p.ActorID == "" {
			return ErrIntentIntegrity
		}
		if number == 1 && p.State != IntentPrepared || number > 1 && previousState == IntentCustodyCommitted && p.State != IntentRecoveryRequired {
			return ErrIntentIntegrity
		}
		if p.EvidenceSHA256 != "" && !validSHA256(p.EvidenceSHA256) || p.ManifestSHA256 != "" && !validSHA256(p.ManifestSHA256) {
			return ErrIntentIntegrity
		}
		expected, err := intentDigest(p)
		if err != nil {
			return err
		}
		if storedHash != expected {
			return fmt.Errorf("intent event %d: %w", number, ErrIntentIntegrity)
		}
		previousHash = storedHash
		previousState = p.State
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if number == 0 {
		return ErrIntentIntegrity
	}
	return nil
}

// EnrichIntent discovers a manifest committed just before a crash, after the
// blob was written but before its journal transition was persisted.
func (s *Store) EnrichIntent(ctx context.Context, intent IngestIntent) (IngestIntent, error) {
	var raw []byte
	var stored string
	err := s.db.QueryRowContext(ctx, `SELECT manifest_json,manifest_sha256 FROM acquisition_manifests
		WHERE tenant_id=? AND case_id=? AND acquisition_id=?`, intent.TenantID, intent.CaseID,
		intent.AcquisitionID).Scan(&raw, &stored)
	if errors.Is(err, sql.ErrNoRows) {
		return intent, nil
	}
	if err != nil {
		return intent, err
	}
	sum := sha256.Sum256(raw)
	if stored != hex.EncodeToString(sum[:]) {
		return intent, ErrIntentIntegrity
	}
	var manifest acquisition.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return intent, ErrIntentIntegrity
	}
	canonical, _, err := manifest.CanonicalBytes()
	if err != nil || string(canonical) != string(raw) || manifest.ID != intent.AcquisitionID || manifest.CaseID != intent.CaseID {
		return intent, ErrIntentIntegrity
	}
	if intent.ManifestSHA256 != "" && intent.ManifestSHA256 != stored {
		return intent, ErrIntentIntegrity
	}
	intent.ManifestSHA256 = stored
	if manifest.Status == acquisition.StatusCompleted && len(manifest.Outputs) == 1 {
		blob := manifest.Outputs[0].EvidenceSHA256
		if intent.EvidenceSHA256 != "" && intent.EvidenceSHA256 != blob {
			return intent, ErrIntentIntegrity
		}
		intent.EvidenceSHA256 = blob
	}
	return intent, nil
}

// ReconcileIntent is trusted startup recovery. It checks the database links
// again and appends a system-attributed transition; it never removes bytes.
func (s *Store) ReconcileIntent(ctx context.Context, intent IngestIntent, blobVerified bool) error {
	tenant, err := casecore.NewTenantID(intent.TenantID)
	if err != nil {
		return err
	}
	caseID, err := casecore.NewCaseID(intent.CaseID)
	if err != nil {
		return err
	}
	actor, err := casecore.NewActorID("system-recovery")
	if err != nil {
		return err
	}
	scope, err := casecore.NewScope(tenant, caseID, actor)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	current, err := latestIntentTx(ctx, tx, scope, intent.AcquisitionID)
	if err != nil {
		return err
	}
	if current.Hash != intent.Hash || current.Number != intent.Number {
		return ErrIntentIntegrity
	}
	if current.EvidenceSHA256 != "" && current.EvidenceSHA256 != intent.EvidenceSHA256 {
		return ErrIntentIntegrity
	}
	if current.ManifestSHA256 != "" && current.ManifestSHA256 != intent.ManifestSHA256 {
		return ErrIntentIntegrity
	}
	complete := blobVerified && validSHA256(intent.EvidenceSHA256) && validSHA256(intent.ManifestSHA256)
	if complete {
		complete = verifyIntentReferencesTx(ctx, tx, scope, intent.AcquisitionID, intent.EvidenceSHA256, intent.ManifestSHA256, true) == nil
	}
	state := IntentRecoveryRequired
	reason := "incomplete or unverified ingest; preserve and quarantine bytes"
	if complete {
		state = IntentCustodyCommitted
		reason = "reconciled verified blob, manifest and custody"
	}
	if current.State == IntentCustodyCommitted && complete {
		return nil
	}
	if current.State == state && current.Reason == reason && current.EvidenceSHA256 == intent.EvidenceSHA256 && current.ManifestSHA256 == intent.ManifestSHA256 {
		return nil
	}
	if complete && current.State != IntentMetadataCommitted && current.State != IntentRecoveryRequired {
		if _, err := appendIntentTx(ctx, tx, scope, intent.AcquisitionID, IntentRecoveryRequired,
			intent.EvidenceSHA256, intent.ManifestSHA256, "recovery verified cross-store components"); err != nil {
			return err
		}
	}
	if _, err := appendIntentTx(ctx, tx, scope, intent.AcquisitionID, state, intent.EvidenceSHA256, intent.ManifestSHA256, reason); err != nil {
		return fmt.Errorf("reconcile %s: %w", intent.AcquisitionID, err)
	}
	return tx.Commit()
}
