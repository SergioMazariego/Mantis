package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/SergioMazariego/Mantis/v2/internal/acquisition"
	"github.com/SergioMazariego/Mantis/v2/internal/auth"
	"github.com/SergioMazariego/Mantis/v2/internal/casecore"
)

var (
	ErrInvalidProvenance = errors.New("invalid provenance record")
	ErrCitationNotFound  = errors.New("citation not found")
)

type Artifact struct {
	ID             string
	AssetID        string
	AcquisitionID  string
	EvidenceSHA256 string
	ArtifactType   string
	SourceLocator  string
}

type ParserRun struct {
	ID            string
	ArtifactID    string
	ParserName    string
	ParserVersion string
	ConfigSHA256  string
	Status        string // SUCCEEDED, PARTIAL or FAILED
}

type RecordProvenance struct {
	ID           string
	ParserRunID  string
	Locator      string
	RecordSHA256 string
}

type Citation struct {
	TenantID       string
	CaseID         string
	RecordID       string
	RecordLocator  string
	RecordSHA256   string
	ParserRunID    string
	ParserName     string
	ParserVersion  string
	ConfigSHA256   string
	ArtifactID     string
	ArtifactType   string
	AssetID        string
	SourceLocator  string
	AcquisitionID  string
	EvidenceSHA256 string
	ManifestSHA256 string
	PlanDigest     string
	SourceKind     string
	SourceClock    acquisition.SourceClock
}

func validRecordID(value string) bool {
	_, err := casecore.NewCaseID(value)
	return err == nil
}

func nonemptyBounded(value string, maximum int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= maximum
}

func (s *Store) currentRole(ctx context.Context, tx *sql.Tx, scope casecore.Scope, action auth.Action) error {
	var role string
	var active int
	err := tx.QueryRowContext(ctx, `SELECT role,active FROM case_memberships
		WHERE tenant_id=? AND case_id=? AND actor_id=?`, scope.TenantID().String(),
		scope.CaseID().String(), scope.ActorID().String()).Scan(&role, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.ErrDenied
	}
	if err != nil {
		return err
	}
	if active != 1 || !auth.RoleAllows(auth.Role(role), action) {
		return auth.ErrDenied
	}
	return nil
}

// PutArtifact binds a case-local source locator to an output listed in an
// immutable manifest. CAS byte verification remains a separate service gate.
func (s *Store) PutArtifact(ctx context.Context, grant auth.Grant, scope casecore.Scope, a Artifact) error {
	if !grant.Allows(scope, auth.ActionIngestEvidence) {
		return auth.ErrDenied
	}
	if !validRecordID(a.ID) || !validRecordID(a.AssetID) || !validRecordID(a.AcquisitionID) ||
		!validSHA256(a.EvidenceSHA256) || !nonemptyBounded(a.ArtifactType, 128) ||
		!nonemptyBounded(a.SourceLocator, 4096) {
		return ErrInvalidProvenance
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.currentRole(ctx, tx, scope, auth.ActionIngestEvidence); err != nil {
		return err
	}
	var raw []byte
	var storedDigest string
	err = tx.QueryRowContext(ctx, `SELECT manifest_json,manifest_sha256 FROM acquisition_manifests
		WHERE tenant_id=? AND case_id=? AND acquisition_id=?`, scope.TenantID().String(),
		scope.CaseID().String(), a.AcquisitionID).Scan(&raw, &storedDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidProvenance
	}
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if storedDigest != hex.EncodeToString(sum[:]) {
		return ErrManifestIntegrity
	}
	var manifest acquisition.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return ErrManifestIntegrity
	}
	canonical, _, err := manifest.CanonicalBytes()
	if err != nil || string(canonical) != string(raw) || manifest.CaseID != scope.CaseID().String() ||
		manifest.ID != a.AcquisitionID || manifest.AssetID != a.AssetID {
		return ErrManifestIntegrity
	}
	listed := false
	for _, output := range manifest.Outputs {
		if output.EvidenceSHA256 == a.EvidenceSHA256 && output.SourceLocator == a.SourceLocator {
			listed = true
			break
		}
	}
	if !listed {
		return ErrInvalidProvenance
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO artifacts
		(tenant_id,case_id,artifact_id,asset_id,acquisition_id,evidence_sha256,artifact_type,source_locator,created_at)
		VALUES(?,?,?,?,?,?,?,?,?)`, scope.TenantID().String(), scope.CaseID().String(), a.ID,
		a.AssetID, a.AcquisitionID, a.EvidenceSHA256, a.ArtifactType, a.SourceLocator,
		time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	if err := appendAudit(ctx, tx, scope, "artifact.created", a.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) PutParserRun(ctx context.Context, grant auth.Grant, scope casecore.Scope, run ParserRun) error {
	if !grant.Allows(scope, auth.ActionIngestEvidence) {
		return auth.ErrDenied
	}
	if !validRecordID(run.ID) || !validRecordID(run.ArtifactID) ||
		!nonemptyBounded(run.ParserName, 128) || !nonemptyBounded(run.ParserVersion, 128) ||
		!validSHA256(run.ConfigSHA256) ||
		(run.Status != "SUCCEEDED" && run.Status != "PARTIAL" && run.Status != "FAILED") {
		return ErrInvalidProvenance
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.currentRole(ctx, tx, scope, auth.ActionIngestEvidence); err != nil {
		return err
	}
	var exists int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM artifacts WHERE tenant_id=? AND case_id=? AND artifact_id=?`,
		scope.TenantID().String(), scope.CaseID().String(), run.ArtifactID).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidProvenance
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO parser_runs
		(tenant_id,case_id,run_id,artifact_id,parser_name,parser_version,config_sha256,status,created_at)
		VALUES(?,?,?,?,?,?,?,?,?)`, scope.TenantID().String(), scope.CaseID().String(), run.ID,
		run.ArtifactID, run.ParserName, run.ParserVersion, run.ConfigSHA256, run.Status,
		time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	if err := appendAudit(ctx, tx, scope, "parser.run.created", run.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) PutRecordProvenance(ctx context.Context, grant auth.Grant, scope casecore.Scope, record RecordProvenance) error {
	if !grant.Allows(scope, auth.ActionIngestEvidence) {
		return auth.ErrDenied
	}
	if !validRecordID(record.ID) || !validRecordID(record.ParserRunID) ||
		!nonemptyBounded(record.Locator, 4096) || !validSHA256(record.RecordSHA256) {
		return ErrInvalidProvenance
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.currentRole(ctx, tx, scope, auth.ActionIngestEvidence); err != nil {
		return err
	}
	var status string
	err = tx.QueryRowContext(ctx, `SELECT status FROM parser_runs WHERE tenant_id=? AND case_id=? AND run_id=?`,
		scope.TenantID().String(), scope.CaseID().String(), record.ParserRunID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidProvenance
	}
	if err != nil {
		return err
	}
	if status == "FAILED" {
		return ErrInvalidProvenance
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO record_provenance
		(tenant_id,case_id,record_id,run_id,record_locator,record_sha256,created_at)
		VALUES(?,?,?,?,?,?,?)`, scope.TenantID().String(), scope.CaseID().String(), record.ID,
		record.ParserRunID, record.Locator, record.RecordSHA256, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	if err := appendAudit(ctx, tx, scope, "record.provenance.created", record.ID); err != nil {
		return err
	}
	return tx.Commit()
}

// ResolveCitation returns every parent needed to trace one parsed record back
// to its acquisition and original evidence digest, within one authorized case.
func (s *Store) ResolveCitation(ctx context.Context, grant auth.Grant, scope casecore.Scope, recordID string) (Citation, error) {
	if !grant.Allows(scope, auth.ActionReadCase) {
		return Citation{}, auth.ErrDenied
	}
	if !validRecordID(recordID) {
		return Citation{}, ErrInvalidProvenance
	}
	if _, err := s.GetCase(ctx, grant, scope); err != nil {
		return Citation{}, err
	}
	var c Citation
	err := s.db.QueryRowContext(ctx, `SELECT p.record_id,p.record_locator,p.record_sha256,
		r.run_id,r.parser_name,r.parser_version,r.config_sha256,
		a.artifact_id,a.artifact_type,a.asset_id,a.source_locator,a.acquisition_id,a.evidence_sha256
		FROM record_provenance p
		JOIN parser_runs r ON r.tenant_id=p.tenant_id AND r.case_id=p.case_id AND r.run_id=p.run_id
		JOIN artifacts a ON a.tenant_id=r.tenant_id AND a.case_id=r.case_id AND a.artifact_id=r.artifact_id
		WHERE p.tenant_id=? AND p.case_id=? AND p.record_id=?`,
		scope.TenantID().String(), scope.CaseID().String(), recordID).Scan(&c.RecordID,
		&c.RecordLocator, &c.RecordSHA256, &c.ParserRunID, &c.ParserName, &c.ParserVersion,
		&c.ConfigSHA256, &c.ArtifactID, &c.ArtifactType, &c.AssetID, &c.SourceLocator,
		&c.AcquisitionID, &c.EvidenceSHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return Citation{}, ErrCitationNotFound
	}
	if err != nil {
		return Citation{}, err
	}
	manifest, err := s.GetManifest(ctx, grant, scope, c.AcquisitionID)
	if err != nil {
		return Citation{}, err
	}
	if manifest.AssetID != c.AssetID {
		return Citation{}, ErrManifestIntegrity
	}
	for _, output := range manifest.Outputs {
		if output.EvidenceSHA256 == c.EvidenceSHA256 && output.SourceLocator == c.SourceLocator {
			_, manifestDigest, err := manifest.CanonicalBytes()
			if err != nil {
				return Citation{}, ErrManifestIntegrity
			}
			c.TenantID = scope.TenantID().String()
			c.CaseID = scope.CaseID().String()
			c.ManifestSHA256 = manifestDigest
			c.PlanDigest = manifest.PlanDigest
			c.SourceKind = manifest.SourceKind
			c.SourceClock = manifest.SourceClock
			return c, nil
		}
	}
	return Citation{}, ErrManifestIntegrity
}
