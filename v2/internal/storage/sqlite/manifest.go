package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/SergioMazariego/Mantis/v2/internal/acquisition"
	"github.com/SergioMazariego/Mantis/v2/internal/auth"
	"github.com/SergioMazariego/Mantis/v2/internal/casecore"
)

var ErrManifestIntegrity = errors.New("acquisition manifest integrity failure")

// PutManifest records one immutable collection result and audits the write in
// the same transaction. The caller must first verify referenced CAS blobs.
func (s *Store) PutManifest(ctx context.Context, grant auth.Grant, scope casecore.Scope, m acquisition.Manifest) (string, error) {
	if !grant.Allows(scope, auth.ActionIngestEvidence) {
		return "", auth.ErrDenied
	}
	if m.CaseID != scope.CaseID().String() {
		return "", auth.ErrDenied
	}
	data, digest, err := m.CanonicalBytes()
	if err != nil {
		return "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var role string
	var active int
	err = tx.QueryRowContext(ctx, `SELECT role,active FROM case_memberships
		WHERE tenant_id=? AND case_id=? AND actor_id=?`, scope.TenantID().String(),
		scope.CaseID().String(), scope.ActorID().String()).Scan(&role, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return "", auth.ErrDenied
	}
	if err != nil {
		return "", err
	}
	if active != 1 || !auth.RoleAllows(auth.Role(role), auth.ActionIngestEvidence) {
		return "", auth.ErrDenied
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO acquisition_manifests
		(tenant_id,case_id,acquisition_id,manifest_json,manifest_sha256) VALUES(?,?,?,?,?)`,
		scope.TenantID().String(), scope.CaseID().String(), m.ID, data, digest)
	if err != nil {
		return "", err
	}
	if err := appendAudit(ctx, tx, scope, "acquisition.manifest.created", m.ID); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return digest, nil
}

func (s *Store) GetManifest(ctx context.Context, grant auth.Grant, scope casecore.Scope, acquisitionID string) (acquisition.Manifest, error) {
	if !grant.Allows(scope, auth.ActionReadCase) {
		return acquisition.Manifest{}, auth.ErrDenied
	}
	if _, err := s.GetCase(ctx, grant, scope); err != nil {
		return acquisition.Manifest{}, err
	}
	var raw []byte
	var storedDigest string
	err := s.db.QueryRowContext(ctx, `SELECT manifest_json,manifest_sha256 FROM acquisition_manifests
		WHERE tenant_id=? AND case_id=? AND acquisition_id=?`, scope.TenantID().String(),
		scope.CaseID().String(), acquisitionID).Scan(&raw, &storedDigest)
	if err != nil {
		return acquisition.Manifest{}, err
	}
	sum := sha256.Sum256(raw)
	if storedDigest != hex.EncodeToString(sum[:]) {
		return acquisition.Manifest{}, ErrManifestIntegrity
	}
	var m acquisition.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return acquisition.Manifest{}, ErrManifestIntegrity
	}
	canonical, _, err := m.CanonicalBytes()
	if err != nil || string(canonical) != string(raw) || m.ID != acquisitionID || m.CaseID != scope.CaseID().String() {
		return acquisition.Manifest{}, ErrManifestIntegrity
	}
	return m, nil
}
