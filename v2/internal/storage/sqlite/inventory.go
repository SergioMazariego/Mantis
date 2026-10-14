package sqlite

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/SergioMazariego/Mantis/v2/internal/acquisition"
	"github.com/SergioMazariego/Mantis/v2/internal/auth"
	"github.com/SergioMazariego/Mantis/v2/internal/casecore"
)

// ReferencedDigests returns verified manifest and intent references for one
// authorized case. This is diagnostic and cannot prove that a blob is readable.
func (s *Store) ReferencedDigests(ctx context.Context, grant auth.Grant, scope casecore.Scope) (map[string]bool, error) {
	if !grant.Allows(scope, auth.ActionReadCase) {
		return nil, auth.ErrDenied
	}
	if _, err := s.GetCase(ctx, grant, scope); err != nil {
		return nil, err
	}
	refs := make(map[string]bool)
	rows, err := s.db.QueryContext(ctx, `SELECT acquisition_id,manifest_json,manifest_sha256 FROM acquisition_manifests WHERE tenant_id=? AND case_id=?`, scope.TenantID().String(), scope.CaseID().String())
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, digest string
		var raw []byte
		if err := rows.Scan(&id, &raw, &digest); err != nil {
			rows.Close()
			return nil, err
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != digest {
			rows.Close()
			return nil, ErrManifestIntegrity
		}
		var m acquisition.Manifest
		if err := json.Unmarshal(raw, &m); err != nil {
			rows.Close()
			return nil, ErrManifestIntegrity
		}
		canonical, _, err := m.CanonicalBytes()
		if err != nil || string(canonical) != string(raw) || m.ID != id || m.CaseID != scope.CaseID().String() {
			rows.Close()
			return nil, ErrManifestIntegrity
		}
		for _, output := range m.Outputs {
			refs[output.EvidenceSHA256] = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT evidence_sha256 FROM ingest_intent_events WHERE tenant_id=? AND case_id=? AND evidence_sha256<>''`, scope.TenantID().String(), scope.CaseID().String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var digest string
		if err := rows.Scan(&digest); err != nil {
			return nil, err
		}
		if len(digest) != 64 {
			return nil, ErrManifestIntegrity
		}
		if _, err := hex.DecodeString(digest); err != nil || digest != strings.ToLower(digest) {
			return nil, ErrManifestIntegrity
		}
		refs[digest] = true
	}
	return refs, rows.Err()
}
