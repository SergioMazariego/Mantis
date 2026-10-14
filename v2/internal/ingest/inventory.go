package ingest

import (
	"context"

	"github.com/SergioMazariego/Mantis/v2/internal/auth"
	"github.com/SergioMazariego/Mantis/v2/internal/casecore"
)

type RecoveryEntry struct {
	SHA256    string
	SizeBytes int64
	Integrity string // VERIFIED or CORRUPT
	Reference string // REFERENCED or ORPHAN
}

// Inventory gives an authorized analyst a case-local, read-only recovery view.
// An ORPHAN is a diagnostic classification and must never be auto-deleted.
func (s *Service) Inventory(ctx context.Context, scope casecore.Scope) ([]RecoveryEntry, error) {
	if s == nil || ctx == nil {
		return nil, ErrUnavailable
	}
	grant, err := s.authorizer.Authorize(ctx, scope, auth.ActionReadCase)
	if err != nil {
		return nil, err
	}
	refs, err := s.metadata.ReferencedDigests(ctx, grant, scope)
	if err != nil {
		return nil, err
	}
	blobs, err := s.blobs.InventoryForRecovery(ctx, scope)
	if err != nil {
		return nil, err
	}
	result := make([]RecoveryEntry, 0, len(blobs))
	for _, blob := range blobs {
		ref := "ORPHAN"
		if refs[blob.SHA256] {
			ref = "REFERENCED"
		}
		result = append(result, RecoveryEntry{blob.SHA256, blob.SizeBytes, blob.Integrity, ref})
	}
	return result, nil
}
