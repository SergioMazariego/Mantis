package evidence

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/SergioMazariego/Mantis/v2/internal/casecore"
)

// InventoryEntry is diagnostic metadata, never authority to expose or delete bytes.
type InventoryEntry struct {
	SHA256    string
	SizeBytes int64
	Integrity string // VERIFIED or CORRUPT
}

// InventoryForRecovery is a trusted internal scan of one case's published CAS.
// It does not follow links, remove files, or expose evidence bytes.
func (s *Store) InventoryForRecovery(ctx context.Context, scope casecore.Scope) ([]InventoryEntry, error) {
	if s == nil || ctx == nil || !scope.Valid() {
		return nil, ErrIntegrity
	}
	base := filepath.Join(s.root, "tenants", scope.TenantID().String(), "cases", scope.CaseID().String(), "blobs", "sha256")
	if _, err := os.Lstat(base); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	entries := make([]InventoryEntry, 0)
	err := filepath.WalkDir(base, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return ErrIntegrity
		}
		rel, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		if rel == "." {
			if !d.IsDir() {
				return ErrIntegrity
			}
			return nil
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if d.IsDir() {
			if len(parts) > 2 || len(parts[len(parts)-1]) != 2 || !validHexPair(parts[len(parts)-1]) {
				return ErrIntegrity
			}
			return nil
		}
		if len(parts) != 3 || !d.Type().IsRegular() || !validHash(parts[2]) ||
			parts[0] != parts[2][:2] || parts[1] != parts[2][2:4] {
			return ErrIntegrity
		}
		if len(entries) >= 10000 {
			return ErrTooLarge
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		entry := InventoryEntry{SHA256: parts[2], SizeBytes: info.Size(), Integrity: "VERIFIED"}
		if err := verifyFile(ctx, path, entry.SHA256, entry.SizeBytes); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			entry.Integrity = "CORRUPT"
		}
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].SHA256 < entries[j].SHA256 })
	return entries, nil
}

func validHexPair(value string) bool {
	for _, ch := range value {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return false
		}
	}
	return true
}
