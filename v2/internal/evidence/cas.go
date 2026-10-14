// Package evidence stores immutable, case-scoped raw evidence bytes.
package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"

	"github.com/SergioMazariego/Mantis/v2/internal/auth"
	"github.com/SergioMazariego/Mantis/v2/internal/casecore"
)

var (
	ErrInvalidRoot = errors.New("invalid evidence store root")
	ErrInvalidHash = errors.New("invalid evidence SHA-256")
	ErrTooLarge    = errors.New("evidence exceeds collection budget")
	ErrIntegrity   = errors.New("evidence integrity failure")
)

type Store struct{ root string }

type Blob struct {
	SHA256    string
	SizeBytes int64
	TenantID  casecore.TenantID
	CaseID    casecore.CaseID
}

func OpenStore(root string) (*Store, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, ErrInvalidRoot
	}
	root = filepath.Clean(root)
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidRoot
	}
	return &Store{root: root}, nil
}

func validHash(value string) bool {
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

func (s *Store) blobPath(scope casecore.Scope, digest string) string {
	return filepath.Join(s.root, "tenants", scope.TenantID().String(), "cases", scope.CaseID().String(),
		"blobs", "sha256", digest[:2], digest[2:4], digest)
}

// Put streams one acquisition into a private staging file, then publishes it
// with an atomic hard link. The final path is never visible with partial bytes.
// Hard-link support is required; unsupported filesystems fail closed.
func (s *Store) Put(ctx context.Context, grant auth.Grant, scope casecore.Scope, input io.Reader, maxBytes int64) (Blob, error) {
	if s == nil || !grant.Allows(scope, auth.ActionIngestEvidence) || input == nil {
		return Blob{}, auth.ErrDenied
	}
	if maxBytes <= 0 {
		return Blob{}, ErrTooLarge
	}
	if ctx == nil {
		return Blob{}, auth.ErrDenied
	}
	if err := ctx.Err(); err != nil {
		return Blob{}, err
	}
	// The staging directory is case-local; names never derive from evidence paths.
	staging := filepath.Join(s.root, "tenants", scope.TenantID().String(), "cases", scope.CaseID().String(), ".staging")
	if err := os.MkdirAll(staging, 0700); err != nil {
		return Blob{}, err
	}
	file, err := os.CreateTemp(staging, "ingest-*")
	if err != nil {
		return Blob{}, err
	}
	name := file.Name()
	defer os.Remove(name)
	hasher := sha256.New()
	size, err := copyBounded(ctx, file, hasher, input, maxBytes)
	if err != nil {
		file.Close()
		return Blob{}, err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return Blob{}, err
	}
	if err := file.Close(); err != nil {
		return Blob{}, err
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	if !validHash(digest) {
		return Blob{}, ErrIntegrity
	}
	final := s.blobPath(scope, digest)
	if err := os.MkdirAll(filepath.Dir(final), 0700); err != nil {
		return Blob{}, err
	}
	if err := os.Link(name, final); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return Blob{}, fmt.Errorf("commit evidence: %w", err)
		}
		if err := verifyFile(ctx, final, digest, size); err != nil {
			return Blob{}, err
		}
	} else {
		// On Windows a read-only hard link cannot be removed. Unlink the staging
		// name before marking the published blob read-only.
		if err := os.Remove(name); err != nil {
			return Blob{}, fmt.Errorf("clean staging file: %w", err)
		}
		if err := os.Chmod(final, 0444); err != nil {
			os.Remove(final)
			return Blob{}, err
		}
		if err := verifyFile(ctx, final, digest, size); err != nil {
			return Blob{}, err
		}
	}
	if _, err := os.Lstat(name); err == nil {
		if err := os.Remove(name); err != nil {
			return Blob{}, fmt.Errorf("clean staging file: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Blob{}, err
	}
	return Blob{SHA256: digest, SizeBytes: size, TenantID: scope.TenantID(), CaseID: scope.CaseID()}, nil
}

func copyBounded(ctx context.Context, output io.Writer, hasher hash.Hash, input io.Reader, maxBytes int64) (int64, error) {
	buffer := make([]byte, 64*1024)
	var total int64
	zeroReads := 0
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		n, readErr := input.Read(buffer)
		if n < 0 || n > len(buffer) {
			return 0, ErrIntegrity
		}
		if n > 0 {
			zeroReads = 0
			if int64(n) > maxBytes-total {
				return 0, ErrTooLarge
			}
			written, err := output.Write(buffer[:n])
			if err != nil {
				return 0, err
			}
			if written != n {
				return 0, io.ErrShortWrite
			}
			if _, err := hasher.Write(buffer[:n]); err != nil {
				return 0, err
			}
			total += int64(n)
		} else if readErr == nil {
			zeroReads++
			if zeroReads >= 100 {
				return 0, io.ErrNoProgress
			}
		}
		if readErr == io.EOF {
			return total, nil
		}
		if readErr != nil {
			return 0, readErr
		}
	}
}

// Open verifies the entire blob before returning a read-only file handle.
// Callers must still preserve the returned case scope in their own records.
func (s *Store) Open(ctx context.Context, grant auth.Grant, scope casecore.Scope, digest string) (*os.File, error) {
	if s == nil || !grant.Allows(scope, auth.ActionReadEvidence) {
		return nil, auth.ErrDenied
	}
	if ctx == nil {
		return nil, auth.ErrDenied
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validHash(digest) {
		return nil, ErrInvalidHash
	}
	path := s.blobPath(scope, digest)
	return openVerified(ctx, path, digest, -1)
}

// VerifyForRecovery is a trusted startup-maintenance operation. It reveals no
// bytes and must never be wired to an end-user route or agent capability.
func (s *Store) VerifyForRecovery(ctx context.Context, scope casecore.Scope, digest string) error {
	if s == nil || ctx == nil || !scope.Valid() || !validHash(digest) {
		return ErrInvalidHash
	}
	return verifyFile(ctx, s.blobPath(scope, digest), digest, -1)
}

func verifyFile(ctx context.Context, path, digest string, expectedSize int64) error {
	file, err := openVerified(ctx, path, digest, expectedSize)
	if err != nil {
		return err
	}
	return file.Close()
}

func openVerified(ctx context.Context, path, digest string, expectedSize int64) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrIntegrity
	}
	if expectedSize >= 0 && info.Size() != expectedSize {
		return nil, ErrIntegrity
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		file.Close()
		return nil, ErrIntegrity
	}
	hasher := sha256.New()
	size, err := copyForHash(ctx, hasher, file)
	if err != nil {
		file.Close()
		return nil, err
	}
	if expectedSize >= 0 && size != expectedSize {
		file.Close()
		return nil, ErrIntegrity
	}
	if hex.EncodeToString(hasher.Sum(nil)) != digest {
		file.Close()
		return nil, ErrIntegrity
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func copyForHash(ctx context.Context, hasher hash.Hash, file io.Reader) (int64, error) {
	buffer := make([]byte, 64*1024)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		n, err := file.Read(buffer)
		if n > 0 {
			if _, hashErr := hasher.Write(buffer[:n]); hashErr != nil {
				return 0, hashErr
			}
			total += int64(n)
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return 0, err
		}
	}
}
