package ntfs

import (
	"errors"
	"fmt"
)

// Sentinel errors. Returned errors wrap these, so use errors.Is.
var (
	// ErrNotNTFS means the device does not look like an NTFS volume.
	ErrNotNTFS = errors.New("ntfs: not an NTFS volume")
	// ErrNotFound means a path, stream or record does not exist.
	ErrNotFound = errors.New("ntfs: file not found")
	// ErrNotDirectory means a directory operation was applied to a non-directory.
	ErrNotDirectory = errors.New("ntfs: not a directory")
	// ErrIsDirectory means a data operation was applied to a directory.
	ErrIsDirectory = errors.New("ntfs: is a directory")
	// ErrEncrypted means the stream is EFS-encrypted (not decrypted by this package).
	ErrEncrypted = errors.New("ntfs: stream is encrypted (EFS)")
	// ErrCompressed means the stream uses NTFS compression (not supported).
	ErrCompressed = errors.New("ntfs: stream is compressed (unsupported)")
	// ErrCorrupt means on-disk structures are inconsistent or out of bounds.
	ErrCorrupt = errors.New("ntfs: corrupt or inconsistent structure")
	// ErrUnsupported means a valid but unsupported feature was encountered.
	ErrUnsupported = errors.New("ntfs: unsupported feature")
	// ErrSkipDir may be returned by a Walk callback to skip a directory
	// (or, when returned for a non-directory, the rest of its parent directory).
	ErrSkipDir = errors.New("ntfs: skip directory")
)

func corrupt(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, a...))
}
