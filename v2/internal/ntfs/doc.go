// Package ntfs is a pure-Go, read-only NTFS parser built on io.ReaderAt. It lets
// Mantis read locked or protected files (registry hives, $MFT, $LogFile,
// $UsnJrnl:$J, Amcache.hve, SRUDB.dat, NTUSER.DAT, browser databases, ...) at
// the raw-volume level, from a Windows "\\.\C:" device handle or an image file.
// It never writes: the only I/O primitive used is ReaderAt.ReadAt.
//
// # Usage
//
// Raw Windows volume handles only accept sector-aligned offsets and lengths;
// wrap them first:
//
//	v, err := ntfs.OpenVolume(ntfs.NewAlignedReaderAt(dev, 4096))
//	f, err := v.OpenPath(`Windows\System32\config\SYSTEM`)
//	io.Copy(dst, f.NewReader())
//
// # Supported
//
//   - $Boot BPB parsing, 64-bit serial, MFT record sizes given as clusters or 2^n.
//   - FILE records and INDX blocks with update-sequence fixup verification
//     (mismatch => ErrCorrupt).
//   - Resident and non-resident attributes, named streams (alternate data
//     streams), runlists with sparse runs and negative deltas, real vs
//     initialized size (bytes past the initialized size read as zero).
//   - $ATTRIBUTE_LIST: attributes in extension records are resolved, and
//     extents of one attribute split across records are merged by starting VCN.
//     This also works for a fragmented $MFT whose later extents live in an
//     extension record (extension records must be reachable through the
//     extents stored in record 0).
//   - Directory indexes ($INDEX_ROOT + $INDEX_ALLOCATION, B-tree descent for
//     lookups and in-order traversal for listing). DOS-only (namespace 2)
//     duplicate names are hidden from listings but can still be opened.
//   - Sparse $DATA (holes read as zeros).
//   - Hostile-input hardening: every on-disk offset/length is bounds-checked and
//     allocations are capped (records, attribute lists, runlists, index blocks,
//     entry counts, directory depth). Corruption yields ErrCorrupt, not panics.
//
// # Case-insensitive names
//
// The volume's $UpCase table (record 10) is loaded and used when present and
// plausible (see Volume.UpcaseLoaded). Otherwise a fallback is used: ASCII plus
// Go's unicode.ToUpper on single UTF-16 units, which can differ from the real
// table for a few characters. Because index order depends on the real table,
// when the fallback is active a failed tree lookup is retried with a linear
// scan of the directory.
//
// # Not supported / limitations
//
//   - NTFS compression (attribute flag 0x0001, LZNT1): data reads return
//     ErrCompressed. Extents() still reports the raw runs.
//   - EFS encryption (flag 0x4000): data reads return ErrEncrypted. No decryption.
//   - Reparse points (junctions, symlinks, mount points, OneDrive placeholders)
//     are never followed; Walk reports them and does not descend, and OpenPath
//     through one resolves its (normally empty) own index.
//   - Only $DATA streams are addressable by path (not "$I30" or other types).
//   - $BITMAP of the index is not consulted: traversal follows sub-node pointers,
//     so unallocated index blocks (which can hold remnants of deleted names) are
//     not reported. Deleted files and slack are out of scope.
//   - Sequence numbers in file references are not verified (stale references to
//     recycled records are only rejected if the record is not in use).
//   - Extension records of $MFT itself must lie within extents described in
//     record 0.
//   - Resident-data extents have PhysicalOffset -1 (data sits inside the MFT
//     record); Extents() clips the last extent to the stream's real size.
//   - $LogFile/journal replay is not performed: the volume is read as-is, so a
//     live or dirty volume may show metadata that is mid-update. On a live
//     system, files can change between reads.
//   - Not safe for concurrent use (Volume, File and AlignedReaderAt share
//     caches and buffers); serialize access.
//
// # Validation status
//
// The package has been exercised only against synthetic images built by this
// package's tests (and mutation fuzzing of them). It has not been validated
// against real NTFS volumes.
package ntfs
