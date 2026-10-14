//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"github.com/SergioMazariego/Mantis/v2/internal/ntfs"
	"golang.org/x/sys/windows"
)

// Options are operator choices the collectors need; set once before Sources().
type Options struct {
	TempDir    string
	MemoryPIDs []uint32
}

var (
	optsMu sync.RWMutex
	opts   Options
)

// Configure stores the operator options used by collectors created afterwards.
func Configure(o Options) {
	optsMu.Lock()
	opts = o
	optsMu.Unlock()
}

func currentOptions() Options {
	optsMu.RLock()
	defer optsMu.RUnlock()
	return opts
}

// IsElevated reports whether the process runs with an elevated administrator token.
func IsElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

var (
	privOnce               sync.Map // privilege name -> bool (enabled)
	pAdjustTokenPrivileges = windows.NewLazySystemDLL("advapi32.dll").NewProc("AdjustTokenPrivileges")
)

// prepareAcquisition enables SeBackupPrivilege once, before any enumeration, when elevated. Directories
// whose ACL denies Administrators (Defender scan history, other users' recycle bins) can only be listed with
// it, and the choice between a direct and a raw read must not depend on which source ran first.
func prepareAcquisition() {
	if IsElevated() {
		enablePrivilege("SeBackupPrivilege")
	}
}

// enablePrivilege turns on a privilege the token already holds (never grants new rights).
func enablePrivilege(name string) bool {
	if v, ok := privOnce.Load(name); ok {
		return v.(bool)
	}
	ok := func() bool {
		var luid windows.LUID
		if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
			return false
		}
		var token windows.Token
		if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
			return false
		}
		defer token.Close()
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
		// AdjustTokenPrivileges succeeds even when the privilege is not held (ERROR_NOT_ALL_ASSIGNED).
		// The error must be read from the same call: a separate GetLastError can run on another thread.
		r, _, callErr := pAdjustTokenPrivileges.Call(uintptr(token), 0, uintptr(unsafe.Pointer(&tp)), uintptr(unsafe.Sizeof(tp)), 0, 0)
		return r != 0 && !errors.Is(callErr, windows.ERROR_NOT_ALL_ASSIGNED)
	}()
	privOnce.Store(name, ok)
	return ok
}

// FreeBytes returns the bytes available to the caller on the volume holding dir.
func FreeBytes(dir string) (uint64, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	var avail, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &total, &free); err != nil {
		return 0, err
	}
	return avail, nil
}

// ---- error classification ----

// classifyErr maps Win32 failures to the typed outcomes that have different
// forensic meanings. The original error stays in the chain.
func classifyErr(err error) error {
	if err == nil {
		return nil
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case windows.ERROR_FILE_NOT_FOUND, windows.ERROR_PATH_NOT_FOUND, windows.ERROR_INVALID_NAME, windows.ERROR_BAD_NETPATH,
			windows.ERROR_NOT_READY, windows.ERROR_DEV_NOT_EXIST:
			return fmt.Errorf("%w: %v", collector.ErrNotPresent, err)
		case windows.ERROR_ACCESS_DENIED, windows.ERROR_PRIVILEGE_NOT_HELD:
			return fmt.Errorf("%w: %v", collector.ErrAccessDenied, err)
		case windows.ERROR_SHARING_VIOLATION, windows.ERROR_LOCK_VIOLATION:
			return fmt.Errorf("%w: %v", collector.ErrLocked, err)
		case windows.ERROR_NOT_SUPPORTED, windows.ERROR_INVALID_FUNCTION, windows.ERROR_CALL_NOT_IMPLEMENTED:
			return fmt.Errorf("%w: %v", collector.ErrNotSupported, err)
		}
	}
	return err
}

// ---- paths ----

func systemDrive() string {
	if d := os.Getenv("SystemDrive"); len(d) >= 2 {
		return strings.ToUpper(d[:2])
	}
	return "C:"
}

func windowsDir() string {
	if d, err := windows.GetWindowsDirectory(); err == nil && d != "" {
		return d
	}
	return systemDrive() + `\Windows`
}

// extended returns a \\?\ path that bypasses MAX_PATH. The input must be absolute.
func extended(p string) string {
	p = filepath.Clean(p)
	if strings.HasPrefix(p, `\\?\`) {
		return p
	}
	if strings.HasPrefix(p, `\\`) {
		return `\\?\UNC\` + p[2:]
	}
	return `\\?\` + p
}

// splitDrive separates "C:\x\y" into ("C", "x\y").
func splitDrive(p string) (string, string, bool) {
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		return strings.ToUpper(p[:1]), strings.ReplaceAll(p[3:], "/", `\`), true
	}
	return "", "", false
}

// destFor derives a package destination that preserves the original path.
func destFor(category, original string) string {
	if drive, rest, ok := splitDrive(original); ok {
		return category + "/" + drive + "/" + strings.ReplaceAll(rest, `\`, "/")
	}
	return category + "/" + strings.ReplaceAll(strings.TrimLeft(original, `\/`), `\`, "/")
}

// ---- raw NTFS access ----

type rawVolume struct {
	f   *os.File
	vol *ntfs.Volume
	err error
}

var (
	rawMu   sync.Mutex
	rawVols = map[string]*rawVolume{}
)

// rawVolumeFor opens a read-only handle on \\.\X: once and parses its NTFS structures.
func rawVolumeFor(drive string) (*ntfs.Volume, error) {
	rawMu.Lock()
	defer rawMu.Unlock()
	if rv, ok := rawVols[drive]; ok {
		return rv.vol, rv.err
	}
	rv := &rawVolume{}
	rawVols[drive] = rv
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(`\\.\`+drive+`:`), windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		rv.err = classifyErr(fmt.Errorf("open volume %s: %w", drive, err))
		return nil, rv.err
	}
	rv.f = os.NewFile(uintptr(handle), `\\.\`+drive+`:`)
	vol, err := ntfs.OpenVolume(ntfs.NewAlignedReaderAt(rv.f, 4096))
	if err != nil {
		rv.f.Close()
		if errors.Is(err, ntfs.ErrNotNTFS) {
			rv.err = fmt.Errorf("%w: %s is not an NTFS volume", collector.ErrNotSupported, drive)
		} else {
			rv.err = fmt.Errorf("parse NTFS volume %s: %w", drive, err)
		}
		return nil, rv.err
	}
	rv.vol = vol
	return vol, nil
}

// acqReader streams one acquisition and reports how it was obtained.
type acqReader struct {
	r      io.Reader
	closer func() error
	method string
	notes  map[string]string
}

func (a *acqReader) Read(p []byte) (int, error) { return a.r.Read(p) }
func (a *acqReader) Close() error {
	if a.closer != nil {
		return a.closer()
	}
	return nil
}
func (a *acqReader) AcquisitionMethod() string           { return a.method }
func (a *acqReader) AcquisitionNotes() map[string]string { return a.notes }

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// openFile acquires one file or NTFS stream (path may end in ":stream"), trying in order:
//  1. a shared, backup-semantics Win32 read (works for most files, including many "locked" ones);
//  2. a raw NTFS read of the volume (administrator; reads the on-disk bytes of exclusively locked
//     files such as registry hives; not point-in-time consistent on a live system).
//
// The method actually used is recorded with the item.
func openFile(ctx context.Context, path string) (*acqReader, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cloudPlaceholder(path) {
		return nil, fmt.Errorf("%w: %s is a cloud placeholder (not hydrated); it is not downloaded during acquisition", collector.ErrNotSupported, path)
	}
	direct, derr := directOpen(path)
	if derr == nil {
		return &acqReader{r: &ctxReader{ctx, direct}, closer: direct.Close, method: "win32-shared-read",
			notes: map[string]string{"read_mode": "FILE_SHARE_READ|WRITE|DELETE, backup semantics"}}, nil
	}
	cerr := classifyErr(derr)
	if isTrulyAbsent(derr) {
		return nil, cerr
	}
	// Locked or access denied: fall back to raw NTFS when possible.
	drive, rel, ok := splitDrive(path)
	if !ok {
		return nil, cerr
	}
	enablePrivilege("SeBackupPrivilege")
	vol, verr := rawVolumeFor(drive)
	if verr != nil {
		return nil, fmt.Errorf("%w (direct read failed: %v; raw volume unavailable: %v)", firstTyped(verr, cerr), derr, verr)
	}
	f, err := vol.OpenPath(rel)
	if err != nil {
		if errors.Is(err, ntfs.ErrNotFound) {
			return nil, fmt.Errorf("%w: %s", collector.ErrNotPresent, path)
		}
		return nil, fmt.Errorf("raw NTFS open %s: %w (direct read failed: %v)", path, err, derr)
	}
	return &acqReader{r: &ctxReader{ctx, f.NewReader()}, method: "ntfs-raw-read",
		notes: map[string]string{
			"read_mode":     "raw volume read via NTFS parser; direct read failed: " + derr.Error(),
			"consistency":   "live raw read, not point-in-time consistent",
			"volume_serial": vol.Info().VolumeSerialHex,
		}}, nil
}

func firstTyped(errs ...error) error {
	for _, e := range errs {
		for _, t := range []error{collector.ErrNotSupported, collector.ErrAccessDenied, collector.ErrLocked, collector.ErrNotPresent} {
			if errors.Is(e, t) {
				return t
			}
		}
	}
	return errs[len(errs)-1]
}

func directOpen(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(extended(path))
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_SEQUENTIAL_SCAN, 0)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err == nil && info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("%s is a directory", path)
	}
	return os.NewFile(uintptr(h), path), nil
}

// fileInfo returns existence and size without opening the content (works for locked files).
func fileInfo(path string) (exists bool, size int64, err error) {
	p, e := windows.UTF16PtrFromString(extended(path))
	if e != nil {
		return false, 0, e
	}
	var data windows.Win32FileAttributeData
	if e := windows.GetFileAttributesEx(p, windows.GetFileExInfoStandard, (*byte)(unsafe.Pointer(&data))); e != nil {
		if errors.Is(classifyErr(e), collector.ErrNotPresent) {
			return false, 0, nil
		}
		return false, 0, e
	}
	if data.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return true, 0, nil
	}
	return true, int64(data.FileSizeHigh)<<32 | int64(data.FileSizeLow), nil
}

func dirExists(path string) bool {
	p, err := windows.UTF16PtrFromString(extended(path))
	if err != nil {
		return false
	}
	a, err := windows.GetFileAttributes(p)
	return err == nil && a&windows.FILE_ATTRIBUTE_DIRECTORY != 0
}

// scratchDir is where staged exports (EVTX, RegSaveKeyEx) are written; it lives
// inside the evidence output directory so the source system disk is not used.
func scratchDir() string {
	dir := currentOptions().TempDir
	if dir == "" {
		return os.TempDir()
	}
	_ = os.MkdirAll(dir, 0o700)
	return dir
}

// isTrulyAbsent is true only for "file/path not found". Other errors that classifyErr maps to
// not_present (invalid name for stream paths, device not ready) still deserve a raw-read attempt.
func isTrulyAbsent(err error) bool {
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
}

// cloudPlaceholder reports files whose content lives in the cloud (OneDrive and similar). Reading
// them would trigger a download over the network, which acquisition must never do.
func cloudPlaceholder(path string) bool {
	p, err := windows.UTF16PtrFromString(extended(stripStream(path)))
	if err != nil {
		return false
	}
	a, err := windows.GetFileAttributes(p)
	const recallOnOpen, recallOnDataAccess = 0x40000, 0x400000
	return err == nil && a&(recallOnOpen|recallOnDataAccess) != 0
}
