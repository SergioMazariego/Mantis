//go:build windows && memdump

package windows

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"golang.org/x/sys/windows"
)

// Process memory dumping is an opt-in build (go build -tags memdump). It is compiled out of the
// default binary on purpose: the capability resembles credential-dumping tooling and triggers
// antivirus heuristics, and most investigations do not need it.

const memdumpCompiled = true

var (
	dbghelp            = windows.NewLazySystemDLL("dbghelp.dll")
	pMiniDumpWriteDump = dbghelp.NewProc("MiniDumpWriteDump")
)

// dumpProcess writes a full-memory minidump of one approved process to the scratch
// directory and streams it. lsass.exe is refused to avoid credential extraction.
func dumpProcess(ctx context.Context, pid uint32) (io.ReadCloser, error) {
	name := processNames()[pid]
	if strings.EqualFold(name, "lsass.exe") || strings.EqualFold(name, "lsaiso.exe") {
		return nil, fmt.Errorf("%w: lsass.exe is excluded; dumping it extracts credentials", collector.ErrNotSupported)
	}
	enablePrivilege("SeDebugPrivilege")
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil, classifyErr(fmt.Errorf("OpenProcess(%d): %w", pid, err))
	}
	defer windows.CloseHandle(h)
	f, err := os.CreateTemp(scratchDir(), fmt.Sprintf("procdump-%d-*.dmp", pid))
	if err != nil {
		return nil, err
	}
	path := f.Name()
	const dumpType = 0x2 | 0x4 | 0x20 | 0x1000 | 0x800 // WithFullMemory | WithHandleData | WithUnloadedModules | WithThreadInfo | WithFullMemoryInfo
	r, _, callErr := pMiniDumpWriteDump.Call(uintptr(h), uintptr(pid), f.Fd(), dumpType, 0, 0, 0)
	if r == 0 {
		f.Close()
		os.Remove(path)
		if errors.Is(callErr, syscall.Errno(0)) {
			callErr = syscall.EINVAL
		}
		return nil, classifyErr(fmt.Errorf("MiniDumpWriteDump(%d): %w", pid, callErr))
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	return &tempFileReader{File: f, path: path, notes: map[string]string{"read_mode": "MiniDumpWriteDump full memory", "process": name, "pid": fmt.Sprint(pid),
		"warning_detail": "full-memory dumps can contain credentials and keys of the dumped process", "acquired": time.Now().UTC().Format(time.RFC3339)}}, nil
}

// memoryDumpSource describes the opt-in process memory dump collector (explicit PIDs only).
func memoryDumpSource() collector.Source {
	mm := func(name, desc string, p collector.ProfileMask, priv collector.Privilege) collector.Meta {
		return baseMeta(name, desc, "memory", priv, p)
	}
	dump := collector.Source{
		ID: "memory-process-dumps", Kind: "windows.memory_group", Locator: "MiniDumpWriteDump(approved PIDs)", Method: "minidump-full-memory", MaxBytes: 32 << 30,
		Meta: mm("Process memory dumps (operator-approved PIDs)", "Full-memory minidumps of the processes named with --memory-pids. lsass.exe is excluded. Dumps may contain credentials and keys of the dumped process", collector.InFullOnly, collector.PrivDebug),
		Detect: func(context.Context) collector.Availability {
			if len(currentOptions().MemoryPIDs) == 0 {
				return collector.Availability{State: collector.NotPresent, Reason: "no PIDs approved; start mantis-collect with --memory-pids <pid,...>"}
			}
			return collector.Availability{State: collector.Available}
		},
		Expand: func(ctx context.Context) ([]collector.Source, error) {
			pids := currentOptions().MemoryPIDs
			if len(pids) == 0 {
				return nil, fmt.Errorf("%w: no PIDs approved (--memory-pids)", collector.ErrNotPresent)
			}
			var out []collector.Source
			for _, pid := range pids {
				pid := pid
				cm := collector.Meta{Name: fmt.Sprintf("memory dump PID %d", pid), Category: "memory", SourceType: "memory", SourcePath: fmt.Sprintf("pid://%d", pid),
					DestPath: fmt.Sprintf("memory/pid-%d.dmp", pid), SideEffects: "reads the target process memory; the dump file is staged in the scratch directory", Sensitive: true}
				out = append(out, collector.Source{ID: fmt.Sprintf("memory-dump-%d", pid), Kind: "windows.memory_dump", Locator: fmt.Sprintf("pid://%d", pid),
					Method: "MiniDumpWriteDump/full-memory", MaxBytes: 32 << 30, Meta: cm,
					Open: func(c context.Context) (io.ReadCloser, error) { return dumpProcess(c, pid) }})
			}
			return out, nil
		},
	}
	dump.Meta.Sensitive = true
	dump.Meta.SideEffects = "reads process memory; dumps may contain secrets; requires --confirm-sensitive"

	return dump
}
