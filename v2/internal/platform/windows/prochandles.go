//go:build windows

package windows

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"golang.org/x/sys/windows"
)

// Handles: the object type table (so type indexes are readable) and a per-handle list of the object types that
// matter in an investigation: handles to other processes and threads (with their granted access), mutexes, named
// sections, ALPC ports, registry keys and files. Names are resolved only on duplicated handles and, for files,
// under a timeout, because naming a synchronous pipe handle can block forever.

var (
	pNtQueryObject        = ntdll.NewProc("NtQueryObject")
	pGetProcessID         = kernel32.NewProc("GetProcessId")
	pGetProcessIDOfThread = kernel32.NewProc("GetProcessIdOfThread")
	handleDetailBudget    = 120 * time.Second
	fileNameTimeout       = 250 * time.Millisecond
	maxStuckFileNames     = 20
	maxHandleRecords      = 250000
	handleTypesOfInterest = map[string]bool{"Process": true, "Thread": true, "Mutant": true, "Section": true, "ALPC Port": true, "Key": true, "File": true}
	noiseFilePrefixes     = []string{`\device\afd`, `\device\condrv`, `\device\deviceapi`}
)

const (
	objectNameInformation  = 1
	objectTypesInformation = 3
	statusBufferOverflow   = 0x80000005
	statusBufferTooSmall   = 0xC0000023
)

// ---- object type table ----

type objectType struct {
	Index uint16 `json:"index"`
	Name  string `json:"name"`
}

// parseObjectTypes decodes an OBJECT_TYPES_INFORMATION buffer (64-bit layout): a count, then entries of 104 bytes each
// followed by their type-name string; TypeIndex is the byte at offset 90 of an entry.
func parseObjectTypes(buf []byte, base uintptr) ([]objectType, error) {
	const entrySize, typeIndexOff = 104, 90
	if len(buf) < 8 {
		return nil, errors.New("object type buffer too short")
	}
	n := int(binary.LittleEndian.Uint32(buf))
	off := 8
	var out []objectType
	for i := 0; i < n; i++ {
		if off < 0 || off+entrySize > len(buf) {
			return out, fmt.Errorf("object type entry %d runs past the buffer", i)
		}
		e := buf[off:]
		nameLen := int(binary.LittleEndian.Uint16(e[0:]))
		maxLen := int(binary.LittleEndian.Uint16(e[2:]))
		ptr := uintptr(binary.LittleEndian.Uint64(e[8:]))
		if ptr < base || nameLen%2 != 0 || nameLen > maxLen {
			return out, fmt.Errorf("object type entry %d has an invalid name", i)
		}
		no := int(ptr - base)
		if no < 0 || no+nameLen > len(buf) {
			return out, fmt.Errorf("object type entry %d name runs past the buffer", i)
		}
		u := make([]uint16, nameLen/2)
		for j := range u {
			u[j] = binary.LittleEndian.Uint16(buf[no+2*j:])
		}
		out = append(out, objectType{Index: uint16(e[typeIndexOff]), Name: string(utf16.Decode(u))})
		off = (no + maxLen + 7) &^ 7
	}
	return out, nil
}

func queryObjectTypes() ([]objectType, error) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return nil, fmt.Errorf("%w: the object type layout is only implemented for 64-bit Windows", collector.ErrNotSupported)
	}
	size := uint32(64 << 10)
	for i := 0; i < 6; i++ {
		buf := make([]byte, size)
		var ret uint32
		r, _, _ := pNtQueryObject.Call(0, objectTypesInformation, uintptr(unsafe.Pointer(&buf[0])), uintptr(size), uintptr(unsafe.Pointer(&ret)))
		switch uint32(r) {
		case 0:
			return parseObjectTypes(buf[:min(int(ret), len(buf))], uintptr(unsafe.Pointer(&buf[0])))
		case statusInfoLengthMismatch, statusBufferOverflow, statusBufferTooSmall:
			size = max(ret, size*2)
		default:
			return nil, fmt.Errorf("NtQueryObject(ObjectTypesInformation) NTSTATUS 0x%08x", uint32(r))
		}
	}
	return nil, errors.New("the object type table kept growing")
}

// ---- system handle table ----

type handleEntry struct {
	Object, PID, Handle uint64
	Access              uint32
	Type                uint16
}

// readSystemHandles reads SystemExtendedHandleInformation and decodes every entry.
func readSystemHandles(ctx context.Context) ([]handleEntry, error) {
	const systemExtendedHandleInformation = 64
	size := uint32(4 << 20)
	var buf []byte
	complete := false
	for i := 0; i < 8 && !complete; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		buf = make([]byte, size)
		var ret uint32
		r, _, _ := pNtQuerySystemInfo.Call(systemExtendedHandleInformation, uintptr(unsafe.Pointer(&buf[0])), uintptr(size), uintptr(unsafe.Pointer(&ret)))
		if uint32(r) == statusInfoLengthMismatch {
			size = ret + (1 << 20)
			continue
		}
		if r != 0 {
			return nil, fmt.Errorf("NtQuerySystemInformation(SystemExtendedHandleInformation) NTSTATUS 0x%08x", uint32(r))
		}
		complete = true
	}
	if !complete {
		return nil, errors.New("the handle table kept growing while it was being read")
	}
	// SYSTEM_HANDLE_INFORMATION_EX { ULONG_PTR NumberOfHandles; ULONG_PTR Reserved; Entries[] }
	// entry: PVOID Object; ULONG_PTR UniqueProcessId; ULONG_PTR HandleValue; ULONG GrantedAccess; USHORT CreatorBackTraceIndex;
	//   USHORT ObjectTypeIndex; ULONG HandleAttributes; ULONG Reserved
	ps := int(unsafe.Sizeof(uintptr(0)))
	var count int
	if ps == 8 {
		count = int(binary.LittleEndian.Uint64(buf[:8]))
	} else {
		count = int(binary.LittleEndian.Uint32(buf[:4]))
	}
	entrySize, pidOff, hOff, accOff, typeOff := 28, 4, 8, 12, 18
	if ps == 8 {
		entrySize, pidOff, hOff, accOff, typeOff = 40, 8, 16, 24, 30
	}
	if limit := (len(buf) - 2*ps) / entrySize; count > limit {
		count = limit
	}
	rd := func(b []byte) uint64 {
		if ps == 8 {
			return binary.LittleEndian.Uint64(b)
		}
		return uint64(binary.LittleEndian.Uint32(b))
	}
	out := make([]handleEntry, 0, count)
	for i := 0; i < count; i++ {
		e := buf[2*ps+entrySize*i:]
		out = append(out, handleEntry{Object: rd(e), PID: rd(e[pidOff:]), Handle: rd(e[hOff:]),
			Access: binary.LittleEndian.Uint32(e[accOff:]), Type: binary.LittleEndian.Uint16(e[typeOff:])})
	}
	return out, nil
}

// ---- access masks ----

func decodeAccess(mask uint32, names map[uint32]string) []string {
	var out []string
	keys := make([]uint32, 0, len(names))
	for k := range names {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, k := range keys {
		if mask&k != 0 {
			out = append(out, names[k])
		}
	}
	return out
}

var processAccessNames = map[uint32]string{0x1: "TERMINATE", 0x2: "CREATE_THREAD", 0x8: "VM_OPERATION", 0x10: "VM_READ", 0x20: "VM_WRITE", 0x40: "DUP_HANDLE",
	0x80: "CREATE_PROCESS", 0x100: "SET_QUOTA", 0x200: "SET_INFORMATION", 0x400: "QUERY_INFORMATION", 0x800: "SUSPEND_RESUME",
	0x1000: "QUERY_LIMITED_INFORMATION", 0x2000: "SET_LIMITED_INFORMATION", 0x100000: "SYNCHRONIZE"}

var threadAccessNames = map[uint32]string{0x1: "TERMINATE", 0x2: "SUSPEND_RESUME", 0x8: "GET_CONTEXT", 0x10: "SET_CONTEXT", 0x20: "SET_INFORMATION",
	0x40: "QUERY_INFORMATION", 0x80: "SET_THREAD_TOKEN", 0x100: "IMPERSONATE", 0x200: "DIRECT_IMPERSONATION", 0x400: "SET_LIMITED_INFORMATION",
	0x800: "QUERY_LIMITED_INFORMATION", 0x100000: "SYNCHRONIZE"}

// handleFlags names the access combinations an investigator looks for in a handle to another process or thread.
func handleFlags(typ string, mask uint32, targetName string) []string {
	var f []string
	switch typ {
	case "Process":
		if mask&0x10 != 0 {
			f = append(f, "memory-read")
		}
		if mask&(0x20|0x8) != 0 {
			f = append(f, "memory-write")
		}
		if mask&0x2 != 0 {
			f = append(f, "create-thread")
		}
		if mask&0x40 != 0 {
			f = append(f, "dup-handle")
		}
		if strings.EqualFold(targetName, "lsass.exe") && mask&0x10 != 0 {
			f = append(f, "lsass-memory-read")
		}
	case "Thread":
		if mask&0x10 != 0 {
			f = append(f, "set-context")
		}
		if mask&0x2 != 0 {
			f = append(f, "suspend-resume")
		}
	}
	return f
}

// ---- object names ----

// objectName returns the NT name of an object, or "" when it has none or the query fails.
func objectName(h windows.Handle) string {
	size := uint32(1024)
	for i := 0; i < 4; i++ {
		buf := make([]byte, size)
		var ret uint32
		r, _, _ := pNtQueryObject.Call(uintptr(h), objectNameInformation, uintptr(unsafe.Pointer(&buf[0])), uintptr(size), uintptr(unsafe.Pointer(&ret)))
		switch uint32(r) {
		case 0:
			// UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer } at the start of buf; Buffer points into buf
			n := int(binary.LittleEndian.Uint16(buf))
			ptr := uintptr(binary.LittleEndian.Uint64(buf[8:]))
			base := uintptr(unsafe.Pointer(&buf[0]))
			if n == 0 || ptr < base || int(ptr-base)+n > len(buf) {
				return ""
			}
			o := int(ptr - base)
			u := make([]uint16, n/2)
			for j := range u {
				u[j] = binary.LittleEndian.Uint16(buf[o+2*j:])
			}
			return string(utf16.Decode(u))
		case statusInfoLengthMismatch, statusBufferOverflow, statusBufferTooSmall:
			size = max(ret, size*2)
		default:
			return ""
		}
	}
	return ""
}

// objectNameWithin names an object in a goroutine and gives up after d: the blocked call is abandoned, never waited on.
func objectNameWithin(h windows.Handle, d time.Duration) (string, bool) {
	ch := make(chan string, 1)
	go func() { ch <- objectName(h) }()
	select {
	case s := <-ch:
		return s, true
	case <-time.After(d):
		return "", false
	}
}

var systemFilePath = regexp.MustCompile(`(?i)^\\device\\harddiskvolume\d+\\windows\\`)

// isSystemFile reports file handles that add noise without evidence value: Afd/console devices and files under \Windows.
func isSystemFile(name string) bool {
	l := strings.ToLower(name)
	for _, p := range noiseFilePrefixes {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return systemFilePath.MatchString(name)
}

// ---- per-handle list ----

type handleRecord struct {
	PID         uint32   `json:"pid"`
	Process     string   `json:"process,omitempty"`
	Handle      string   `json:"handle"`
	Type        string   `json:"type"`
	Access      string   `json:"access"`
	AccessFlags []string `json:"access_flags,omitempty"`
	Name        string   `json:"name,omitempty"`
	TargetPID   uint32   `json:"target_pid,omitempty"`
	TargetName  string   `json:"target_process,omitempty"`
	Flags       []string `json:"flags,omitempty"`
}

func processHandleDetail(ctx context.Context, w *warnings) (any, error) {
	enablePrivilege("SeDebugPrivilege")
	types, terr := queryObjectTypes()
	if terr != nil {
		return nil, terr
	}
	typeName := map[uint16]string{}
	for _, t := range types {
		typeName[t.Index] = t.Name
	}
	entries, err := readSystemHandles(ctx)
	if err != nil {
		return nil, err
	}
	names := processNames()
	self := uint32(os.Getpid())
	selfProc := windows.CurrentProcess()
	deadline := time.Now().Add(handleDetailBudget)

	srcs := map[uint32]windows.Handle{}
	failed := map[uint32]string{}
	defer func() {
		for _, h := range srcs {
			windows.CloseHandle(h)
		}
	}()
	open := func(pid uint32) windows.Handle {
		if h, ok := srcs[pid]; ok {
			return h
		}
		if _, bad := failed[pid]; bad {
			return 0
		}
		if isCredentialProcess(names[pid]) { // handles owned by lsass/lsaiso are never duplicated
			failed[pid] = "not opened: credential process"
			return 0
		}
		h, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, pid)
		if err != nil {
			failed[pid] = err.Error()
			return 0
		}
		srcs[pid] = h
		return h
	}
	pidOf := func(proc *windows.LazyProc, h windows.Handle) uint32 {
		id, _, _ := proc.Call(uintptr(h))
		return uint32(id)
	}

	var out []handleRecord
	counts := map[string]int{}
	skippedNoise, unnamed, stuck := 0, 0, 0
	fileNames := true
	truncated := ""
	for i, e := range entries {
		if i&0x3ff == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if time.Now().After(deadline) {
				truncated = fmt.Sprintf("time budget of %s reached after %d of %d handles", handleDetailBudget, i, len(entries))
				break
			}
		}
		typ := typeName[e.Type]
		if !handleTypesOfInterest[typ] || e.PID == 0 || e.PID == 4 || uint32(e.PID) == self {
			continue
		}
		if typ == "File" && !fileNames {
			continue
		}
		pid := uint32(e.PID)
		src := open(pid)
		if src == 0 {
			continue
		}
		var dup windows.Handle
		rec := handleRecord{PID: pid, Process: names[pid], Handle: fmt.Sprintf("0x%x", e.Handle), Type: typ, Access: fmt.Sprintf("0x%x", e.Access)}
		switch typ {
		case "Process", "Thread":
			// ask for a handle that can only be queried, so the target can be identified without extra rights
			query, proc := uint32(0x1000), pGetProcessID
			if typ == "Thread" {
				query, proc = 0x800, pGetProcessIDOfThread
			}
			if err := windows.DuplicateHandle(src, windows.Handle(e.Handle), selfProc, &dup, query, false, 0); err != nil {
				if err := windows.DuplicateHandle(src, windows.Handle(e.Handle), selfProc, &dup, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
					continue
				}
			}
			rec.TargetPID = pidOf(proc, dup)
			windows.CloseHandle(dup)
			if rec.TargetPID == 0 || rec.TargetPID == pid {
				continue // handles to itself are noise; unknown targets cannot be reported
			}
			rec.TargetName = names[rec.TargetPID]
			if typ == "Process" {
				rec.AccessFlags = decodeAccess(e.Access, processAccessNames)
			} else {
				rec.AccessFlags = decodeAccess(e.Access, threadAccessNames)
			}
			rec.Flags = handleFlags(typ, e.Access, rec.TargetName)
		default:
			if err := windows.DuplicateHandle(src, windows.Handle(e.Handle), selfProc, &dup, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
				continue
			}
			if typ == "File" {
				nm, ok := objectNameWithin(dup, fileNameTimeout)
				if !ok { // the dup handle is still in use by the blocked call: leave it open
					stuck++
					if stuck >= maxStuckFileNames {
						fileNames = false
					}
					continue
				}
				rec.Name = nm
				windows.CloseHandle(dup)
				if rec.Name == "" {
					unnamed++
					continue
				}
				if isSystemFile(rec.Name) {
					skippedNoise++
					continue
				}
			} else {
				rec.Name = objectName(dup)
				windows.CloseHandle(dup)
				if rec.Name == "" {
					unnamed++ // unnamed mutexes, sections and ports say nothing about behavior
					continue
				}
			}
		}
		counts[typ]++
		if len(out) >= maxHandleRecords {
			truncated = fmt.Sprintf("record limit of %d reached", maxHandleRecords)
			break
		}
		out = append(out, rec)
	}
	if truncated != "" {
		w.add("handle list incomplete: %s", truncated)
	}
	if stuck > 0 {
		w.add("%d file handle(s) did not answer a name query within %s (synchronous pipes or devices); %s", stuck, fileNameTimeout,
			map[bool]string{true: "file names stayed enabled", false: "file name resolution was switched off for the rest of the run"}[fileNames])
	}
	if len(failed) > 0 {
		var fp []string
		for pid, msg := range failed {
			fp = append(fp, fmt.Sprintf("%d:%s (%s)", pid, names[pid], msg))
		}
		sort.Strings(fp)
		w.add("%d process(es) could not be opened to duplicate their handles (protected or access denied): %s", len(failed), strings.Join(fp[:min(len(fp), 10)], "; "))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PID != out[j].PID {
			return out[i].PID < out[j].PID
		}
		return out[i].Handle < out[j].Handle
	})
	return map[string]any{
		"note": "Handles of the types Process, Thread (only to other processes, with granted access), Mutant, Section, ALPC Port, Key and File, named without blocking. " +
			"Unnamed objects, system file paths and devices that only add noise are counted, not listed",
		"object_types": types, "total_handles": len(entries), "listed": len(out), "listed_by_type": counts,
		"unnamed_skipped": unnamed, "noise_files_skipped": skippedNoise, "handles": out}, nil
}

func processHandlesSource() collector.Source {
	m := baseMeta("Process handles (named)", "Handles to other processes and threads with granted access, and the named mutexes, sections, ALPC ports, registry keys and files each process holds",
		"processes", collector.PrivDebug, collector.InFullOnly)
	m.SideEffects = "duplicates handles of other processes into Mantis to read their object names; file names are queried under a timeout"
	return withDetect(jsonSource("processes-handles", m, "ntquerysystem+duplicatehandle+ntqueryobject", "api://process-handles", processHandleDetail), available)
}
