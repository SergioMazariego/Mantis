//go:build windows

package windows

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
)

// processes-performance records the per-process and per-thread counters that a performance-counter
// process lister reports (priority, CPU times, virtual and pool memory, context switches, thread
// states). It reads SystemProcessInformation in one call: no process handles are opened, so it works
// without elevation and also covers protected processes.

const (
	systemProcessInformation = 5
	spiHeaderSize            = 256 // SYSTEM_PROCESS_INFORMATION without the thread array (64-bit layout)
	sthreadSize              = 80  // SYSTEM_THREAD_INFORMATION (64-bit layout)
)

var threadStates = map[uint32]string{0: "Initialized", 1: "Ready", 2: "Running", 3: "Standby", 4: "Terminated", 5: "Waiting", 6: "Transition",
	7: "DeferredReady", 8: "GateWaitObsolete", 9: "WaitingForProcessInUse"}

var waitReasons = []string{"Executive", "FreePage", "PageIn", "PoolAllocation", "DelayExecution", "Suspended", "UserRequest", "WrExecutive", "WrFreePage",
	"WrPageIn", "WrPoolAllocation", "WrDelayExecution", "WrSuspended", "WrUserRequest", "WrEventPair", "WrQueue", "WrLpcReceive", "WrLpcReply",
	"WrVirtualMemory", "WrPageOut", "WrRendezvous", "WrKeyedEvent", "WrTerminated", "WrProcessInSwap", "WrCpuRateControl", "WrCalloutStack",
	"WrKernel", "WrResource", "WrPushLock", "WrMutex", "WrQuantumEnd", "WrDispatchInt", "WrPreempted", "WrYieldExecution", "WrFastMutex",
	"WrGuardedMutex", "WrRundown", "WrAlertByThreadId", "WrDeferredPreempt"}

type perfThread struct {
	TID             uint64 `json:"tid"`
	Priority        int32  `json:"priority"`
	BasePriority    int32  `json:"base_priority"`
	ContextSwitches uint32 `json:"context_switches"`
	State           string `json:"state"`
	WaitReason      string `json:"wait_reason,omitempty"`
	StartAddress    string `json:"start_address,omitempty"`
	CreatedUTC      string `json:"created_utc,omitempty"`
	UserTime100ns   uint64 `json:"user_time_100ns"`
	KernelTime100ns uint64 `json:"kernel_time_100ns"`
	WaitTimeTicks   uint32 `json:"wait_time_ticks,omitempty"`
}

type perfProcess struct {
	PID                 uint64       `json:"pid"`
	ParentPID           uint64       `json:"parent_pid"`
	Name                string       `json:"name"`
	BasePriority        int32        `json:"base_priority"`
	Threads             uint32       `json:"threads"`
	ThreadsPeak         uint32       `json:"threads_peak"`
	Handles             uint32       `json:"handle_count"`
	SessionID           uint32       `json:"session_id"`
	CreatedUTC          string       `json:"created_utc,omitempty"`
	UserTime100ns       uint64       `json:"user_time_100ns"`
	KernelTime100ns     uint64       `json:"kernel_time_100ns"`
	CycleTime           uint64       `json:"cycle_time"`
	VirtualBytes        uint64       `json:"virtual_bytes"`
	PeakVirtualBytes    uint64       `json:"peak_virtual_bytes"`
	WorkingSetBytes     uint64       `json:"working_set_bytes"`
	PeakWorkingSetBytes uint64       `json:"peak_working_set_bytes"`
	WorkingSetPrivate   uint64       `json:"working_set_private_bytes"`
	PrivateBytes        uint64       `json:"private_bytes"`
	PeakPrivateBytes    uint64       `json:"peak_private_bytes"`
	PagefileBytes       uint64       `json:"pagefile_bytes"`
	PageFaults          uint32       `json:"page_faults"`
	HardFaults          uint32       `json:"hard_faults"`
	PagedPoolBytes      uint64       `json:"paged_pool_bytes"`
	PeakPagedPoolBytes  uint64       `json:"peak_paged_pool_bytes"`
	NonPagedPoolBytes   uint64       `json:"nonpaged_pool_bytes"`
	PeakNonPagedBytes   uint64       `json:"peak_nonpaged_pool_bytes"`
	ReadOps             uint64       `json:"io_read_operations"`
	WriteOps            uint64       `json:"io_write_operations"`
	OtherOps            uint64       `json:"io_other_operations"`
	ReadBytes           uint64       `json:"io_read_bytes"`
	WriteBytes          uint64       `json:"io_write_bytes"`
	OtherBytes          uint64       `json:"io_other_bytes"`
	ThreadDetail        []perfThread `json:"thread_detail,omitempty"`
}

// filetimeUTC converts a Windows FILETIME (100 ns since 1601) to RFC 3339 UTC; 0 means "not set".
func filetimeUTC(ft uint64) string {
	if ft == 0 {
		return ""
	}
	const epochDiff = 116444736000000000
	if ft < epochDiff {
		return ""
	}
	return time.Unix(0, int64(ft-epochDiff)*100).UTC().Format(time.RFC3339Nano)
}

// parseProcessInformation decodes a SystemProcessInformation buffer. base is the address of buf[0]:
// image-name pointers inside the buffer are absolute addresses and are translated back to offsets.
// Malformed entries stop the walk with a warning instead of reading out of bounds.
func parseProcessInformation(buf []byte, base uintptr, withThreads bool) ([]perfProcess, []string) {
	var out []perfProcess
	var warns []string
	off := 0
	for {
		if off < 0 || off+spiHeaderSize > len(buf) {
			warns = append(warns, fmt.Sprintf("process entry at offset %d runs past the buffer", off))
			break
		}
		e := buf[off:]
		u32 := func(o int) uint32 { return binary.LittleEndian.Uint32(e[o:]) }
		u64 := func(o int) uint64 { return binary.LittleEndian.Uint64(e[o:]) }
		next := int(u32(0))
		nthreads := int(u32(4))
		p := perfProcess{
			Threads: uint32(nthreads), WorkingSetPrivate: u64(8), HardFaults: u32(16), ThreadsPeak: u32(20), CycleTime: u64(24),
			CreatedUTC: filetimeUTC(u64(32)), UserTime100ns: u64(40), KernelTime100ns: u64(48),
			BasePriority: int32(u32(72)), PID: u64(80), ParentPID: u64(88), Handles: u32(96), SessionID: u32(100),
			PeakVirtualBytes: u64(112), VirtualBytes: u64(120), PageFaults: u32(128), PeakWorkingSetBytes: u64(136), WorkingSetBytes: u64(144),
			PeakPagedPoolBytes: u64(152), PagedPoolBytes: u64(160), PeakNonPagedBytes: u64(168), NonPagedPoolBytes: u64(176),
			PagefileBytes: u64(184), PeakPrivateBytes: u64(192), PrivateBytes: u64(200),
			ReadOps: u64(208), WriteOps: u64(216), OtherOps: u64(224), ReadBytes: u64(232), WriteBytes: u64(240), OtherBytes: u64(248),
		}
		// ImageName: USHORT Length, USHORT MaximumLength, padding, PWSTR Buffer
		nameLen := int(binary.LittleEndian.Uint16(e[56:]))
		namePtr := uintptr(u64(64))
		if nameLen > 0 && namePtr >= base {
			if no := int(namePtr - base); no >= 0 && no+nameLen <= len(buf) && nameLen%2 == 0 {
				u := make([]uint16, nameLen/2)
				for i := range u {
					u[i] = binary.LittleEndian.Uint16(buf[no+2*i:])
				}
				p.Name = string(utf16.Decode(u))
			}
		}
		if p.PID == 0 && p.Name == "" {
			p.Name = "Idle"
		}
		tOff := off + spiHeaderSize
		if nthreads < 0 || tOff+nthreads*sthreadSize > len(buf) {
			warns = append(warns, fmt.Sprintf("pid %d: thread array runs past the buffer", p.PID))
			nthreads = max(0, (len(buf)-tOff)/sthreadSize)
		}
		if withThreads {
			for i := 0; i < nthreads; i++ {
				t := buf[tOff+i*sthreadSize:]
				t32 := func(o int) uint32 { return binary.LittleEndian.Uint32(t[o:]) }
				t64 := func(o int) uint64 { return binary.LittleEndian.Uint64(t[o:]) }
				st, ok := threadStates[t32(68)]
				if !ok {
					st = fmt.Sprintf("Unknown(%d)", t32(68))
				}
				th := perfThread{
					KernelTime100ns: t64(0), UserTime100ns: t64(8), CreatedUTC: filetimeUTC(t64(16)), WaitTimeTicks: t32(24),
					StartAddress: fmt.Sprintf("0x%x", t64(32)), TID: t64(48), Priority: int32(t32(56)), BasePriority: int32(t32(60)),
					ContextSwitches: t32(64), State: st,
				}
				if st == "Waiting" || st == "WaitingForProcessInUse" {
					if wr := int(t32(72)); wr >= 0 && wr < len(waitReasons) {
						th.WaitReason = waitReasons[wr]
					} else {
						th.WaitReason = fmt.Sprintf("Unknown(%d)", wr)
					}
				}
				p.ThreadDetail = append(p.ThreadDetail, th)
			}
		}
		out = append(out, p)
		if next == 0 {
			break
		}
		off += next
	}
	return out, warns
}

func processPerformance(ctx context.Context, w *warnings) (any, error) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return nil, fmt.Errorf("%w: the process information layout is only implemented for 64-bit Windows", collector.ErrNotSupported)
	}
	size := uint32(2 << 20)
	var buf []byte
	var ret uint32
	complete := false
	for i := 0; i < 12 && !complete; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		buf = make([]byte, size)
		r, _, _ := pNtQuerySystemInfo.Call(systemProcessInformation, uintptr(unsafe.Pointer(&buf[0])), uintptr(size), uintptr(unsafe.Pointer(&ret)))
		switch {
		case uint32(r) == statusInfoLengthMismatch:
			size = ret + (512 << 10) // the process list can grow between the size query and the read
		case r != 0:
			return nil, fmt.Errorf("NtQuerySystemInformation(SystemProcessInformation) NTSTATUS 0x%08x", uint32(r))
		default:
			complete = true
		}
	}
	if !complete {
		return nil, errors.New("the process list kept growing while it was being read")
	}
	procs, warns := parseProcessInformation(buf[:ret], uintptr(unsafe.Pointer(&buf[0])), true)
	for _, x := range warns {
		w.add("%s", x)
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	threads := 0
	for _, p := range procs {
		threads += len(p.ThreadDetail)
	}
	return map[string]any{
		"note":          "SystemProcessInformation snapshot: base priority, CPU times (100 ns units), virtual/working/private/pool memory (bytes), page faults, I/O counters and per-thread state, priority and context switches",
		"process_count": len(procs), "thread_count": threads, "processes": procs,
	}, nil
}

func procPerfSource() collector.Source {
	m := baseMeta("Processes (performance counters)", "Per process: base priority, CPU user/kernel times, virtual size, peak private, paged/non-paged pool, page and hard faults, I/O counters; per thread: state, wait reason, priority, context switches, start address and times",
		"processes", collector.PrivUser, collector.InStdFull)
	m.SideEffects = "none; one NtQuerySystemInformation call, no process handles opened"
	return withDetect(jsonSource("processes-performance", m, "ntquerysysteminformation", "api://process-performance", processPerformance), available)
}
