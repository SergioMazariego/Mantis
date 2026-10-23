//go:build windows

package windows

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"unsafe"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"golang.org/x/sys/windows"
)

// processes-memory-map walks the address space of every readable process with VirtualQueryEx and records the
// executable regions: where code runs from, with which protection, and whether a file backs it. Private
// executable memory (no image or file behind it) and RWX regions are what shellcode and reflective loaders leave.
// Only region metadata is recorded, plus whether a private executable region starts with "MZ"; no memory contents
// are stored.

var pGetMappedFileName = psapi.NewProc("GetMappedFileNameW")

const (
	memCommit  = 0x1000
	memImage   = 0x1000000
	memMapped  = 0x40000
	memPrivate = 0x20000

	maxExecRegionsPerProcess = 1500
	maxMZProbesPerProcess    = 256
)

func protectName(p uint32) string {
	base := map[uint32]string{0x01: "NOACCESS", 0x02: "R", 0x04: "RW", 0x08: "WC", 0x10: "X", 0x20: "RX", 0x40: "RWX", 0x80: "WCX"}[p&0xff]
	if base == "" {
		if p == 0 {
			return ""
		}
		base = fmt.Sprintf("0x%x", p&0xff)
	}
	if p&0x100 != 0 {
		base += "+guard"
	}
	if p&0x200 != 0 {
		base += "+nocache"
	}
	if p&0x400 != 0 {
		base += "+writecombine"
	}
	return base
}

func isExecutable(p uint32) bool {
	switch p & 0xff {
	case 0x10, 0x20, 0x40, 0x80:
		return true
	}
	return false
}

func regionType(t uint32) string {
	switch t {
	case memImage:
		return "image"
	case memMapped:
		return "mapped"
	case memPrivate:
		return "private"
	}
	return fmt.Sprintf("0x%x", t)
}

type memRegion struct {
	Base         string `json:"base"`
	Size         uint64 `json:"size"`
	Type         string `json:"type"` // image, mapped or private
	Protect      string `json:"protect"`
	AllocProtect string `json:"alloc_protect,omitempty"`
	File         string `json:"file,omitempty"` // NT path of the image or mapped file behind the region
	RWX          bool   `json:"rwx,omitempty"`
	Unbacked     bool   `json:"unbacked_executable,omitempty"` // executable private memory: no file behind it
	MZ           bool   `json:"mz_header,omitempty"`           // private executable region that starts with "MZ": a mapped PE
}

type memProcess struct {
	PID                 uint32      `json:"pid"`
	Name                string      `json:"name"`
	Regions             int         `json:"regions"`
	CommittedPrivate    uint64      `json:"committed_private_bytes"`
	ExecutableRegions   int         `json:"executable_regions"`
	RWXRegions          int         `json:"rwx_regions"`
	UnbackedExecutable  int         `json:"unbacked_executable_regions"`
	Executable          []memRegion `json:"executable,omitempty"`
	ExecutableTruncated bool        `json:"executable_truncated,omitempty"`
	Unavailable         string      `json:"unavailable,omitempty"`
}

func mappedFileName(h windows.Handle, addr uintptr) string {
	var buf [1024]uint16
	n, _, _ := pGetMappedFileName.Call(uintptr(h), addr, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// walkMemory records the executable regions of one process.
func walkMemory(h windows.Handle) memProcess {
	var mp memProcess
	files := map[uintptr]string{}
	probes := 0
	var addr uintptr
	for {
		var mbi windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(h, addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
			break
		}
		next := mbi.BaseAddress + mbi.RegionSize
		if next <= addr || mbi.RegionSize == 0 {
			break
		}
		addr = next
		mp.Regions++
		if mbi.State != memCommit {
			continue
		}
		if mbi.Type == memPrivate {
			mp.CommittedPrivate += uint64(mbi.RegionSize)
		}
		if !isExecutable(mbi.Protect) {
			continue
		}
		mp.ExecutableRegions++
		reg := memRegion{Base: fmt.Sprintf("0x%x", mbi.BaseAddress), Size: uint64(mbi.RegionSize), Type: regionType(mbi.Type),
			Protect: protectName(mbi.Protect), AllocProtect: protectName(mbi.AllocationProtect)}
		reg.RWX = mbi.Protect&0xff == 0x40
		if reg.RWX {
			mp.RWXRegions++
		}
		switch mbi.Type {
		case memPrivate:
			reg.Unbacked = true
			mp.UnbackedExecutable++
			if probes < maxMZProbesPerProcess {
				probes++
				var sig [2]byte
				var read uintptr
				if err := windows.ReadProcessMemory(h, mbi.BaseAddress, &sig[0], 2, &read); err == nil && read == 2 && sig[0] == 'M' && sig[1] == 'Z' {
					reg.MZ = true
				}
			}
		case memImage, memMapped:
			f, ok := files[mbi.AllocationBase]
			if !ok {
				f = mappedFileName(h, mbi.BaseAddress)
				files[mbi.AllocationBase] = f
			}
			reg.File = f
		}
		if len(mp.Executable) < maxExecRegionsPerProcess {
			mp.Executable = append(mp.Executable, reg)
		} else {
			mp.ExecutableTruncated = true
		}
	}
	return mp
}

func processMemoryMap(ctx context.Context, w *warnings) (any, error) {
	enablePrivilege("SeDebugPrivilege")
	names := processNames()
	pids := make([]uint32, 0, len(names))
	for pid := range names {
		if pid != 0 && pid != 4 {
			pids = append(pids, pid)
		}
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	var out []memProcess
	denied := 0
	var flagged []string
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
		if err != nil {
			denied++
			out = append(out, memProcess{PID: pid, Name: names[pid], Unavailable: "OpenProcess: " + err.Error()})
			continue
		}
		mp := walkMemory(h)
		windows.CloseHandle(h)
		mp.PID, mp.Name = pid, names[pid]
		if mp.UnbackedExecutable > 0 || mp.RWXRegions > 0 {
			flagged = append(flagged, fmt.Sprintf("%d:%s(unbacked=%d,rwx=%d)", pid, mp.Name, mp.UnbackedExecutable, mp.RWXRegions))
		}
		out = append(out, mp)
	}
	if denied > 0 {
		w.add("%d process(es) could not be opened for memory queries (protected processes or insufficient privilege); no protection was bypassed", denied)
	}
	return map[string]any{
		"note": "Executable regions per process: base, size, type (image, mapped, private), protection, backing file, RWX and unbacked-executable flags, and whether a private executable region starts with MZ. " +
			"JIT engines (browsers, .NET, Java, Node.js) legitimately create private executable memory: read the flags together with the process",
		"process_count": len(out), "with_private_or_rwx_executable": len(flagged),
		"flagged": strings.Join(flagged, " "), "processes": out}, nil
}

func processMemoryMapSource() collector.Source {
	m := baseMeta("Process memory map (executable regions)", "Executable memory regions of every readable process: protection, backing file, RWX and unbacked-executable flags (no memory contents are stored)",
		"processes", collector.PrivDebug, collector.InStdFull)
	m.SideEffects = "queries the address space of other processes (VirtualQueryEx) and reads 2 bytes at the start of private executable regions"
	return withDetect(jsonSource("processes-memory-map", m, "virtualqueryex", "api://process-memory-map", processMemoryMap), available)
}
