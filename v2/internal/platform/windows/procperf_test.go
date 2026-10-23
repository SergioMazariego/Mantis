//go:build windows

package windows

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
	"unsafe"
)

// buildProcessBuffer lays out two SYSTEM_PROCESS_INFORMATION entries (64-bit layout) with two and one
// threads, and the image name of the second entry stored after them inside the same buffer.
func buildProcessBuffer() []byte {
	buf := make([]byte, 4096)
	base := uintptr(unsafe.Pointer(&buf[0]))
	put32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(buf[off:], v) }
	put64 := func(off int, v uint64) { binary.LittleEndian.PutUint64(buf[off:], v) }

	// entry 0: Idle (pid 0, no name), 2 threads
	e0 := 0
	put32(e0+0, uint32(spiHeaderSize+2*sthreadSize))
	put32(e0+4, 2)
	put64(e0+80, 0)
	put64(e0+120, 8192)
	for i := 0; i < 2; i++ {
		t := e0 + spiHeaderSize + i*sthreadSize
		put64(t+48, uint64(100+i))      // tid
		put32(t+56, 5)                  // priority
		put32(t+60, 8)                  // base priority
		put32(t+64, uint32(1000*(i+1))) // context switches
		put32(t+68, 5)                  // Waiting
		put32(t+72, 6)                  // UserRequest
	}
	// entry 1: "ping.exe" pid 4321 parent 700, 1 thread
	e1 := e0 + spiHeaderSize + 2*sthreadSize
	name := utf16.Encode([]rune("ping.exe"))
	nameOff := e1 + spiHeaderSize + sthreadSize
	for i, c := range name {
		binary.LittleEndian.PutUint16(buf[nameOff+2*i:], c)
	}
	put32(e1+0, 0) // last entry
	put32(e1+4, 1)
	put64(e1+32, 133700000000000000) // create time
	put64(e1+40, 123)
	put64(e1+48, 456)
	binary.LittleEndian.PutUint16(buf[e1+56:], uint16(len(name)*2))
	binary.LittleEndian.PutUint16(buf[e1+58:], uint16(len(name)*2))
	put64(e1+64, uint64(base)+uint64(nameOff))
	put32(e1+72, 8)
	put64(e1+80, 4321)
	put64(e1+88, 700)
	put32(e1+96, 42)
	put64(e1+120, 1<<30)
	put64(e1+200, 4096*10)
	t := e1 + spiHeaderSize
	put64(t+48, 999)
	put32(t+68, 2) // Running
	put64(t+32, 0x7ff600001000)
	put32(e0, uint32(e1-e0)) // link entry 0 to entry 1
	return buf[:nameOff+len(name)*2+8]
}

func TestParseProcessInformationReadsProcessesAndThreads(t *testing.T) {
	buf := buildProcessBuffer()
	procs, warns := parseProcessInformation(buf, uintptr(unsafe.Pointer(&buf[0])), true, false)
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if len(procs) != 2 {
		t.Fatalf("expected 2 processes, got %d", len(procs))
	}
	idle := procs[0]
	if idle.Name != "Idle" || idle.PID != 0 || len(idle.ThreadDetail) != 2 || idle.VirtualBytes != 8192 {
		t.Errorf("idle entry wrong: %+v", idle)
	}
	if idle.ThreadDetail[1].ContextSwitches != 2000 || idle.ThreadDetail[1].State != "Waiting" || idle.ThreadDetail[1].WaitReason != "UserRequest" {
		t.Errorf("thread decoding wrong: %+v", idle.ThreadDetail[1])
	}
	ping := procs[1]
	if ping.Name != "ping.exe" || ping.PID != 4321 || ping.ParentPID != 700 || ping.Handles != 42 || ping.BasePriority != 8 {
		t.Errorf("ping entry wrong: %+v", ping)
	}
	if ping.UserTime100ns != 123 || ping.KernelTime100ns != 456 || ping.VirtualBytes != 1<<30 || ping.PrivateBytes != 40960 {
		t.Errorf("ping counters wrong: %+v", ping)
	}
	if len(ping.ThreadDetail) != 1 || ping.ThreadDetail[0].State != "Running" || ping.ThreadDetail[0].StartAddress != "0x7ff600001000" || ping.ThreadDetail[0].TID != 999 {
		t.Errorf("ping thread wrong: %+v", ping.ThreadDetail)
	}
	if ping.CreatedUTC == "" {
		t.Error("creation time must be decoded")
	}
}

func TestParseProcessInformationNeverReadsOutOfBounds(t *testing.T) {
	buf := buildProcessBuffer()
	short := buf[:spiHeaderSize+10] // truncated inside the first entry's thread array
	procs, warns := parseProcessInformation(short, uintptr(unsafe.Pointer(&short[0])), true, false)
	if len(warns) == 0 {
		t.Error("a truncated buffer must produce a warning")
	}
	_ = procs
	// a NextEntryOffset that points past the end must not panic
	bad := append([]byte(nil), buf...)
	binary.LittleEndian.PutUint32(bad[0:], 1<<30)
	if _, w := parseProcessInformation(bad, uintptr(unsafe.Pointer(&bad[0])), false, false); len(w) == 0 {
		t.Error("an out-of-range NextEntryOffset must produce a warning")
	}
}

func TestParseExtendedThreadsReadsWin32StartStackAndTeb(t *testing.T) {
	buf := make([]byte, 4096)
	put32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(buf[off:], v) }
	put64 := func(off int, v uint64) { binary.LittleEndian.PutUint64(buf[off:], v) }
	put32(0, 0) // single entry
	put32(4, 2) // two threads
	put64(80, 4321)
	for i := 0; i < 2; i++ {
		th := spiHeaderSize + i*sthreadExtSize
		put64(th+32, 0x7ffb00001000) // kernel start: ntdll!RtlUserThreadStart
		put64(th+48, uint64(500+i))  // tid
		put32(th+68, 5)
		put64(th+80, 0x00000050a0000000+uint64(i)) // stack base
		put64(th+88, 0x00000050a0000000-0x10000)   // stack limit
		put64(th+96, 0x1f2d0000000+uint64(i))      // Win32 start address, inside no module
		put64(th+104, 0x50a1000000)                // TEB
	}
	procs, warns := parseProcessInformation(buf[:spiHeaderSize+2*sthreadExtSize], uintptr(unsafe.Pointer(&buf[0])), true, true)
	if len(warns) != 0 || len(procs) != 1 || len(procs[0].ThreadDetail) != 2 {
		t.Fatalf("expected 1 process with 2 threads, got %+v %v", procs, warns)
	}
	th := procs[0].ThreadDetail[1]
	if th.TID != 501 || th.StartAddress != "0x7ffb00001000" || th.Win32Start != "0x1f2d0000001" || th.TebBase != "0x50a1000000" || th.StackBase != "0x50a0000001" || th.StackLimit != "0x509fff0000" {
		t.Errorf("extended thread fields wrong: %+v", th)
	}
	// the non-extended layout must not invent these fields
	plain, _ := parseProcessInformation(buf[:spiHeaderSize+2*sthreadSize], uintptr(unsafe.Pointer(&buf[0])), true, false)
	if len(plain) == 1 && len(plain[0].ThreadDetail) > 0 && plain[0].ThreadDetail[0].Win32Start != "" {
		t.Error("the plain layout carries no Win32 start address")
	}
}
