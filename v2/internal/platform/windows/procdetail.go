//go:build windows

package windows

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"golang.org/x/sys/windows"
)

// Process detail that goes beyond the Toolhelp view: token (privileges, logon session, impersonation),
// protection level, architecture, PEB-recorded paths, parent validity and local-profile user names.

var pIsWow64Process2 = kernel32.NewProc("IsWow64Process2")

const (
	processBasicInformation      = 0
	processWow64Information      = 26
	processProtectionInformation = 61
	maxPEBString                 = 64 << 10
	maxEnvironmentBytes          = 256 << 10
)

// ---- token ----

type tokenDetails struct {
	Type, Impersonation, Elevation string
	LogonSession                   string
	AppContainer                   *bool
	Enabled, Disabled              []string
}

var (
	privNameMu    sync.Mutex
	privNameCache = map[windows.LUID]string{}
)

func privilegeName(l windows.LUID) string {
	privNameMu.Lock()
	defer privNameMu.Unlock()
	if n, ok := privNameCache[l]; ok {
		return n
	}
	n := lookupPrivilegeName(l)
	if n == "" {
		n = fmt.Sprintf("LUID(%d,%d)", l.HighPart, l.LowPart)
	}
	privNameCache[l] = n
	return n
}

var pLookupPrivilegeName = advapi32.NewProc("LookupPrivilegeNameW")

func lookupPrivilegeName(l windows.LUID) string {
	var buf [128]uint16
	n := uint32(len(buf))
	if r, _, _ := pLookupPrivilegeName.Call(0, uintptr(unsafe.Pointer(&l)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n))); r == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

func tokenQuery(tok windows.Token, class uint32) []byte {
	var n uint32
	windows.GetTokenInformation(tok, class, nil, 0, &n)
	if n == 0 || n > 1<<20 {
		return nil
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(tok, class, &buf[0], n, &n); err != nil {
		return nil
	}
	return buf[:n]
}

// readTokenDetails decodes TokenStatistics, TokenElevationType, TokenIsAppContainer and TokenPrivileges.
func readTokenDetails(tok windows.Token) tokenDetails {
	var d tokenDetails
	if b := tokenQuery(tok, windows.TokenStatistics); len(b) >= 28 {
		// TOKEN_STATISTICS: TokenId LUID, AuthenticationId LUID, ExpirationTime, TokenType, ImpersonationLevel, ...
		d.LogonSession = fmt.Sprintf("0x%x", uint64(binary.LittleEndian.Uint32(b[12:]))<<32|uint64(binary.LittleEndian.Uint32(b[8:])))
		d.Type = map[uint32]string{1: "primary", 2: "impersonation"}[binary.LittleEndian.Uint32(b[24:])]
		if d.Type == "impersonation" && len(b) >= 32 {
			d.Impersonation = []string{"anonymous", "identification", "impersonation", "delegation"}[min(binary.LittleEndian.Uint32(b[28:]), 3)]
		}
	}
	if b := tokenQuery(tok, windows.TokenElevationType); len(b) >= 4 {
		d.Elevation = map[uint32]string{1: "default", 2: "full", 3: "limited"}[binary.LittleEndian.Uint32(b)]
	}
	if b := tokenQuery(tok, 29); len(b) >= 4 { // TokenIsAppContainer
		v := binary.LittleEndian.Uint32(b) != 0
		d.AppContainer = &v
	}
	if b := tokenQuery(tok, windows.TokenPrivileges); len(b) >= 4 {
		count := int(binary.LittleEndian.Uint32(b))
		for i := 0; i < count && 4+12*(i+1) <= len(b); i++ {
			e := b[4+12*i:]
			l := windows.LUID{LowPart: binary.LittleEndian.Uint32(e), HighPart: int32(binary.LittleEndian.Uint32(e[4:]))}
			name := privilegeName(l)
			if binary.LittleEndian.Uint32(e[8:])&windows.SE_PRIVILEGE_ENABLED != 0 {
				d.Enabled = append(d.Enabled, name)
			} else {
				d.Disabled = append(d.Disabled, name)
			}
		}
		sort.Strings(d.Enabled)
		sort.Strings(d.Disabled)
	}
	return d
}

// ---- protection level and architecture ----

var protectionSigners = []string{"", "Authenticode", "CodeGen", "Antimalware", "Lsa", "Windows", "WinTcb", "WinSystem", "App"}

// protectionName decodes a PS_PROTECTION byte: type in bits 0-2, signer in bits 4-7.
func protectionName(b byte) string {
	typ := map[byte]string{1: "PPL", 2: "PP"}[b&7]
	if typ == "" {
		return ""
	}
	signer := "Unknown"
	if s := int(b >> 4); s < len(protectionSigners) {
		signer = protectionSigners[s]
	}
	return typ + "-" + signer
}

func processProtection(h windows.Handle) string {
	var b byte
	var ret uint32
	if r, _, _ := pNtQueryInformationPrc.Call(uintptr(h), processProtectionInformation, uintptr(unsafe.Pointer(&b)), 1, uintptr(unsafe.Pointer(&ret))); r != 0 {
		return ""
	}
	return protectionName(b)
}

func peMachineName(m uint16) string {
	switch m {
	case 0x14c:
		return "x86"
	case 0x8664:
		return "x64"
	case 0xaa64:
		return "arm64"
	case 0x1c4:
		return "arm"
	}
	return fmt.Sprintf("0x%x", m)
}

// processArchitecture reports the architecture of the process; a 32-bit process on 64-bit Windows is marked as WOW64.
func processArchitecture(h windows.Handle) (arch string, wow64 bool) {
	if pIsWow64Process2.Find() != nil {
		return "", false
	}
	var proc, native uint16
	if r, _, _ := pIsWow64Process2.Call(uintptr(h), uintptr(unsafe.Pointer(&proc)), uintptr(unsafe.Pointer(&native))); r == 0 {
		return "", false
	}
	if proc != 0 {
		return peMachineName(proc) + " (WOW64/emulated)", true
	}
	// x64 code on ARM64 is emulated without WOW64, so IsWow64Process2 reports nothing: ask for the process machine
	if m, ok := processMachine(h); ok && m != native {
		return peMachineName(m) + " (emulated)", false
	}
	return peMachineName(native), false
}

var pGetProcessInformation = kernel32.NewProc("GetProcessInformation")

// processMachine reads PROCESS_MACHINE_INFORMATION (Windows 11 and later); ok is false where it is unavailable.
func processMachine(h windows.Handle) (uint16, bool) {
	if pGetProcessInformation.Find() != nil {
		return 0, false
	}
	const processMachineTypeInfo = 9
	var info struct {
		Machine    uint16
		Reserved   uint16
		Attributes uint32
	}
	if r, _, _ := pGetProcessInformation.Call(uintptr(h), processMachineTypeInfo, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info)); r == 0 || info.Machine == 0 {
		return 0, false
	}
	return info.Machine, true
}

// ---- PEB ----

type pebInfo struct {
	ImagePath, CommandLine, CurrentDirectory, WindowTitle string
	environment                                           uint64 // address of the environment block in the target
	wow64                                                 bool
}

func readRemote(h windows.Handle, addr uint64, n int) []byte {
	if addr == 0 || n <= 0 {
		return nil
	}
	buf := make([]byte, n)
	var read uintptr
	if err := windows.ReadProcessMemory(h, uintptr(addr), &buf[0], uintptr(n), &read); err != nil && read == 0 {
		return nil
	}
	return buf[:read]
}

func readRemoteString(h windows.Handle, addr uint64, byteLen int) string {
	if byteLen <= 0 || byteLen > maxPEBString {
		return ""
	}
	b := readRemote(h, addr, byteLen&^1)
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// readPEB reads the process parameters recorded in the target's PEB. The process must have been opened with
// PROCESS_QUERY_INFORMATION|PROCESS_VM_READ. 32-bit processes use their own 32-bit PEB.
func readPEB(h windows.Handle) (pebInfo, error) {
	var info pebInfo
	var wow uint64
	var ret uint32
	pNtQueryInformationPrc.Call(uintptr(h), processWow64Information, uintptr(unsafe.Pointer(&wow)), 8, uintptr(unsafe.Pointer(&ret)))
	str := func(params []byte, lenOff, ptrOff int, ptrSize int) string {
		if len(params) < ptrOff+ptrSize {
			return ""
		}
		l := int(binary.LittleEndian.Uint16(params[lenOff:]))
		var p uint64
		if ptrSize == 8 {
			p = binary.LittleEndian.Uint64(params[ptrOff:])
		} else {
			p = uint64(binary.LittleEndian.Uint32(params[ptrOff:]))
		}
		return readRemoteString(h, p, l)
	}
	if wow != 0 { // 32-bit PEB: ProcessParameters at +0x10; RTL_USER_PROCESS_PARAMETERS32 offsets
		pb := readRemote(h, wow+0x10, 4)
		if len(pb) < 4 {
			return info, fmt.Errorf("cannot read the 32-bit PEB")
		}
		params := readRemote(h, uint64(binary.LittleEndian.Uint32(pb)), 0x80)
		if len(params) < 0x78 {
			return info, fmt.Errorf("cannot read the 32-bit process parameters")
		}
		info.wow64 = true
		info.CurrentDirectory = str(params, 0x24, 0x28, 4)
		info.ImagePath = str(params, 0x38, 0x3c, 4)
		info.CommandLine = str(params, 0x40, 0x44, 4)
		info.WindowTitle = str(params, 0x70, 0x74, 4)
		info.environment = uint64(binary.LittleEndian.Uint32(params[0x48:]))
		return info, nil
	}
	var pbi [48]byte
	if r, _, _ := pNtQueryInformationPrc.Call(uintptr(h), processBasicInformation, uintptr(unsafe.Pointer(&pbi[0])), uintptr(len(pbi)), uintptr(unsafe.Pointer(&ret))); r != 0 {
		return info, fmt.Errorf("NtQueryInformationProcess(ProcessBasicInformation) NTSTATUS 0x%08x", uint32(r))
	}
	peb := binary.LittleEndian.Uint64(pbi[8:])
	pp := readRemote(h, peb+0x20, 8)
	if len(pp) < 8 {
		return info, fmt.Errorf("cannot read the PEB")
	}
	params := readRemote(h, binary.LittleEndian.Uint64(pp), 0xC0)
	if len(params) < 0xC0 {
		return info, fmt.Errorf("cannot read the process parameters")
	}
	info.CurrentDirectory = str(params, 0x38, 0x40, 8)
	info.ImagePath = str(params, 0x60, 0x68, 8)
	info.CommandLine = str(params, 0x70, 0x78, 8)
	info.WindowTitle = str(params, 0xB0, 0xB8, 8)
	info.environment = binary.LittleEndian.Uint64(params[0x80:])
	return info, nil
}

// splitEnvironment turns a double-NUL terminated UTF-16 environment block into NAME=value strings.
func splitEnvironment(b []byte) []string {
	var out []string
	var cur []uint16
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			if len(cur) == 0 {
				break // empty string: end of block
			}
			out = append(out, string(utf16.Decode(cur)))
			cur = cur[:0]
			continue
		}
		cur = append(cur, c)
	}
	if len(cur) > 0 {
		out = append(out, string(utf16.Decode(cur)))
	}
	return out
}

// readEnvironmentBlock reads the environment of the target up to its terminating double NUL (bounded).
func readEnvironmentBlock(h windows.Handle, addr uint64) []byte {
	var out []byte
	for len(out) < maxEnvironmentBytes {
		chunk := readRemote(h, addr+uint64(len(out)), 4096)
		if len(chunk) == 0 {
			break
		}
		out = append(out, chunk...)
		for i := 0; i+3 < len(out); i += 2 {
			if out[i] == 0 && out[i+1] == 0 && out[i+2] == 0 && out[i+3] == 0 {
				return out[:i+4]
			}
		}
		if len(chunk) < 4096 {
			break
		}
	}
	return out
}

// samePath compares the image path recorded in the PEB with the one the kernel reports. Both are brought to one
// spelling first (\SystemRoot, \??\ and \\?\ prefixes, 8.3 short names); ok is false when the PEB path is not a
// drive path after that (nothing can be concluded, so no mismatch is claimed).
func samePath(peb, kernel string) (same, ok bool) {
	norm := func(s string) string {
		s = strings.TrimSpace(s)
		l := strings.ToLower(s)
		switch {
		case strings.HasPrefix(l, `\\?\`), strings.HasPrefix(l, `\??\`):
			s = s[4:]
		case strings.HasPrefix(l, `\systemroot\`):
			s = windowsDir() + s[len(`\systemroot`):]
		}
		if strings.Contains(s, "~") {
			s = normalizeModulePath(s)
		}
		return strings.ToLower(s)
	}
	p, k := norm(peb), norm(kernel)
	if len(p) < 3 || p[1] != ':' || len(k) < 3 || k[1] != ':' {
		return false, false
	}
	return p == k, true
}

// isCredentialProcess names the processes whose memory holds credentials (LSA and its isolated counterpart).
func isCredentialProcess(name string) bool {
	return strings.EqualFold(name, "lsass.exe") || strings.EqualFold(name, "lsaiso.exe")
}

// ---- parent validity ----

// resolveParents records whether each process's parent is still running. Windows reuses PIDs, so a parent
// that was created after its child cannot be the real parent: it is reported as pid-reused.
func resolveParents(procs []procRecord) {
	by := make(map[uint32]*procRecord, len(procs))
	for i := range procs {
		by[procs[i].PID] = &procs[i]
	}
	parse := func(s string) time.Time { t, _ := time.Parse(time.RFC3339Nano, s); return t }
	for i := range procs {
		p := &procs[i]
		if p.PID == 0 || p.ParentPID == 0 {
			continue
		}
		par := by[p.ParentPID]
		switch {
		case par == nil:
			p.ParentState = "exited"
		case par.CreatedUTC == "" || p.CreatedUTC == "":
			// without both creation times the parent cannot be told apart from a newer process that took the PID
			p.ParentState = "unverified"
		case parse(par.CreatedUTC).After(parse(p.CreatedUTC)):
			p.ParentState = "pid-reused"
		default:
			p.ParentState = "running"
			p.ParentName = par.Name
		}
	}
}

// ---- user names from local profiles ----

var (
	profileNamesOnce sync.Once
	profileNames     map[string]string
)

// profileUserName resolves a domain account SID to the name of its local profile folder without contacting a
// domain controller (ProfileList keeps SID -> profile path).
func profileUserName(sid string) string {
	profileNamesOnce.Do(func() {
		profileNames = map[string]string{}
		for _, up := range userProfiles() {
			if up.SID != "" {
				profileNames[strings.ToUpper(up.SID)] = up.Name
			}
		}
	})
	return profileNames[strings.ToUpper(sid)]
}

// ---- environment (sensitive) ----

type envRecord struct {
	PID         uint32   `json:"pid"`
	Name        string   `json:"name"`
	Variables   []string `json:"variables,omitempty"`
	Truncated   bool     `json:"truncated,omitempty"`
	Unavailable string   `json:"unavailable,omitempty"`
}

// processEnvironment reads the environment block of every process that can be opened with read access. Environment
// variables regularly hold tokens, keys and passwords: this source is sensitive and Full-only.
func processEnvironment(ctx context.Context, w *warnings) (any, error) {
	enablePrivilege("SeDebugPrivilege")
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var out []envRecord
	denied := 0
	for err := windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if pe.ProcessID == 0 || pe.ProcessID == 4 {
			continue
		}
		rec := envRecord{PID: pe.ProcessID, Name: windows.UTF16ToString(pe.ExeFile[:])}
		h, oerr := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pe.ProcessID)
		if oerr != nil {
			rec.Unavailable = "OpenProcess: " + oerr.Error()
			denied++
			out = append(out, rec)
			continue
		}
		if info, perr := readPEB(h); perr != nil {
			rec.Unavailable = perr.Error()
		} else if info.environment != 0 {
			blk := readEnvironmentBlock(h, info.environment)
			rec.Variables = splitEnvironment(blk)
			rec.Truncated = len(blk) >= maxEnvironmentBytes
		}
		windows.CloseHandle(h)
		out = append(out, rec)
	}
	if denied > 0 {
		w.add("%d process(es) could not be opened with read access (protected processes); no protection was bypassed", denied)
	}
	return map[string]any{"processes": out, "count": len(out),
		"note": "environment blocks as recorded in each process's PEB; they may contain secrets"}, nil
}

func processEnvironmentSource() collector.Source {
	m := baseMeta("Process environment variables", "Environment block of every readable process, read from its PEB. May contain tokens, keys and passwords of the user",
		"processes", collector.PrivDebug, collector.InFullOnly)
	m.SideEffects = "reads the PEB and environment block of other processes (read-only memory access)"
	src := jsonSource("processes-environment", m, "peb-environment", "api://process-environment", processEnvironment)
	return sensitiveFullOnly(withDetect(src, available), "process environment blocks regularly contain secrets (API keys, tokens, passwords)")
}
