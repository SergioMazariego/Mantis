//go:build windows

package windows

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"time"
	"unsafe"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"golang.org/x/sys/windows"
)

var (
	ntdll                  = windows.NewLazySystemDLL("ntdll.dll")
	pNtQueryInformationPrc = ntdll.NewProc("NtQueryInformationProcess")
	pNtQuerySystemInfo     = ntdll.NewProc("NtQuerySystemInformation")
	pGetProcessMemoryInfo  = psapi.NewProc("GetProcessMemoryInfo")
	kernel32               = windows.NewLazySystemDLL("kernel32.dll")
	pGetProcessHandleCount = kernel32.NewProc("GetProcessHandleCount")
	wintrust               = windows.NewLazySystemDLL("wintrust.dll")
	pWinVerifyTrust        = wintrust.NewProc("WinVerifyTrust")
)

const (
	processCommandLineInformation = 60
	statusInfoLengthMismatch      = 0xC0000004
	maxHashFileBytes              = 512 << 20
	maxHashTotalBytes             = 4 << 30
)

type moduleInfo struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Base string `json:"base"`
	Size uint32 `json:"size"`
}

type procRecord struct {
	PID          uint32  `json:"pid"`
	ParentPID    uint32  `json:"parent_pid"`
	ParentName   string  `json:"parent_name,omitempty"`  // only when the parent is still running
	ParentState  string  `json:"parent_state,omitempty"` // running, exited, or pid-reused (the parent PID now belongs to a newer process)
	Name         string  `json:"name"`
	ImagePath    string  `json:"image_path,omitempty"`
	CommandLine  string  `json:"command_line,omitempty"`
	CreatedUTC   string  `json:"created_utc,omitempty"`
	CollectedUTC string  `json:"collected_utc,omitempty"` // when this record was read: the list is walked over several seconds
	SessionID    *uint32 `json:"session_id,omitempty"`
	Threads      uint32  `json:"threads"`
	HandleCount  uint32  `json:"handle_count,omitempty"`
	User         string  `json:"user,omitempty"`
	UserSID      string  `json:"user_sid,omitempty"`
	Elevated     *bool   `json:"token_elevated,omitempty"`
	Integrity    string  `json:"integrity_level,omitempty"`

	TokenType          string   `json:"token_type,omitempty"`
	Impersonation      string   `json:"impersonation_level,omitempty"`
	ElevationType      string   `json:"elevation_type,omitempty"`
	LogonSession       string   `json:"logon_session_id,omitempty"`
	AppContainer       *bool    `json:"app_container,omitempty"`
	PrivilegesEnabled  []string `json:"privileges_enabled,omitempty"`
	PrivilegesDisabled []string `json:"privileges_disabled,omitempty"`
	Protection         string   `json:"protection,omitempty"` // PPL/PP and signer, empty when unprotected
	Architecture       string   `json:"architecture,omitempty"`

	CurrentDirectory string `json:"current_directory,omitempty"` // from the PEB
	PEBImagePath     string `json:"peb_image_path,omitempty"`
	PEBImageMatches  *bool  `json:"peb_image_matches,omitempty"` // PEB image path equals the path the kernel reports: false suggests hollowing or a spoofed image
	WindowTitle      string `json:"window_title,omitempty"`

	WorkingSet   uint64         `json:"working_set_bytes,omitempty"`
	PeakWS       uint64         `json:"peak_working_set_bytes,omitempty"`
	PrivateBytes uint64         `json:"private_bytes,omitempty"`
	PageFaults   uint32         `json:"page_faults,omitempty"`
	Modules      []moduleInfo   `json:"modules,omitempty"`
	Image        *enrichedImage `json:"image,omitempty"`
	Sockets      []socketRecord `json:"sockets,omitempty"`
	Inaccessible []string       `json:"inaccessible,omitempty"` // what could not be read and why (protected process, access denied)
}

func filetimeToUTC(ft windows.Filetime) string {
	if ft.HighDateTime == 0 && ft.LowDateTime == 0 {
		return ""
	}
	return time.Unix(0, ft.Nanoseconds()).UTC().Format(time.RFC3339Nano)
}

func commandLine(h windows.Handle) (string, error) {
	size := uint32(1024)
	for i := 0; i < 4; i++ {
		buf := make([]byte, size)
		var ret uint32
		r, _, _ := pNtQueryInformationPrc.Call(uintptr(h), processCommandLineInformation, uintptr(unsafe.Pointer(&buf[0])), uintptr(size), uintptr(unsafe.Pointer(&ret)))
		switch uint32(r) {
		case 0:
			// UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer }; Buffer points into buf
			length := int(binary.LittleEndian.Uint16(buf))
			ptrOff := 8
			if unsafe.Sizeof(uintptr(0)) == 4 {
				ptrOff = 4
			}
			var ptr uintptr
			if ptrOff == 8 {
				ptr = uintptr(binary.LittleEndian.Uint64(buf[ptrOff:]))
			} else {
				ptr = uintptr(binary.LittleEndian.Uint32(buf[ptrOff:]))
			}
			if length == 0 || ptr == 0 {
				return "", nil
			}
			chars := unsafe.Slice((*uint16)(*(*unsafe.Pointer)(unsafe.Pointer(&ptr))), length/2)
			return windows.UTF16ToString(chars), nil
		case statusInfoLengthMismatch, 0x80000005, 0xC0000023: // length mismatch, buffer overflow, buffer too small
			if ret > size {
				size = ret + 64
			} else {
				size *= 2
			}
		default:
			return "", fmt.Errorf("NtQueryInformationProcess(CommandLine) NTSTATUS 0x%08x", uint32(r))
		}
	}
	return "", fmt.Errorf("command line buffer kept growing")
}

func integrityName(tok windows.Token) string {
	var n uint32
	windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, nil, 0, &n)
	if n == 0 {
		return ""
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, &buf[0], n, &n); err != nil {
		return ""
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
	sid := label.Label.Sid
	if sid == nil || sid.SubAuthorityCount() == 0 {
		return ""
	}
	rid := sid.SubAuthority(uint32(sid.SubAuthorityCount()) - 1)
	switch {
	case rid >= 0x4000:
		return "system+"
	case rid >= 0x3000:
		return "high"
	case rid >= 0x2000:
		return "medium"
	case rid >= 0x1000:
		return "low"
	}
	return "untrusted"
}

func modulesOf(pid uint32) ([]moduleInfo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var me windows.ModuleEntry32
	me.Size = uint32(unsafe.Sizeof(me))
	var out []moduleInfo
	for err := windows.Module32First(snap, &me); err == nil; err = windows.Module32Next(snap, &me) {
		out = append(out, moduleInfo{Name: windows.UTF16ToString(me.Module[:]), Path: windows.UTF16ToString(me.ExePath[:]),
			Base: fmt.Sprintf("0x%x", me.ModBaseAddr), Size: me.ModBaseSize})
	}
	return out, nil
}

// ---- image hashing and Authenticode ----

// Process images are described with the same enrichment used for persistence images (see imageEnricher):
// hashes, Authenticode verdict and signer, company, product, version, original file name and import hash.

type wintrustFileInfo struct {
	Size      uint32
	FilePath  *uint16
	File      windows.Handle
	KnownSubj *windows.GUID
}

type wintrustData struct {
	Size           uint32
	PolicyCB       uintptr
	SIPClientData  uintptr
	UIChoice       uint32
	RevocationChk  uint32
	UnionChoice    uint32
	File           *wintrustFileInfo
	StateAction    uint32
	StateData      windows.Handle
	URLReference   *uint16
	ProvFlags      uint32
	UIContext      uint32
	SignatureSetts uintptr
}

var wvtGenericVerifyV2 = windows.GUID{Data1: 0x00AAC56B, Data2: 0xCD44, Data3: 0x11D0, Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE}}

// verifySignature checks the embedded Authenticode signature without UI or network
// access (revocation checks are off and URL retrieval is cache-only). Files that are
// catalog-signed (most Windows binaries) report "no embedded signature"; this is a
// documented limitation of the embedded-only check.
func verifySignature(path string) (string, string) {
	st, code, _ := verifySignatureDetail(path)
	return st, code
}

// verifySignatureDetail is verifySignature plus the name of the signer certificate (embedded signature, or the
// catalog signer for catalog-signed files).
func verifySignatureDetail(path string) (string, string, string) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "unknown", err.Error(), ""
	}
	fi := wintrustFileInfo{FilePath: p}
	fi.Size = uint32(unsafe.Sizeof(fi))
	data := wintrustData{UIChoice: 2 /*WTD_UI_NONE*/, RevocationChk: 0, UnionChoice: 1 /*WTD_CHOICE_FILE*/, File: &fi, StateAction: 1, /*VERIFY*/
		ProvFlags: 0x1000 /*WTD_CACHE_ONLY_URL_RETRIEVAL*/}
	data.Size = uint32(unsafe.Sizeof(data))
	invalidHwnd := ^uintptr(0)
	r, _, _ := pWinVerifyTrust.Call(invalidHwnd, uintptr(unsafe.Pointer(&wvtGenericVerifyV2)), uintptr(unsafe.Pointer(&data)))
	signer := ""
	if uint32(r) == 0 {
		signer = signerFromState(data.StateData)
	}
	data.StateAction = 2 // WTD_STATEACTION_CLOSE
	pWinVerifyTrust.Call(invalidHwnd, uintptr(unsafe.Pointer(&wvtGenericVerifyV2)), uintptr(unsafe.Pointer(&data)))
	code := fmt.Sprintf("0x%08X", uint32(r))
	switch uint32(r) {
	case 0:
		return "valid", code, signer
	case 0x800B0100:
		// most Windows binaries are catalog-signed: look the file hash up in the catalog database
		if st, cc, sg, found := verifyCatalogSignatureDetail(path); found {
			return st, cc, sg
		}
		return "unsigned (no embedded signature and no catalog entry)", code, ""
	case 0x80096010:
		return "signature present but digest mismatch (modified file)", code, ""
	case 0x800B0101:
		return "certificate expired", code, ""
	case 0x800B0109, 0x800B010A:
		return "signature present, chain not trusted", code, ""
	case 0x80092003, 0x800B0001:
		return "could not verify (file unreadable or trust provider unavailable)", code, ""
	}
	return "invalid or untrusted", code, ""
}

// ---- process snapshot ----

func processSnapshotDetailed(ctx context.Context, w *warnings, withModules, withImages bool) (any, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	enablePrivilege("SeDebugPrivilege") // only raises a privilege the token already holds
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var procs []procRecord
	for err := windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		procs = append(procs, procRecord{PID: pe.ProcessID, ParentPID: pe.ParentProcessID, Name: windows.UTF16ToString(pe.ExeFile[:]), Threads: pe.Threads})
	}
	sockets := socketTables(w)
	byPID := map[uint32][]socketRecord{}
	for _, s := range sockets {
		byPID[s.PID] = append(byPID[s.PID], s)
	}
	cache := &imageEnricher{seen: map[string]*enrichedImage{}}
	denied := 0
	for i := range procs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p := &procs[i]
		p.Sockets = byPID[p.PID]
		p.CollectedUTC = time.Now().UTC().Format(time.RFC3339Nano)
		if p.PID == 0 {
			continue
		}
		var sid uint32
		if err := windows.ProcessIdToSessionId(p.PID, &sid); err == nil {
			p.SessionID = &sid
		}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, p.PID)
		if err != nil {
			p.Inaccessible = append(p.Inaccessible, "OpenProcess: "+err.Error())
			denied++
			if withModules {
				if mods, merr := modulesOf(p.PID); merr == nil {
					p.Modules = mods
				}
			}
			continue
		}
		var buf [32768]uint16
		n := uint32(len(buf))
		if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err == nil {
			p.ImagePath = windows.UTF16ToString(buf[:n])
		}
		var c, e, k, u windows.Filetime
		if err := windows.GetProcessTimes(h, &c, &e, &k, &u); err == nil {
			p.CreatedUTC = filetimeToUTC(c)
		}
		if cl, err := commandLine(h); err == nil {
			p.CommandLine = cl
		} else {
			p.Inaccessible = append(p.Inaccessible, "command line: "+err.Error())
		}
		var hc uint32
		if r, _, _ := pGetProcessHandleCount.Call(uintptr(h), uintptr(unsafe.Pointer(&hc))); r != 0 {
			p.HandleCount = hc
		}
		var mc struct {
			Cb, PageFaults                                                          uint32
			PeakWS, WS, QPeakPaged, QPaged, QPeakNP, QNP, Pagefile, PeakPF, Private uintptr
		}
		mc.Cb = uint32(unsafe.Sizeof(mc))
		if r, _, _ := pGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&mc)), uintptr(mc.Cb)); r != 0 {
			p.WorkingSet, p.PeakWS, p.PrivateBytes, p.PageFaults = uint64(mc.WS), uint64(mc.PeakWS), uint64(mc.Private), mc.PageFaults
		}
		var tok windows.Token
		if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err == nil {
			if tu, err := tok.GetTokenUser(); err == nil {
				p.UserSID = tu.User.Sid.String()
				if !isLocalSID(p.UserSID) {
					if name := profileUserName(p.UserSID); name != "" {
						p.User = name + " (domain account; name taken from the local profile, no domain controller contacted)"
					} else {
						p.User = "(domain SID; name not resolved to avoid contacting a domain controller)"
					}
				} else if acct, dom, _, err := tu.User.Sid.LookupAccount(""); err == nil {
					p.User = dom + `\` + acct
				}
			}
			el := tok.IsElevated()
			p.Elevated = &el
			p.Integrity = integrityName(tok)
			td := readTokenDetails(tok)
			p.TokenType, p.Impersonation, p.ElevationType, p.LogonSession, p.AppContainer = td.Type, td.Impersonation, td.Elevation, td.LogonSession, td.AppContainer
			p.PrivilegesEnabled, p.PrivilegesDisabled = td.Enabled, td.Disabled
			tok.Close()
		} else {
			p.Inaccessible = append(p.Inaccessible, "token: "+err.Error())
		}
		p.Protection = processProtection(h)
		p.Architecture, _ = processArchitecture(h)
		windows.CloseHandle(h)
		if ph, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, p.PID); err == nil {
			if info, perr := readPEB(ph); perr == nil {
				p.CurrentDirectory, p.PEBImagePath, p.WindowTitle = info.CurrentDirectory, info.ImagePath, info.WindowTitle
				if info.ImagePath != "" && p.ImagePath != "" {
					same := samePath(info.ImagePath, p.ImagePath)
					p.PEBImageMatches = &same
				}
			} else {
				p.Inaccessible = append(p.Inaccessible, "PEB: "+perr.Error())
			}
			windows.CloseHandle(ph)
		} else {
			p.Inaccessible = append(p.Inaccessible, "PEB: OpenProcess(read): "+err.Error())
		}
		if withModules {
			if mods, err := modulesOf(p.PID); err == nil {
				p.Modules = mods
			} else {
				p.Inaccessible = append(p.Inaccessible, "modules: "+err.Error())
			}
		}
		if withImages && p.ImagePath != "" {
			p.Image = cache.describe(ctx, p.ImagePath)
		}
	}
	if denied > 0 {
		w.add("%d process(es) could not be opened (protected processes or insufficient privilege); they are listed with limited fields", denied)
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	resolveParents(procs)
	return map[string]any{"processes": procs, "count": len(procs), "elevated": IsElevated(),
		"note": "protected and inaccessible processes are listed with the reason; no protection was bypassed. collected_utc is when each record was read; parent_state tells whether the parent is still running"}, nil
}

// ---- handle table (types and owners only; names are not resolved) ----

func handleTable(ctx context.Context, w *warnings) (any, error) {
	entries, err := readSystemHandles(ctx)
	if err != nil {
		return nil, err
	}
	type perProc struct {
		PID       uint64         `json:"pid"`
		Handles   int            `json:"handle_count"`
		ByType    map[string]int `json:"by_type"`
		ByTypeIdx map[uint16]int `json:"by_type_index"`
	}
	// the type table of this build turns the numeric indexes into names (Process, Thread, File, Key, Mutant, ...)
	types, terr := queryObjectTypes()
	typeName := map[uint16]string{}
	for _, t := range types {
		typeName[t.Index] = t.Name
	}
	if terr != nil {
		w.add("object type table unavailable (%v): handles are counted by type index only", terr)
	}
	agg := map[uint64]*perProc{}
	for _, e := range entries {
		pp := agg[e.PID]
		if pp == nil {
			pp = &perProc{PID: e.PID, ByType: map[string]int{}, ByTypeIdx: map[uint16]int{}}
			agg[e.PID] = pp
		}
		pp.Handles++
		pp.ByTypeIdx[e.Type]++
		if n := typeName[e.Type]; n != "" {
			pp.ByType[n]++
		}
	}
	out := make([]*perProc, 0, len(agg))
	for _, v := range agg {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	w.add("handle object names are not resolved in this table (resolving names can block on pipes and devices); see processes-handles for named handles")
	return map[string]any{"total_handles": len(entries), "object_types": types, "processes": out,
		"note": "handles aggregated per process by object type name; by_type_index keeps the raw build-specific index, mapped by object_types"}, nil
}

func processSources() []collector.Source {
	m := func(name, desc string, p collector.ProfileMask, priv collector.Privilege, art ...string) collector.Meta {
		return baseMeta(name, desc, "processes", priv, p, art...)
	}
	list := withDetect(jsonSource("processes-detailed", m("Processes (detailed)", "PID/PPID and parent validity, image path, command line, current directory and window title from the PEB, creation time, session, token user/elevation/integrity/privileges/logon session, protection level, architecture, memory counters, handle count, loaded modules, image hashes, Authenticode status and signer, company and version, owned sockets",
		collector.InAll, collector.PrivDebug, "execution/evtx-4688-process-created.md"), "toolhelp+ntquery+wintrust", "api://processes", func(ctx context.Context, w *warnings) (any, error) {
		return processSnapshotDetailed(ctx, w, true, true)
	}), available)
	list.Meta.SideEffects = "reads executable files to hash them (updates last-access times on volumes where that is enabled)"
	handles := withDetect(jsonSource("processes-handle-table", m("Handle table (counts per process/type)", "System handle table aggregated per process and object type, with the build's object type table", collector.InFullOnly, collector.PrivDebug),
		"ntquerysysteminformation", "api://handle-table", handleTable), available)
	return []collector.Source{list, handles, procPerfSource(), processHandlesSource(), processMemoryMapSource(), processModuleImagesSource(), processEnvironmentSource()}
}
