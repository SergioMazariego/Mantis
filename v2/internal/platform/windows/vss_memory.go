//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unsafe"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"golang.org/x/sys/windows"
)

// ---- Volume Shadow Copies (read-only) ----

var (
	pNtOpenDirectoryObject  = ntdll.NewProc("NtOpenDirectoryObject")
	pNtQueryDirectoryObject = ntdll.NewProc("NtQueryDirectoryObject")
	pNtClose                = ntdll.NewProc("NtClose")
)

type ntUnicode struct {
	Length, MaximumLength uint16
	Buffer                *uint16
}

type objectAttributes struct {
	Length             uint32
	RootDirectory      windows.Handle
	ObjectName         *ntUnicode
	Attributes         uint32
	SecurityDescriptor uintptr
	SecurityQoS        uintptr
}

// shadowDevices lists the snapshot device names present in the object manager.
// Enumeration is read-only; snapshots are never created or deleted by Mantis.
func shadowDevices(w *warnings) []string {
	name, _ := windows.UTF16FromString(`\Device`)
	us := ntUnicode{Length: uint16((len(name) - 1) * 2), MaximumLength: uint16(len(name) * 2), Buffer: &name[0]}
	oa := objectAttributes{ObjectName: &us, Attributes: 0x40 /*OBJ_CASE_INSENSITIVE*/}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var h windows.Handle
	if r, _, _ := pNtOpenDirectoryObject.Call(uintptr(unsafe.Pointer(&h)), 1 /*DIRECTORY_QUERY*/, uintptr(unsafe.Pointer(&oa))); r != 0 {
		w.add("NtOpenDirectoryObject(\\Device): NTSTATUS 0x%08x; falling back to probing", uint32(r))
		return probeShadowDevices()
	}
	defer pNtClose.Call(uintptr(h))
	var names []string
	var ctx uint32
	buf := make([]byte, 64<<10)
	restart := uintptr(1)
	for {
		var ret uint32
		r, _, _ := pNtQueryDirectoryObject.Call(uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, restart, uintptr(unsafe.Pointer(&ctx)), uintptr(unsafe.Pointer(&ret)))
		restart = 0
		if uint32(r) != 0 && uint32(r) != 0x105 /*STATUS_MORE_ENTRIES*/ {
			break
		}
		// OBJECT_DIRECTORY_INFORMATION: two UNICODE_STRING (Name, TypeName), array terminated by a zero Name
		stride := int(unsafe.Sizeof(ntUnicode{})) * 2
		for off := 0; off+stride <= len(buf); off += stride {
			e := (*[2]ntUnicode)(unsafe.Pointer(&buf[off]))
			if e[0].Buffer == nil || e[0].Length == 0 {
				break
			}
			n := windows.UTF16ToString(unsafe.Slice(e[0].Buffer, int(e[0].Length)/2))
			if strings.HasPrefix(strings.ToLower(n), "harddiskvolumeshadowcopy") {
				names = append(names, n)
			}
		}
		if r == 0 {
			break
		}
	}
	sort.Slice(names, func(i, j int) bool { return shadowIndex(names[i]) < shadowIndex(names[j]) })
	return names
}

func shadowIndex(name string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(strings.ToLower(name), "harddiskvolumeshadowcopy"))
	return n
}

// rawDirExists checks a device path as given: extended() would clean away the trailing backslash that
// distinguishes the volume root from the device object itself.
func rawDirExists(path string) bool {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	a, err := windows.GetFileAttributes(p)
	return err == nil && a&windows.FILE_ATTRIBUTE_DIRECTORY != 0
}

func probeShadowDevices() []string {
	var out []string
	for i := 1; i <= 512; i++ {
		n := fmt.Sprintf("HarddiskVolumeShadowCopy%d", i)
		if rawDirExists(`\\?\GLOBALROOT\Device\` + n + `\`) {
			out = append(out, n)
		}
	}
	return out
}

func shadowRoot(device string) string { return `\\?\GLOBALROOT\Device\` + device }

func shadowInventory(w *warnings) map[string]any {
	devs := shadowDevices(w)
	live := map[string][]string{} // volume serial -> drive letters
	for _, v := range fixedVolumes() {
		p, _ := windows.UTF16PtrFromString(v.Drive + `:\`)
		var serial, maxc, flags uint32
		if err := windows.GetVolumeInformation(p, nil, 0, &serial, &maxc, &flags, nil, 0); err == nil {
			key := fmt.Sprintf("%08X", serial)
			live[key] = append(live[key], v.Drive+":")
		}
	}
	var snaps []map[string]any
	for _, d := range devs {
		rec := map[string]any{"device": d, "path": shadowRoot(d) + `\`, "index": shadowIndex(d)}
		root := shadowRoot(d) + `\`
		p, err := windows.UTF16PtrFromString(root)
		if err == nil {
			var serial, maxc, flags uint32
			var fs [64]uint16
			if err := windows.GetVolumeInformation(p, nil, 0, &serial, &maxc, &flags, &fs[0], uint32(len(fs))); err == nil {
				s := fmt.Sprintf("%08X", serial)
				rec["volume_serial"], rec["filesystem"] = s, windows.UTF16ToString(fs[:])
				rec["origin_volume_candidates"] = live[s]
			} else {
				rec["volume_error"] = err.Error()
			}
			h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
				windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
			if err == nil {
				var c, a, m windows.Filetime
				if err := windows.GetFileTime(h, &c, &a, &m); err == nil {
					rec["root_directory_created_utc"] = filetimeToUTC(c)
					rec["root_timestamp_note"] = "timestamp of the snapshot root directory; not an authoritative VSS creation time (the VSS API/WMI records that)"
				}
				windows.CloseHandle(h)
			} else {
				rec["access_error"] = classifyErr(err).Error()
			}
		}
		snaps = append(snaps, rec)
	}
	if len(snaps) == 0 {
		w.add("no existing shadow copies were found (or they are not visible to this token)")
	}
	return map[string]any{"snapshots": snaps, "count": len(snaps),
		"note": "read-only discovery of existing snapshots. Mantis does not create or delete snapshots; creating one would alter the system and needs an explicit policy"}
}

var vssArtifactFiles = []string{
	`Windows\System32\config\SYSTEM`, `Windows\System32\config\SOFTWARE`, `Windows\System32\config\DEFAULT`, // SAM and SECURITY are credential stores: not read from snapshots by default
	`Windows\appcompat\Programs\Amcache.hve`, `Windows\System32\winevt\Logs\Security.evtx`, `Windows\System32\winevt\Logs\System.evtx`,
	`Windows\System32\winevt\Logs\Application.evtx`, `Windows\System32\sru\SRUDB.dat`, `Windows\System32\wbem\Repository\OBJECTS.DATA`,
}

func vssSources() []collector.Source {
	vm := func(name, desc string, p collector.ProfileMask) collector.Meta {
		return baseMeta(name, desc, "shadow-copies", collector.PrivAdmin, p)
	}
	inv := withDetect(jsonSource("vss-snapshots", vm("Volume Shadow Copy inventory", "Existing snapshots: device, volume serial, origin-volume candidates and root timestamps (read-only)", collector.InStdFull),
		"object-manager-enumeration", `\Device\HarddiskVolumeShadowCopy*`, func(ctx context.Context, w *warnings) (any, error) { return shadowInventory(w), nil }), available)
	inv.Meta.Privilege = collector.PrivAdmin
	art := collector.Source{
		ID: "vss-artifacts", Kind: "windows.file_group", Locator: `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*\{registry hives, Amcache, core EVTX, SRUM, WMI}`,
		Method: "snapshot-file-copy", MaxBytes: defaultFileMax, Meta: vm("Key artifacts from existing shadow copies", "Registry hives, Amcache, core event logs, SRUM and WMI repository as they existed in each snapshot (provenance records the snapshot device)", collector.InFullOnly),
		Detect: func(context.Context) collector.Availability {
			if len(shadowDevices(&warnings{})) == 0 {
				return collector.Availability{State: collector.NotPresent, Reason: "no existing shadow copies"}
			}
			if !IsElevated() {
				return collector.Availability{State: collector.NeedsAdmin, Reason: "reading snapshot devices needs an elevated token"}
			}
			return collector.Availability{State: collector.Available}
		},
		Expand: func(ctx context.Context) ([]collector.Source, error) {
			devs := shadowDevices(&warnings{})
			if len(devs) == 0 {
				return nil, fmt.Errorf("%w: no existing shadow copies", collector.ErrNotPresent)
			}
			var out []collector.Source
			if len(devs) > 6 {
				omitted := append([]string(nil), devs[:len(devs)-6]...)
				devs = devs[len(devs)-6:] // the most recent snapshots
				// the older snapshots are often the ones from before the compromise: their omission is a declared gap
				msg := fmt.Sprintf("%d older shadow copies were not read (only the 6 most recent are): %s", len(omitted), strings.Join(omitted, ", "))
				out = append(out, collector.Source{ID: "vss-artifacts-older-snapshots-gap", Kind: "windows.collection_gap", Locator: `\Device\HarddiskVolumeShadowCopy*`,
					Method: "snapshot-file-copy", MaxBytes: 1, Meta: collector.Meta{Name: "Older shadow copies (not read)", Category: "shadow-copies", DestPath: "shadow-copies/gaps/older-snapshots.txt"},
					Open: func(context.Context) (io.ReadCloser, error) { return nil, errors.New(msg) }})
			}
			for _, d := range devs {
				for _, rel := range vssArtifactFiles {
					path := shadowRoot(d) + `\` + rel
					cm := collector.Meta{Name: d + `\` + rel, Category: "shadow-copies", DestPath: "shadow-copies/" + d + "/" + strings.ReplaceAll(rel, `\`, "/"),
						SourcePath: path}
					s := fileSource("vss-"+short(path), cm, path, defaultFileMax)
					s.Meta.DestPath = cm.DestPath
					s.Meta.SourcePath = path
					out = append(out, s)
				}
			}
			return out, nil
		},
	}
	return []collector.Source{inv, art}
}

// ---- memory (user-mode only) ----

var (
	pVirtualQueryEx     = kernel32.NewProc("VirtualQueryEx")
	pGetMappedFileNameW = psapi.NewProc("GetMappedFileNameW")
)

type memoryBasicInfo struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionID       uint16
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

func memoryRegions(ctx context.Context, w *warnings) (any, error) {
	if unsafe.Sizeof(uintptr(0)) == 4 {
		return nil, fmt.Errorf("%w: the memory map needs a 64-bit build (MEMORY_BASIC_INFORMATION differs on 32-bit)", collector.ErrNotSupported)
	}
	enablePrivilege("SeDebugPrivilege")
	procs := processNames()
	type regionRec struct {
		Base    string `json:"base"`
		Size    uint64 `json:"size"`
		State   string `json:"state"`
		Protect string `json:"protect"`
		Type    string `json:"type"`
		Mapped  string `json:"mapped_file,omitempty"`
	}
	type procRegions struct {
		PID     uint32      `json:"pid"`
		Name    string      `json:"name"`
		Regions []regionRec `json:"regions,omitempty"`
		Total   uint64      `json:"committed_bytes"`
		Error   string      `json:"error,omitempty"`
		Capped  bool        `json:"regions_capped,omitempty"`
	}
	protect := func(p uint32) string {
		m := map[uint32]string{0x01: "NOACCESS", 0x02: "R", 0x04: "RW", 0x08: "WCOPY", 0x10: "X", 0x20: "RX", 0x40: "RWX", 0x80: "WCOPY+X"}
		s := m[p&0xff]
		if p&0x100 != 0 {
			s += "|GUARD"
		}
		return s
	}
	var out []procRegions
	pids := make([]uint32, 0, len(procs))
	for pid := range procs {
		pids = append(pids, pid)
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if pid == 0 || pid == 4 {
			continue
		}
		pr := procRegions{PID: pid, Name: procs[pid]}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
		if err != nil {
			pr.Error = "OpenProcess: " + err.Error()
			out = append(out, pr)
			continue
		}
		var addr uintptr
		for len(pr.Regions) < 20000 {
			var mbi memoryBasicInfo
			r, _, _ := pVirtualQueryEx.Call(uintptr(h), addr, uintptr(unsafe.Pointer(&mbi)), unsafe.Sizeof(mbi))
			if r == 0 {
				break
			}
			if mbi.State == 0x1000 { // MEM_COMMIT
				pr.Total += uint64(mbi.RegionSize)
				rec := regionRec{Base: fmt.Sprintf("0x%x", mbi.BaseAddress), Size: uint64(mbi.RegionSize), State: "COMMIT", Protect: protect(mbi.Protect),
					Type: map[uint32]string{0x20000: "PRIVATE", 0x40000: "MAPPED", 0x1000000: "IMAGE"}[mbi.Type]}
				if mbi.Type == 0x1000000 || mbi.Type == 0x40000 {
					var nb [520]uint16
					if n, _, _ := pGetMappedFileNameW.Call(uintptr(h), mbi.BaseAddress, uintptr(unsafe.Pointer(&nb[0])), uintptr(len(nb))); n > 0 {
						rec.Mapped = windows.UTF16ToString(nb[:n])
					}
				}
				pr.Regions = append(pr.Regions, rec)
			}
			next := mbi.BaseAddress + mbi.RegionSize
			if next <= addr {
				break
			}
			addr = next
		}
		if len(pr.Regions) >= 20000 {
			pr.Capped = true
		}
		windows.CloseHandle(h)
		out = append(out, pr)
	}
	w.add("only metadata is recorded: no process memory contents are read by this source")
	return map[string]any{"processes": out}, nil
}

func memorySources() []collector.Source {
	mm := func(name, desc string, p collector.ProfileMask, priv collector.Privilege) collector.Meta {
		return baseMeta(name, desc, "memory", priv, p)
	}
	meta := withDetect(jsonSource("memory-process-regions", mm("Process virtual memory map", "Committed virtual memory regions per process (base, size, protection, type, mapped image); metadata only", collector.InFullOnly, collector.PrivDebug),
		"virtualqueryex", "api://process-memory-map", memoryRegions), available)

	dump := memoryDumpSource()

	phys := collector.Source{
		ID: "memory-physical-ram", Kind: "windows.memory_physical", Locator: `\\.\PhysicalMemory`, Method: "unsupported", MaxBytes: 1,
		Meta: mm("Physical memory (RAM) acquisition", "Not supported: a complete, safe acquisition needs a signed kernel driver, which Mantis does not ship or download. Reported as a limitation, never as success", collector.InFullOnly, collector.PrivAdmin),
		Detect: func(context.Context) collector.Availability {
			return collector.Availability{State: collector.NotSupported, Reason: "requires a kernel driver; out of scope"}
		},
		Open: func(context.Context) (io.ReadCloser, error) {
			return nil, fmt.Errorf("%w: physical memory acquisition requires a signed kernel driver (not shipped); use an approved external RAM acquisition tool", collector.ErrNotSupported)
		},
	}
	return []collector.Source{meta, dump, phys}
}
