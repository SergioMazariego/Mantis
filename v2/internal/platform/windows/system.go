//go:build windows

package windows

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
)

var (
	netapi32          = windows.NewLazySystemDLL("netapi32.dll")
	pNetUserModalsGet = netapi32.NewProc("NetUserModalsGet")
	pNetGetJoinInfo   = netapi32.NewProc("NetGetJoinInformation")
	pNetBufferFree    = netapi32.NewProc("NetApiBufferFree")
	pGetDynamicTZ     = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetDynamicTimeZoneInformation")
	pGetTickCount64   = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64")
)

// HostInfo describes the endpoint for the evidence package manifest.
func HostInfo() map[string]string {
	info := map[string]string{"arch": runtime.GOARCH, "os": "windows"}
	if h, err := os.Hostname(); err == nil {
		info["hostname"] = h
	}
	if v := windows.RtlGetVersion(); v != nil {
		info["windows_version"] = fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
		info["windows_build"] = fmt.Sprint(v.BuildNumber)
		if v.BuildNumber >= 22000 {
			info["windows_family"] = "Windows 11 or newer"
		} else {
			info["windows_family"] = "Windows 10 or older"
		}
		if v.ProductType != 1 {
			info["windows_product"] = "server or domain controller"
		}
	}
	var proc, native uint16
	if err := windows.IsWow64Process2(windows.CurrentProcess(), &proc, &native); err == nil {
		info["native_machine"] = machineName(native)
		if proc != 0 {
			info["emulated_process"] = "true"
		}
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		for _, n := range []string{"ProductName", "DisplayVersion", "EditionID"} {
			if s, _, err := k.GetStringValue(n); err == nil {
				info[strings.ToLower(n)] = s
			}
		}
		k.Close()
	}
	var tz struct {
		Bias         int32
		StandardName [32]uint16
		StandardDate [8]uint16
		StandardBias int32
		DaylightName [32]uint16
		DaylightDate [8]uint16
		DaylightBias int32
		KeyName      [128]uint16
		Disabled     uint8
	}
	if r, _, _ := pGetDynamicTZ.Call(uintptr(unsafe.Pointer(&tz))); r != 0xffffffff {
		info["timezone"] = windows.UTF16ToString(tz.KeyName[:])
		bias := tz.Bias
		switch r { // 1 = standard time, 2 = daylight time (the active bias includes the matching adjustment)
		case 1:
			bias += tz.StandardBias
		case 2:
			bias += tz.DaylightBias
		}
		info["utc_offset_minutes"] = fmt.Sprint(-bias)
		info["utc_offset_note"] = "offset in effect at collection time (daylight saving included)"
	}
	return info
}

func machineName(m uint16) string {
	switch m {
	case 0x8664:
		return "amd64"
	case 0xAA64:
		return "arm64"
	case 0x14c:
		return "x86"
	case 0x1c4:
		return "arm"
	}
	return fmt.Sprintf("0x%x", m)
}

func systemSources() []collector.Source {
	m := func(name, desc string, p collector.ProfileMask, art ...string) collector.Meta {
		return baseMeta(name, desc, "system", collector.PrivUser, p, art...)
	}
	return []collector.Source{
		withDetect(jsonSource("system-os", m("Operating system inventory", "Windows version/build, architecture, identity, boot time, time zone, installation metadata, machine environment", collector.InAll,
			"enumeration/computer-name.md", "enumeration/current-version.md", "enumeration/time-zone-information.md", "enumeration/select.md"),
			"windows-api/os-inventory", "api://os-inventory", func(ctx context.Context, w *warnings) (any, error) { return osInventory(w), nil }), available),
		withDetect(jsonSource("system-disks", m("Physical disks, partitions and volumes", "Physical disks (not just logical volumes), partition tables, logical volumes, mount points and the volume-to-disk mapping", collector.InAll),
			"windows-api/disk-inventory", "api://disks", func(ctx context.Context, w *warnings) (any, error) { return diskInventory(w), nil }), available),
		withDetect(jsonSource("system-software", m("Installed software", "Installed software from Uninstall keys (64-bit, 32-bit and loaded user hives)", collector.InStdFull),
			"windows-api/installed-software", "registry://Uninstall", func(ctx context.Context, w *warnings) (any, error) { return installedSoftware(w), nil }), available),
		withDetect(jsonSource("system-services", m("Services and drivers (live)", "Service Control Manager inventory of services and kernel/file-system drivers: state, start type, image path, account", collector.InAll,
			"persistence/registry-services.md"),
			"scm-enumeration", "api://scm", func(ctx context.Context, w *warnings) (any, error) { return serviceInventory(w) }), available),
		withDetect(jsonSource("system-loaded-drivers", m("Loaded kernel drivers", "Drivers currently loaded in the kernel (image base and path)", collector.InStdFull),
			"psapi-enumdevicedrivers", "api://loaded-drivers", func(ctx context.Context, w *warnings) (any, error) { return loadedDrivers(w), nil }), available),
	}
}

func osInventory(w *warnings) map[string]any {
	out := map[string]any{"host": HostInfo()}
	if v := windows.RtlGetVersion(); v != nil {
		out["rtl_version"] = map[string]any{"major": v.MajorVersion, "minor": v.MinorVersion, "build": v.BuildNumber, "platform_id": v.PlatformId,
			"service_pack": windows.UTF16ToString(v.CsdVersion[:]), "product_type": v.ProductType, "suite_mask": v.SuiteMask}
	}
	now := time.Now().UTC()
	out["collected_utc"] = now.Format(time.RFC3339Nano)
	if r, _, _ := pGetTickCount64.Call(); r != 0 {
		up := time.Duration(r) * time.Millisecond
		out["uptime_seconds"] = int64(up.Seconds())
		out["last_boot_utc"] = now.Add(-up).Format(time.RFC3339)
		out["last_boot_note"] = "derived from GetTickCount64; sleep/hibernate time is included in the tick count"
	}
	// names
	names := map[string]string{}
	for label, f := range map[string]uint32{"netbios": windows.ComputerNameNetBIOS, "dns_hostname": windows.ComputerNameDnsHostname,
		"dns_domain": windows.ComputerNameDnsDomain, "dns_fully_qualified": windows.ComputerNameDnsFullyQualified} {
		var n uint32 = 256
		buf := make([]uint16, n)
		if err := windows.GetComputerNameEx(f, &buf[0], &n); err == nil {
			names[label] = windows.UTF16ToString(buf[:n])
		}
	}
	out["names"] = names
	out["domain_join"] = joinInfo(w)
	out["computer_sid"] = computerSID(w)
	// installation + version registry values (raw, typed)
	var dumps []regKeyDump
	for _, t := range []regTarget{
		hklm(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, false, 0),
		hklm(`SYSTEM\CurrentControlSet\Control\TimeZoneInformation`, false, 0),
		hklm(`SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName`, false, 0),
		hklm(`SYSTEM\Setup`, false, 0),
		hklm(`SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, false, 0),
		hklm(`SOFTWARE\Microsoft\Windows\CurrentVersion\Setup`, false, 0),
		hklm(`SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo`, true, 2),
		hklm(`SYSTEM\CurrentControlSet\Control\Windows`, false, 0),
		hklm(`SYSTEM\CurrentControlSet\Control\FileSystem`, false, 0),
		hklm(`SYSTEM\Select`, false, 0),
	} {
		if !dumpTarget(t, w, &dumps) {
			w.add("not present: %s", t.display())
		}
	}
	out["registry"] = dumps
	// machine environment variables are in the registry dump above; the process
	// environment is deliberately not recorded (it may contain operator secrets).
	return out
}

func joinInfo(w *warnings) map[string]any {
	var name *uint16
	var typ uint32
	r, _, _ := pNetGetJoinInfo.Call(0, uintptr(unsafe.Pointer(&name)), uintptr(unsafe.Pointer(&typ)))
	if r != 0 {
		w.add("NetGetJoinInformation failed: %v", syscall.Errno(r))
		return nil
	}
	defer pNetBufferFree.Call(uintptr(unsafe.Pointer(name)))
	status := map[uint32]string{0: "unknown", 1: "unjoined", 2: "workgroup", 3: "domain"}[typ]
	return map[string]any{"name": windows.UTF16PtrToString(name), "status": status}
}

// computerSID returns the local machine SID (the domain id of the local SAM).
func computerSID(w *warnings) string {
	var buf uintptr
	if r, _, _ := pNetUserModalsGet.Call(0, 2, uintptr(unsafe.Pointer(&buf))); r != 0 {
		w.add("NetUserModalsGet failed: %v", syscall.Errno(r))
		return ""
	}
	defer pNetBufferFree.Call(buf)
	// USER_MODALS_INFO_2 { LPWSTR domain_name; PSID domain_id; }
	words := (*[2]uintptr)(*(*unsafe.Pointer)(unsafe.Pointer(&buf)))
	sid := (*windows.SID)(*(*unsafe.Pointer)(unsafe.Pointer(&words[1])))
	return sid.String()
}

// ---- disks ----

const (
	ioctlStorageQueryProperty = 0x002D1400
	ioctlDiskGeometryEx       = 0x000700A0
	ioctlDiskLayoutEx         = 0x00070050
	ioctlVolumeDiskExtents    = 0x00560000
	ioctlDiskGetAttributes    = 0x000740F0 // IOCTL_DISK_GET_DISK_ATTRIBUTES
)

type physicalDisk struct {
	Index          int             `json:"index"`
	Path           string          `json:"path"`
	Vendor         string          `json:"vendor,omitempty"`
	Product        string          `json:"product,omitempty"`
	Revision       string          `json:"revision,omitempty"`
	Serial         string          `json:"serial,omitempty"`
	BusType        string          `json:"bus_type,omitempty"`
	Removable      bool            `json:"removable_media,omitempty"`
	BytesPerSector uint32          `json:"bytes_per_sector,omitempty"`
	SizeBytes      int64           `json:"size_bytes,omitempty"`
	PartitionStyle string          `json:"partition_style,omitempty"`
	Offline        *bool           `json:"offline,omitempty"`   // disk attribute: taken offline (diskpart "Offline")
	ReadOnly       *bool           `json:"read_only,omitempty"` // disk attribute: read-only
	Dynamic        *bool           `json:"dynamic,omitempty"`   // Logical Disk Manager (dynamic disk) partitions present
	DiskSignature  string          `json:"disk_signature_or_guid,omitempty"`
	Partitions     []partitionInfo `json:"partitions,omitempty"`
	LayoutRawB64   string          `json:"layout_raw_base64,omitempty"`
	Errors         []string        `json:"errors,omitempty"`
}

type partitionInfo struct {
	Number     uint32 `json:"number"`
	Offset     int64  `json:"offset_bytes"`
	Length     int64  `json:"length_bytes"`
	Style      string `json:"style"`
	TypeGUID   string `json:"gpt_type_guid,omitempty"`
	PartID     string `json:"gpt_partition_id,omitempty"`
	Name       string `json:"gpt_name,omitempty"`
	Attributes uint64 `json:"gpt_attributes,omitempty"`
	MBRType    uint8  `json:"mbr_type,omitempty"`
	Boot       bool   `json:"mbr_boot,omitempty"`
	HiddenSect uint32 `json:"mbr_hidden_sectors,omitempty"`
}

var busTypes = map[uint32]string{0: "Unknown", 1: "SCSI", 2: "ATAPI", 3: "ATA", 4: "1394", 5: "SSA", 6: "Fibre", 7: "USB", 8: "RAID", 9: "iSCSI", 10: "SAS", 11: "SATA", 12: "SD", 13: "MMC", 14: "Virtual", 15: "FileBackedVirtual", 16: "Spaces", 17: "NVMe", 18: "SCM", 19: "UFS"}

func guidString(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	g := windows.GUID{Data1: binary.LittleEndian.Uint32(b[0:4]), Data2: binary.LittleEndian.Uint16(b[4:6]), Data3: binary.LittleEndian.Uint16(b[6:8])}
	copy(g.Data4[:], b[8:16])
	return g.String()
}

func deviceIoctl(h windows.Handle, code uint32, in []byte, outSize int) ([]byte, error) {
	out := make([]byte, outSize)
	var ret uint32
	var inPtr *byte
	if len(in) > 0 {
		inPtr = &in[0]
	}
	if err := windows.DeviceIoControl(h, code, inPtr, uint32(len(in)), &out[0], uint32(len(out)), &ret, nil); err != nil {
		return nil, err
	}
	return out[:ret], nil
}

func asciiAt(buf []byte, off uint32) string {
	if off == 0 || int(off) >= len(buf) {
		return ""
	}
	end := int(off)
	for end < len(buf) && buf[end] != 0 {
		end++
	}
	return strings.TrimSpace(string(buf[off:end]))
}

func openNoAccess(path string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	// dwDesiredAccess=0 queries device metadata without needing administrator rights
	return windows.CreateFile(p, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
}

func diskInventory(w *warnings) map[string]any {
	var disks []physicalDisk
	for i := 0; i < 64; i++ {
		path := fmt.Sprintf(`\\.\PhysicalDrive%d`, i)
		h, err := openNoAccess(path)
		if err != nil {
			continue
		}
		d := physicalDisk{Index: i, Path: path}
		// storage descriptor
		q := make([]byte, 12) // STORAGE_PROPERTY_QUERY: PropertyId(4) QueryType(4) AdditionalParameters(1+pad)
		if out, err := deviceIoctl(h, ioctlStorageQueryProperty, q, 4096); err == nil && len(out) >= 36 {
			d.Removable = out[10] != 0
			d.Vendor = asciiAt(out, binary.LittleEndian.Uint32(out[12:]))
			d.Product = asciiAt(out, binary.LittleEndian.Uint32(out[16:]))
			d.Revision = asciiAt(out, binary.LittleEndian.Uint32(out[20:]))
			d.Serial = asciiAt(out, binary.LittleEndian.Uint32(out[24:]))
			d.BusType = busTypes[binary.LittleEndian.Uint32(out[28:])]
		} else if err != nil {
			d.Errors = append(d.Errors, "storage descriptor: "+err.Error())
		}
		if out, err := deviceIoctl(h, ioctlDiskGeometryEx, nil, 256); err == nil && len(out) >= 32 {
			d.BytesPerSector = binary.LittleEndian.Uint32(out[20:])
			d.SizeBytes = int64(binary.LittleEndian.Uint64(out[24:]))
		} else if err != nil {
			d.Errors = append(d.Errors, "geometry: "+err.Error())
		}
		if out, err := deviceIoctl(h, ioctlDiskLayoutEx, nil, 48+144*128); err == nil && len(out) >= 48 {
			d.LayoutRawB64 = base64.StdEncoding.EncodeToString(out)
			style := binary.LittleEndian.Uint32(out[0:])
			count := int(binary.LittleEndian.Uint32(out[4:]))
			d.PartitionStyle = map[uint32]string{0: "MBR", 1: "GPT", 2: "RAW"}[style]
			switch style {
			case 0:
				d.DiskSignature = fmt.Sprintf("0x%08x", binary.LittleEndian.Uint32(out[8:]))
			case 1:
				d.DiskSignature = guidString(out[8:24])
			}
			for p := 0; p < count && 48+144*(p+1) <= len(out); p++ {
				e := out[48+144*p:]
				pi := partitionInfo{Number: binary.LittleEndian.Uint32(e[24:]), Offset: int64(binary.LittleEndian.Uint64(e[8:])), Length: int64(binary.LittleEndian.Uint64(e[16:]))}
				if binary.LittleEndian.Uint32(e[0:]) == 1 {
					pi.Style = "GPT"
					pi.TypeGUID, pi.PartID = guidString(e[32:48]), guidString(e[48:64])
					pi.Attributes = binary.LittleEndian.Uint64(e[64:])
					nm := make([]uint16, 36)
					for i := range nm {
						nm[i] = binary.LittleEndian.Uint16(e[72+2*i:])
					}
					pi.Name = windows.UTF16ToString(nm)
				} else {
					pi.Style = "MBR"
					pi.MBRType, pi.Boot, pi.HiddenSect = e[32], e[33] != 0, binary.LittleEndian.Uint32(e[36:])
				}
				d.Partitions = append(d.Partitions, pi)
			}
		} else if err != nil {
			d.Errors = append(d.Errors, "layout: "+err.Error())
		}
		// GET_DISK_ATTRIBUTES: Version, Reserved, Attributes (bit 0 offline, bit 1 read-only)
		if out, err := deviceIoctl(h, ioctlDiskGetAttributes, nil, 16); err == nil && len(out) >= 16 {
			attr := binary.LittleEndian.Uint64(out[8:])
			off, ro := attr&1 != 0, attr&2 != 0
			d.Offline, d.ReadOnly = &off, &ro
		}
		dyn := false
		for _, pi := range d.Partitions {
			// LDM metadata/data partitions (GPT) or MBR type 0x42 mark a dynamic disk
			if pi.MBRType == 0x42 || strings.EqualFold(pi.TypeGUID, "{5808C8AA-7E8F-42E0-85D2-E1E90434CFB3}") || strings.EqualFold(pi.TypeGUID, "{AF9B60A0-1431-4F62-BC68-3311714A69AD}") {
				dyn = true
			}
		}
		if len(d.Partitions) > 0 {
			d.Dynamic = &dyn
		}
		windows.CloseHandle(h)
		disks = append(disks, d)
	}
	if len(disks) == 0 {
		w.add("no physical drives could be opened")
	}

	// logical volumes
	var vols []map[string]any
	buf := make([]uint16, 260)
	fh, err := windows.FindFirstVolume(&buf[0], uint32(len(buf)))
	if err != nil {
		w.add("FindFirstVolume: %v", err)
	} else {
		defer windows.FindVolumeClose(fh)
		for {
			vols = append(vols, volumeRecord(windows.UTF16ToString(buf), w))
			if err := windows.FindNextVolume(fh, &buf[0], uint32(len(buf))); err != nil {
				break
			}
		}
	}
	return map[string]any{"physical_disks": disks, "volumes": vols,
		"note": "physical disks are enumerated through \\\\.\\PhysicalDriveN descriptors; logical volumes are linked to disks through volume disk extents"}
}

func volumeRecord(guidPath string, w *warnings) map[string]any {
	rec := map[string]any{"volume_guid_path": guidPath}
	p, _ := windows.UTF16PtrFromString(guidPath)
	var paths []string
	var need uint32
	pb := make([]uint16, 512)
	if err := windows.GetVolumePathNamesForVolumeName(p, &pb[0], uint32(len(pb)), &need); err == nil {
		// multi-string buffer: NUL-separated paths, double-NUL terminated (UTF-16 preserved)
		start := 0
		for j, c := range pb {
			if c != 0 {
				continue
			}
			if j > start {
				paths = append(paths, windows.UTF16ToString(pb[start:j]))
			}
			start = j + 1
			if j+1 < len(pb) && pb[j+1] == 0 {
				break
			}
		}
	}
	rec["mount_points"] = paths
	rec["drive_type"] = map[uint32]string{0: "unknown", 1: "no_root", 2: "removable", 3: "fixed", 4: "remote", 5: "cdrom", 6: "ramdisk"}[windows.GetDriveType(p)]
	var name, fs [261]uint16
	var serial, maxComp, flags uint32
	if err := windows.GetVolumeInformation(p, &name[0], 261, &serial, &maxComp, &flags, &fs[0], 261); err == nil {
		rec["label"], rec["filesystem"] = windows.UTF16ToString(name[:]), windows.UTF16ToString(fs[:])
		rec["serial"] = fmt.Sprintf("%08X", serial)
		rec["flags"] = flags
	} else {
		rec["info_error"] = err.Error()
	}
	var avail, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &total, &free); err == nil {
		rec["total_bytes"], rec["free_bytes"] = total, free
	}
	// volume -> disk extents
	h, err := openNoAccess(strings.TrimRight(guidPath, `\`))
	if err == nil {
		defer windows.CloseHandle(h)
		if out, err := deviceIoctl(h, ioctlVolumeDiskExtents, nil, 8+24*64); err == nil && len(out) >= 8 {
			n := int(binary.LittleEndian.Uint32(out))
			var ext []map[string]any
			for i := 0; i < n && 8+24*(i+1) <= len(out); i++ {
				e := out[8+24*i:]
				ext = append(ext, map[string]any{"disk_number": binary.LittleEndian.Uint32(e), "offset_bytes": int64(binary.LittleEndian.Uint64(e[8:])), "length_bytes": int64(binary.LittleEndian.Uint64(e[16:]))})
			}
			rec["disk_extents"] = ext
		}
	}
	return rec
}

// ---- software ----

func installedSoftware(w *warnings) map[string]any {
	type entry struct {
		Source string            `json:"source"`
		Key    string            `json:"key"`
		Values map[string]string `json:"values"`
		Write  string            `json:"last_write_utc,omitempty"`
	}
	var out []entry
	want := []string{"DisplayName", "DisplayVersion", "Publisher", "InstallDate", "InstallLocation", "InstallSource", "UninstallString", "EstimatedSize", "WindowsInstaller", "SystemComponent"}
	collect := func(label string, root registry.Key, path string, view uint32) {
		k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE|view)
		if err != nil {
			return
		}
		defer k.Close()
		names, _ := k.ReadSubKeyNames(-1)
		for _, n := range names {
			sk, err := registry.OpenKey(k, n, registry.QUERY_VALUE|view)
			if err != nil {
				continue
			}
			e := entry{Source: label, Key: path + `\` + n, Values: map[string]string{}}
			if info, err := sk.Stat(); err == nil {
				e.Write = info.ModTime().UTC().Format(time.RFC3339)
			}
			for _, vn := range want {
				if v, err := readValue(sk, vn); err == nil {
					if v.Text != "" {
						e.Values[vn] = v.Text
					} else if v.Number != nil {
						e.Values[vn] = fmt.Sprint(*v.Number)
					}
				}
			}
			sk.Close()
			out = append(out, e)
		}
	}
	const u = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	collect("HKLM-64", registry.LOCAL_MACHINE, u, registry.WOW64_64KEY)
	collect("HKLM-32", registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, registry.WOW64_64KEY)
	for sid := range loadedUserSIDs() {
		collect("HKU-"+sid, registry.USERS, sid+`\`+u, registry.WOW64_64KEY)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return map[string]any{"entries": out, "count": len(out)}
}

// ---- services and drivers ----

func serviceInventory(w *warnings) (any, error) {
	// least privilege: connect and enumerate only (mgr.Connect would request all access)
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, err
	}
	defer windows.CloseServiceHandle(scm)
	var bytesNeeded, returned, resume uint32
	buf := make([]byte, 64<<10)
	const infoLevel = 0 // SC_ENUM_PROCESS_INFO
	const types = windows.SERVICE_WIN32 | windows.SERVICE_DRIVER
	type svcEntry struct {
		name, display string
		typ, state    uint32
		pid           uint32
	}
	var entries []svcEntry
	for {
		err := windows.EnumServicesStatusEx(scm, infoLevel, types, windows.SERVICE_STATE_ALL, &buf[0], uint32(len(buf)), &bytesNeeded, &returned, &resume, nil)
		if err != nil && err != windows.ERROR_MORE_DATA {
			return nil, err
		}
		if returned > 0 {
			arr := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), returned)
			for _, e := range arr { // copy now: the strings live in buf, which the next call overwrites
				entries = append(entries, svcEntry{windows.UTF16PtrToString(e.ServiceName), windows.UTF16PtrToString(e.DisplayName),
					e.ServiceStatusProcess.ServiceType, e.ServiceStatusProcess.CurrentState, e.ServiceStatusProcess.ProcessId})
			}
		}
		if err == nil {
			break
		}
		if int(bytesNeeded) > len(buf) {
			buf = make([]byte, bytesNeeded)
		}
	}
	type svc struct {
		Name        string `json:"name"`
		DisplayName string `json:"display_name"`
		Type        uint32 `json:"service_type"`
		State       uint32 `json:"current_state"`
		PID         uint32 `json:"process_id,omitempty"`
		StartType   uint32 `json:"start_type"`
		BinaryPath  string `json:"binary_path,omitempty"`
		Account     string `json:"service_start_name,omitempty"`
		Description string `json:"description,omitempty"`
		Error       string `json:"error,omitempty"`
	}
	out := make([]svc, 0, len(entries))
	for _, e := range entries {
		s := svc{Name: e.name, DisplayName: e.display, Type: e.typ, State: e.state, PID: e.pid}
		namePtr, _ := windows.UTF16PtrFromString(s.Name)
		if h, err := windows.OpenService(scm, namePtr, windows.SERVICE_QUERY_CONFIG); err == nil {
			sv := &mgr.Service{Name: s.Name, Handle: h}
			if cfg, err := sv.Config(); err == nil {
				s.StartType, s.BinaryPath, s.Account = cfg.StartType, cfg.BinaryPathName, cfg.ServiceStartName
				s.Description = cfg.Description
			} else {
				s.Error = err.Error()
			}
			windows.CloseServiceHandle(h)
		} else {
			s.Error = err.Error()
			w.add("open service %s: %v", s.Name, err)
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	var dumps []regKeyDump
	dumpTarget(hklm(`SYSTEM\CurrentControlSet\Services`, true, 2), w, &dumps) // complete registry configuration, incl. Parameters\ServiceDll
	return map[string]any{"services": out, "count": len(out), "registry_services_key": dumps}, nil
}

// ---- loaded drivers ----

var (
	psapi                = windows.NewLazySystemDLL("psapi.dll")
	pEnumDeviceDrivers   = psapi.NewProc("EnumDeviceDrivers")
	pGetDeviceDriverFile = psapi.NewProc("GetDeviceDriverFileNameW")
)

func loadedDrivers(w *warnings) map[string]any {
	var needed uint32
	pEnumDeviceDrivers.Call(0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 {
		w.add("EnumDeviceDrivers returned no data")
		return map[string]any{"drivers": []any{}}
	}
	bases := make([]uintptr, needed/uint32(unsafe.Sizeof(uintptr(0)))+16)
	if r, _, err := pEnumDeviceDrivers.Call(uintptr(unsafe.Pointer(&bases[0])), uintptr(len(bases))*unsafe.Sizeof(uintptr(0)), uintptr(unsafe.Pointer(&needed))); r == 0 {
		w.add("EnumDeviceDrivers: %v", err)
		return map[string]any{"drivers": []any{}}
	}
	n := int(needed) / int(unsafe.Sizeof(uintptr(0)))
	if n > len(bases) {
		n = len(bases)
	}
	var out []map[string]any
	for _, b := range bases[:n] {
		name := make([]uint16, 520)
		l, _, _ := pGetDeviceDriverFile.Call(b, uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)))
		out = append(out, map[string]any{"image_base": fmt.Sprintf("0x%x", b), "path": windows.UTF16ToString(name[:l])})
	}
	return map[string]any{"drivers": out, "count": len(out), "note": "image bases are kernel addresses at collection time"}
}
