//go:build windows

package windows

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const defaultSourceBytes int64 = 512 << 20

// evtExportLogChannelPath is EVT_EXPORT_LOG_FLAGS::EvtExportLogChannelPath: the
// path argument names a live channel (flag 0 is rejected as an invalid parameter).
const evtExportLogChannelPath = 0x1

func legacySources() []collector.Source {
	logs := []string{"Application", "Security", "System", "Windows PowerShell", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-WMI-Activity/Operational", "Microsoft-Windows-Sysmon/Operational"}
	sources := make([]collector.Source, 0, len(logs)+40)
	sources = append(sources,
		collector.Source{ID: "process-snapshot", Kind: "windows.process_snapshot", Locator: "native://Toolhelp32Snapshot", Method: "Toolhelp32Snapshot/v1", MaxBytes: 16 << 20,
			Open: func(ctx context.Context) (io.ReadCloser, error) {
				data, err := processSnapshot(ctx)
				if err != nil {
					return nil, err
				}
				return io.NopCloser(bytes.NewReader(data)), nil
			}},
		collector.Source{ID: "tcp-connections", Kind: "windows.tcp_connections", Locator: "native://GetExtendedTcpTable", Method: "GetExtendedTcpTable/v1", MaxBytes: 16 << 20,
			Open: func(ctx context.Context) (io.ReadCloser, error) {
				data, err := tcpSnapshot(ctx)
				if err != nil {
					return nil, err
				}
				return io.NopCloser(bytes.NewReader(data)), nil
			}},
		collector.Source{ID: "autorun-registry", Kind: "windows.autorun_registry", Locator: "registry://Run-and-RunOnce", Method: "registry-query/v1", MaxBytes: 8 << 20,
			Open: func(ctx context.Context) (io.ReadCloser, error) {
				data, err := autorunSnapshot(ctx)
				if err != nil {
					return nil, err
				}
				return io.NopCloser(bytes.NewReader(data)), nil
			}},
		collector.Source{ID: "disk-inventory", Kind: "windows.disk_inventory", Locator: "native://logical-volumes", Method: "GetLogicalDrives/v1", MaxBytes: 1 << 20,
			Open: func(ctx context.Context) (io.ReadCloser, error) {
				data, err := diskSnapshot(ctx)
				if err != nil {
					return nil, err
				}
				return io.NopCloser(bytes.NewReader(data)), nil
			}},
		collector.Source{ID: "userassist", Kind: "windows.userassist_registry", Locator: "registry://HKCU/Explorer/UserAssist", Method: "registry-query/v1", MaxBytes: 16 << 20,
			Open: func(ctx context.Context) (io.ReadCloser, error) {
				data, err := userAssistSnapshot(ctx)
				if err != nil {
					return nil, err
				}
				return io.NopCloser(bytes.NewReader(data)), nil
			}},
	)
	for _, name := range logs {
		logName := name
		sources = append(sources, collector.Source{ID: "evtx-" + safeID(name), Kind: "windows.evtx", Locator: "eventlog://" + name, Method: "EvtExportLog/v1", MaxBytes: defaultSourceBytes,
			Open: func(ctx context.Context) (io.ReadCloser, error) { return exportLog(ctx, logName) }})
	}
	if home, err := os.UserHomeDir(); err == nil {
		path := filepath.Join(home, "AppData", "Roaming", "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt")
		sources = append(sources, collector.Source{ID: "powershell-history", Kind: "windows.powershell_history", Locator: "user-profile/PowerShell/PSReadLine/ConsoleHost_history.txt", Method: "bounded-file-copy/v1", MaxBytes: 64 << 20,
			Open: func(ctx context.Context) (io.ReadCloser, error) { return openRegular(ctx, path) }})
	}
	if root, err := windows.GetWindowsDirectory(); err == nil {
		sources = append(sources, treeGroupSource(filepath.Join(root, "Temp"), "system-temp", "systemroot/Temp", 32))
		sources = append(sources, treeGroupSource(filepath.Join(root, "Prefetch"), "prefetch", "systemroot/Prefetch", 32))
	}
	if home, err := os.UserHomeDir(); err == nil {
		recent := filepath.Join(home, "AppData", "Roaming", "Microsoft", "Windows", "Recent")
		sources = append(sources, treeGroupSource(recent, "user-recent", "user-profile/Recent", 32))
	}
	return sources
}

func treeGroupSource(root, id, locator string, maxFiles int) collector.Source {
	return collector.Source{ID: id, Kind: "windows.directory_artifacts", Locator: locator, Method: "bounded-directory-walk/v1", MaxBytes: 64 << 20,
		Expand: func(ctx context.Context) ([]collector.Source, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return treeFileSources(root, id, locator, maxFiles), nil
		}}
}

func treeFileSources(root, sourcePrefix, locatorPrefix string, maxFiles int) []collector.Source {
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	var files []string
	visited := 0
	truncated := false
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			truncated = true
			return nil
		}
		visited++
		if visited > 512 {
			truncated = true
			return filepath.SkipAll
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return filepath.SkipDir
		}
		depth := strings.Count(filepath.Clean(rel), string(os.PathSeparator))
		if entry.IsDir() {
			if rel != "." && depth >= 3 {
				truncated = true
				return filepath.SkipDir
			}
			attrsPath, _ := windows.UTF16PtrFromString(path)
			attrs, attrErr := windows.GetFileAttributes(attrsPath)
			if attrErr != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return nil
		}
		attrsPath, _ := windows.UTF16PtrFromString(path)
		attrs, attrErr := windows.GetFileAttributes(attrsPath)
		if attrErr != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return nil
		}
		files = append(files, path)
		if len(files) >= maxFiles {
			truncated = true
			return filepath.SkipAll
		}
		return nil
	})
	sort.Strings(files)
	out := make([]collector.Source, 0, len(files))
	for i, path := range files {
		rel, err := filepath.Rel(root, path)
		if err != nil || strings.HasPrefix(rel, "..") {
			continue
		}
		locator := locatorPrefix + "/" + filepath.ToSlash(rel)
		out = append(out, collector.Source{ID: fmt.Sprintf("%s-%02d", sourcePrefix, i+1), Kind: "windows.file_artifact", Locator: locator, Method: "bounded-file-copy/v1", MaxBytes: 64 << 20,
			Open: func(ctx context.Context) (io.ReadCloser, error) { return openRegular(ctx, path) }})
	}
	if truncated {
		out = append(out, collector.Source{ID: sourcePrefix + "-enumeration-gap", Kind: "windows.collection_gap", Locator: locatorPrefix, Method: "bounded-directory-walk/v1", MaxBytes: 1,
			Open: func(context.Context) (io.ReadCloser, error) {
				return nil, errors.New("directory enumeration stopped at a safety limit or encountered an inaccessible path")
			}})
	}
	return out
}

type diskRecord struct {
	Root       string `json:"root"`
	DriveType  uint32 `json:"drive_type"`
	VolumeName string `json:"volume_name,omitempty"`
	FileSystem string `json:"filesystem,omitempty"`
	Serial     uint32 `json:"volume_serial,omitempty"`
	FreeBytes  uint64 `json:"free_bytes,omitempty"`
	TotalBytes uint64 `json:"total_bytes,omitempty"`
	Status     string `json:"status"`
}

func diskSnapshot(ctx context.Context) ([]byte, error) {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil, err
	}
	rows := make([]diskRecord, 0, 8)
	for i := uint(0); i < 26; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if mask&(1<<i) == 0 {
			continue
		}
		root := fmt.Sprintf("%c:\\", 'A'+i)
		rootPtr, _ := windows.UTF16PtrFromString(root)
		row := diskRecord{Root: root, DriveType: windows.GetDriveType(rootPtr), Status: "OK"}
		if row.DriveType == windows.DRIVE_REMOTE || row.DriveType == windows.DRIVE_CDROM {
			// querying network or optical drives can generate traffic or UI delays on the target
			row.Status = "NOT_QUERIED_REMOTE_OR_OPTICAL"
			rows = append(rows, row)
			continue
		}
		free, total, freeTotal := uint64(0), uint64(0), uint64(0)
		if err := windows.GetDiskFreeSpaceEx(rootPtr, &free, &total, &freeTotal); err != nil {
			row.Status = "SPACE_QUERY_ERROR"
		} else {
			row.FreeBytes, row.TotalBytes = freeTotal, total
		}
		volume := make([]uint16, 261)
		fs := make([]uint16, 261)
		var serial, componentMax, flags uint32
		if err := windows.GetVolumeInformation(rootPtr, &volume[0], uint32(len(volume)), &serial, &componentMax, &flags, &fs[0], uint32(len(fs))); err != nil {
			if row.Status == "OK" {
				row.Status = "VOLUME_QUERY_ERROR"
			}
		} else {
			row.VolumeName = windows.UTF16ToString(volume)
			row.FileSystem = windows.UTF16ToString(fs)
			row.Serial = serial
		}
		rows = append(rows, row)
	}
	return json.Marshal(struct {
		CapturedAt string       `json:"captured_at_utc"`
		Volumes    []diskRecord `json:"volumes"`
	}{time.Now().UTC().Format(time.RFC3339Nano), rows})
}

type autorunValue struct {
	Hive    string `json:"hive"`
	Key     string `json:"key"`
	Name    string `json:"name,omitempty"`
	Type    uint32 `json:"type,omitempty"`
	Command string `json:"command,omitempty"`
	Status  string `json:"status"`
}

func autorunSnapshot(ctx context.Context) ([]byte, error) {
	targets := []struct {
		hive string
		root registry.Key
		path string
	}{
		{"HKLM", registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`},
		{"HKLM", registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
		{"HKLM32", registry.LOCAL_MACHINE, `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`},
		{"HKLM32", registry.LOCAL_MACHINE, `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`},
		{"HKCU", registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`},
		{"HKCU", registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
	}
	rows := make([]autorunValue, 0, 64)
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key, err := registry.OpenKey(target.root, target.path, registry.QUERY_VALUE)
		if err != nil {
			status := "ERROR"
			if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
				status = "ABSENT"
			}
			rows = append(rows, autorunValue{Hive: target.hive, Key: target.path, Status: status})
			continue
		}
		names, namesErr := key.ReadValueNames(4096)
		if namesErr != nil {
			rows = append(rows, autorunValue{Hive: target.hive, Key: target.path, Status: "ERROR"})
			key.Close()
			continue
		}
		for _, name := range names {
			if len(rows) >= 4096 {
				key.Close()
				return nil, errors.New("autorun value count exceeds collection limit")
			}
			if err := ctx.Err(); err != nil {
				key.Close()
				return nil, err
			}
			value, valueType, valueErr := key.GetStringValue(name)
			if valueErr != nil {
				rows = append(rows, autorunValue{Hive: target.hive, Key: target.path, Name: name, Status: "UNSUPPORTED_OR_ERROR"})
				continue
			}
			if len(value) > 64<<10 {
				rows = append(rows, autorunValue{Hive: target.hive, Key: target.path, Name: name, Type: valueType, Status: "VALUE_TOO_LARGE"})
				continue
			}
			rows = append(rows, autorunValue{Hive: target.hive, Key: target.path, Name: name, Type: valueType, Command: value, Status: "OK"})
		}
		key.Close()
	}
	return json.Marshal(struct {
		CapturedAt string         `json:"captured_at_utc"`
		Values     []autorunValue `json:"values"`
	}{time.Now().UTC().Format(time.RFC3339Nano), rows})
}

type userAssistValue struct {
	Key        string `json:"key"`
	Name       string `json:"name"`
	Type       uint32 `json:"type,omitempty"`
	DataBase64 string `json:"data_base64,omitempty"`
	Status     string `json:"status"`
}

func userAssistSnapshot(ctx context.Context) ([]byte, error) {
	const rootPath = `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`
	root, err := registry.OpenKey(registry.CURRENT_USER, rootPath, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	subkeys, err := root.ReadSubKeyNames(128)
	if err != nil && !errors.Is(err, io.EOF) { // io.EOF only means "no subkeys"
		return nil, err
	}
	sort.Strings(subkeys)
	rows := make([]userAssistValue, 0, 256)
	for _, subkey := range subkeys {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key, err := registry.OpenKey(registry.CURRENT_USER, rootPath+`\`+subkey+`\Count`, registry.QUERY_VALUE)
		if err != nil {
			rows = append(rows, userAssistValue{Key: subkey, Status: "COUNT_KEY_UNAVAILABLE"})
			continue
		}
		names, err := key.ReadValueNames(4096)
		if err != nil && !errors.Is(err, io.EOF) { // io.EOF only means "no values"
			key.Close()
			return nil, err
		}
		sort.Strings(names)
		for _, name := range names {
			if len(rows) >= 4096 {
				key.Close()
				return nil, errors.New("UserAssist value count exceeds collection limit")
			}
			if err := ctx.Err(); err != nil {
				key.Close()
				return nil, err
			}
			size, valueType, err := key.GetValue(name, nil)
			if err != nil || size < 0 || size > 64<<10 {
				rows = append(rows, userAssistValue{Key: subkey, Name: name, Status: "VALUE_SIZE_ERROR"})
				continue
			}
			data := make([]byte, size)
			_, valueType, err = key.GetValue(name, data)
			if err != nil {
				rows = append(rows, userAssistValue{Key: subkey, Name: name, Status: "VALUE_READ_ERROR"})
				continue
			}
			rows = append(rows, userAssistValue{Key: subkey, Name: name, Type: valueType, DataBase64: base64.StdEncoding.EncodeToString(data), Status: "OK"})
		}
		key.Close()
	}
	data, err := json.Marshal(struct {
		CapturedAt string            `json:"captured_at_utc"`
		Values     []userAssistValue `json:"values"`
	}{time.Now().UTC().Format(time.RFC3339Nano), rows})
	if err != nil {
		return nil, err
	}
	if len(data) > 16<<20 {
		return nil, errors.New("UserAssist snapshot exceeds collection limit")
	}
	return data, nil
}

type processRecord struct {
	PID       uint32 `json:"pid"`
	ParentPID uint32 `json:"parent_pid"`
	Threads   uint32 `json:"threads"`
	Image     string `json:"image"`
}

func processSnapshot(ctx context.Context) ([]byte, error) {
	h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	if err := windows.Process32First(h, &entry); err != nil {
		return nil, err
	}
	items := make([]processRecord, 0, 256)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		items = append(items, processRecord{entry.ProcessID, entry.ParentProcessID, entry.Threads, windows.UTF16ToString(entry.ExeFile[:])})
		if len(items) >= 32768 {
			return nil, errors.New("process count exceeds collection limit")
		}
		entry.Size = uint32(unsafe.Sizeof(windows.ProcessEntry32{}))
		if err := windows.Process32Next(h, &entry); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return nil, err
		}
	}
	return json.Marshal(struct {
		CapturedAt string          `json:"captured_at_utc"`
		Processes  []processRecord `json:"processes"`
	}{time.Now().UTC().Format(time.RFC3339Nano), items})
}

type tcpRecord struct {
	State         uint32 `json:"state"`
	LocalAddress  string `json:"local_address"`
	LocalPort     uint16 `json:"local_port"`
	RemoteAddress string `json:"remote_address"`
	RemotePort    uint16 `json:"remote_port"`
	PID           uint32 `json:"pid"`
}

func tcpSnapshot(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dll := windows.NewLazySystemDLL("iphlpapi.dll")
	proc := dll.NewProc("GetExtendedTcpTable")
	if err := dll.Load(); err != nil {
		return nil, err
	}
	var size uint32
	r1, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, 2, 5, 0)
	if size < 4 || size > 64<<20 {
		return nil, fmt.Errorf("TCP table size outside limit: %d", size)
	}
	buf := make([]byte, size)
	r1, _, _ = proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, 2, 5, 0)
	if r1 != 0 {
		return nil, syscall.Errno(r1)
	}
	count := binary.LittleEndian.Uint32(buf[:4])
	const rowSize = 24
	if count > uint32((len(buf)-4)/rowSize) {
		return nil, errors.New("invalid TCP table row count")
	}
	items := make([]tcpRecord, 0, count)
	for index := uint32(0); index < count; index++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		row := buf[4+index*rowSize : 4+(index+1)*rowSize]
		localIP := net.IPv4(row[4], row[5], row[6], row[7]).String()
		remoteIP := net.IPv4(row[12], row[13], row[14], row[15]).String()
		items = append(items, tcpRecord{binary.LittleEndian.Uint32(row[0:4]), localIP, binary.BigEndian.Uint16(row[8:10]), remoteIP, binary.BigEndian.Uint16(row[16:18]), binary.LittleEndian.Uint32(row[20:24])})
	}
	return json.Marshal(struct {
		CapturedAt  string      `json:"captured_at_utc"`
		Connections []tcpRecord `json:"connections"`
	}{time.Now().UTC().Format(time.RFC3339Nano), items})
}

func openRegular(ctx context.Context, path string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("source is not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		f.Close()
		return nil, errors.New("source changed during open")
	}
	return f, nil
}

func exportLog(ctx context.Context, name string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	notes := channelFileTimes(name) // before the export touches the file
	tmp, err := os.CreateTemp(scratchDir(), "mantis-evtx-*.evtx")
	if err != nil {
		return nil, err
	}
	path := tmp.Name()
	if err := tmp.Close(); err != nil {
		os.Remove(path)
		return nil, err
	}
	if err := os.Remove(path); err != nil {
		return nil, err
	}
	logPtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	dll := windows.NewLazySystemDLL("wevtapi.dll")
	proc := dll.NewProc("EvtExportLog")
	if err := dll.Load(); err != nil {
		return nil, err
	}
	r1, _, callErr := proc.Call(0, uintptr(unsafe.Pointer(logPtr)), 0, uintptr(unsafe.Pointer(pathPtr)), evtExportLogChannelPath)
	runtime.KeepAlive(logPtr)
	runtime.KeepAlive(pathPtr)
	if r1 == 0 {
		os.Remove(path)
		if callErr == syscall.Errno(0) {
			callErr = syscall.EINVAL
		}
		return nil, fmt.Errorf("export Windows event log %q: %w", name, callErr)
	}
	file, err := os.Open(path)
	if err != nil {
		os.Remove(path)
		return nil, err
	}
	return &removeOnClose{File: file, path: path, notes: notes}, nil
}

type removeOnClose struct {
	*os.File
	path  string
	notes map[string]string
}

func (f *removeOnClose) AcquisitionNotes() map[string]string { return f.notes }

// channelFileTimes returns the times of the .evtx file that backs a channel. The export is a new file, so these are
// the only record of when the live log was created, last written and last accessed.
func channelFileTimes(name string) map[string]string {
	lp := readChannelConfig(name).LogFilePath
	if lp == "" {
		return nil
	}
	if exp, err := registry.ExpandString(lp); err == nil {
		lp = exp
	}
	notes := fileTimeNotes(lp)
	if notes != nil {
		notes["source_file"] = lp
	}
	return notes
}

func (f *removeOnClose) Close() error {
	closeErr := f.File.Close()
	return errors.Join(closeErr, os.Remove(f.path))
}

func safeID(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			out = append(out, r)
		} else {
			out = append(out, '-')
		}
	}
	return string(out)
}
