//go:build windows

package windows

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"golang.org/x/sys/windows"
)

var (
	wevtapi                 = windows.NewLazySystemDLL("wevtapi.dll")
	pEvtOpenChannelEnum     = wevtapi.NewProc("EvtOpenChannelEnum")
	pEvtNextChannelPath     = wevtapi.NewProc("EvtNextChannelPath")
	pEvtOpenChannelConfig   = wevtapi.NewProc("EvtOpenChannelConfig")
	pEvtGetChannelConfigPrp = wevtapi.NewProc("EvtGetChannelConfigProperty")
	pEvtClose               = wevtapi.NewProc("EvtClose")
)

const errNoMoreItems = syscall.Errno(259)

// listChannels enumerates every event channel registered on the host.
func listChannels() ([]string, error) {
	if err := wevtapi.Load(); err != nil {
		return nil, fmt.Errorf("%w: %v", collector.ErrNotSupported, err)
	}
	h, _, callErr := pEvtOpenChannelEnum.Call(0, 0)
	if h == 0 {
		return nil, classifyErr(callErr)
	}
	defer pEvtClose.Call(h)
	var names []string
	buf := make([]uint16, 512)
	for {
		var used uint32
		r, _, callErr := pEvtNextChannelPath.Call(h, uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)))
		if r == 0 {
			if errors.Is(callErr, errNoMoreItems) {
				break
			}
			if errors.Is(callErr, syscall.ERROR_INSUFFICIENT_BUFFER) && used > uint32(len(buf)) {
				buf = make([]uint16, used)
				continue
			}
			return names, classifyErr(callErr)
		}
		names = append(names, windows.UTF16ToString(buf[:used]))
	}
	sort.Strings(names)
	return names, nil
}

// channelFileName mirrors the Windows convention: '/' in a channel name becomes "%4".
func channelFileName(name string) string { return strings.ReplaceAll(name, "/", "%4") + ".evtx" }

type channelConfig struct {
	Name           string `json:"channel"`
	Enabled        *bool  `json:"enabled,omitempty"`
	Type           string `json:"type,omitempty"`
	OwningProvider string `json:"owning_publisher,omitempty"`
	LogFilePath    string `json:"log_file_path,omitempty"`
	MaxSizeBytes   uint64 `json:"max_size_bytes,omitempty"`
	Retention      *bool  `json:"retention,omitempty"`
	AutoBackup     *bool  `json:"auto_backup,omitempty"`
	Error          string `json:"error,omitempty"`
}

// EVT_CHANNEL_CONFIG_PROPERTY_ID values used below.
const (
	evtCfgEnabled   = 0
	evtCfgType      = 2
	evtCfgOwning    = 3
	evtCfgRetention = 6
	evtCfgBackup    = 7
	evtCfgMaxSize   = 8
	evtCfgLogFile   = 9
)

func readChannelConfig(name string) channelConfig {
	cc := channelConfig{Name: name}
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		cc.Error = err.Error()
		return cc
	}
	h, _, callErr := pEvtOpenChannelConfig.Call(0, uintptr(unsafe.Pointer(p)), 0)
	if h == 0 {
		cc.Error = callErr.Error()
		return cc
	}
	defer pEvtClose.Call(h)
	// EVT_VARIANT: 8-byte union, uint32 Count, uint32 Type.
	get := func(id uintptr) (union uint64, strVal string, vt uint32, ok bool) {
		var used uint32
		pEvtGetChannelConfigPrp.Call(h, id, 0, 0, 0, uintptr(unsafe.Pointer(&used)))
		if used < 16 {
			return 0, "", 0, false
		}
		buf := make([]byte, used)
		if r, _, _ := pEvtGetChannelConfigPrp.Call(h, id, 0, uintptr(used), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used))); r == 0 {
			return 0, "", 0, false
		}
		union = binary.LittleEndian.Uint64(buf[0:8])
		vt = binary.LittleEndian.Uint32(buf[12:16])
		if vt == 1 { // EvtVarTypeString: pointer into the same buffer's string area
			ptr := (*uint16)(*(*unsafe.Pointer)(unsafe.Pointer(&union)))
			strVal = windows.UTF16PtrToString(ptr)
		}
		return union, strVal, vt, true
	}
	boolVal := func(id uintptr) *bool {
		if u, _, vt, ok := get(id); ok && vt == 13 { // EvtVarTypeBoolean
			b := uint32(u) != 0
			return &b
		}
		return nil
	}
	cc.Enabled = boolVal(evtCfgEnabled)
	cc.Retention = boolVal(evtCfgRetention)
	cc.AutoBackup = boolVal(evtCfgBackup)
	if u, _, vt, ok := get(evtCfgType); ok && vt == 8 {
		cc.Type = map[uint64]string{0: "Admin", 1: "Operational", 2: "Analytic", 3: "Debug"}[u&0xffffffff]
	}
	if _, s, _, ok := get(evtCfgOwning); ok {
		cc.OwningProvider = s
	}
	if _, s, _, ok := get(evtCfgLogFile); ok {
		cc.LogFilePath = s
	}
	if u, _, vt, ok := get(evtCfgMaxSize); ok && vt == 10 {
		cc.MaxSizeBytes = u
	}
	return cc
}

// coreChannels is the Quick Triage subset (substring match on the channel name).
var coreChannels = []string{
	"Application", "System", "Security", "Windows PowerShell", "Microsoft-Windows-PowerShell/Operational",
	"Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-TaskScheduler/Operational",
	"Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-WMI-Activity/Operational",
	"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
	"Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", "Microsoft-Windows-TerminalServices-RDPClient/Operational",
	"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", "Microsoft-Windows-GroupPolicy/Operational",
	"Microsoft-Windows-WLAN-AutoConfig/Operational", "Microsoft-Windows-SMBClient/Security", "Microsoft-Windows-SMBServer/Security",
	"Microsoft-Windows-Bits-Client/Operational", "Microsoft-Windows-Shell-Core/Operational",
	"Microsoft-Windows-NetworkProfile/Operational",
}

func eventlogSources() []collector.Source {
	meta := baseMeta("Windows Event Logs", "Native EVTX export of event channels with their channel configuration; interpretation is out of scope for acquisition",
		"eventlogs", collector.PrivAdmin, 0,
		"account/evtx-4624-successful-logon.md", "account/evtx-4625-failed-logon.md", "account/evtx-4648-explicit-credentials.md",
		"account/evtx-4720-account-created.md", "execution/evtx-4688-process-created.md", "execution/evtx-4104-script-block-logging.md",
		"persistence/evtx-7045-service-install.md", "persistence/evtx-5861-event-consumer-created.md", "persistence/task-scheduler-operational-log.md",
		"network/evtx-5156-wfp-permitted.md", "network/evtx-4778-session-reconnected.md")
	meta.SideEffects = "EvtExportLog stages a copy of each channel in the scratch directory inside the output folder"

	group := func(id, name string, profiles collector.ProfileMask, filter func(string) bool) collector.Source {
		m := meta
		m.Name, m.Profiles = name, profiles
		return collector.Source{
			ID: id, Kind: "windows.evtx_group", Locator: "eventlog://(discovered channels)", Method: "EvtOpenChannelEnum+EvtExportLog", MaxBytes: 4 << 30, Meta: m,
			Detect: func(context.Context) collector.Availability {
				if _, err := listChannels(); err != nil {
					return collector.Availability{State: collector.NotSupported, Reason: err.Error()}
				}
				return collector.Availability{State: collector.Available}
			},
			Expand: func(context.Context) ([]collector.Source, error) {
				names, err := listChannels()
				if err != nil {
					return nil, err
				}
				var out []collector.Source
				var skipped []string
				ids := map[string]bool{}
				for _, n := range names {
					if filter != nil && !filter(n) {
						continue
					}
					// Analytic and Debug channels are ETL-backed and disabled by default: EvtExportLog cannot
					// produce an EVTX file for them, so they are recorded as a not_supported gap instead.
					if t := readChannelConfig(n).Type; t == "Analytic" || t == "Debug" {
						skipped = append(skipped, n)
						continue
					}
					src := evtxChannelSource(n, meta)
					if ids[src.ID] {
						src.ID += "-" + short(n) // different names can map to the same sanitized id
					}
					ids[src.ID] = true
					out = append(out, src)
				}
				if len(skipped) > 0 {
					sort.Strings(skipped)
					list := strings.Join(skipped, "; ")
					gm := meta
					gm.Name, gm.SourceType, gm.SourcePath = "Analytic/Debug channels (not exportable)", "eventlog", "eventlog://(analytic and debug channels)"
					gm.DestPath = "eventlogs/gaps/analytic-debug-channels.txt"
					out = append(out, collector.Source{ID: "evtx-analytic-debug-skipped", Kind: "windows.collection_gap", Locator: gm.SourcePath, Method: "EvtOpenChannelConfig", MaxBytes: 1, Meta: gm,
						Open: func(context.Context) (io.ReadCloser, error) {
							return nil, fmt.Errorf("%w: %d ETL-backed analytic/debug channels cannot be exported as EVTX: %s", collector.ErrNotSupported, len(skipped), list)
						}})
				}
				if len(out) == 0 {
					return nil, fmt.Errorf("%w: no matching event channels", collector.ErrNotPresent)
				}
				return out, nil
			},
		}
	}
	core := group("evtx-core", "Windows Event Logs: core channels (Quick Triage)", collector.InQuick, func(n string) bool {
		for _, c := range coreChannels {
			if strings.EqualFold(c, n) || (strings.HasSuffix(c, "/") && strings.HasPrefix(strings.ToLower(n), strings.ToLower(c))) {
				return true
			}
		}
		// every TerminalServices / RemoteDesktop channel is relevant for remote-access triage
		ln := strings.ToLower(n)
		return strings.Contains(ln, "terminalservices") || strings.Contains(ln, "remotedesktopservices")
	})
	all := group("evtx-all", "Windows Event Logs: every discovered channel", collector.InStdFull, nil)

	cfg := meta
	cfg.Name, cfg.Profiles = "Event channel configuration", collector.InAll
	cfg.SourceType = "api"
	cfgSrc := jsonSource("evtx-channel-config", cfg, "EvtOpenChannelConfig", "eventlog://(channel configuration)", func(ctx context.Context, w *warnings) (any, error) {
		names, err := listChannels()
		if err != nil {
			return nil, err
		}
		out := make([]channelConfig, 0, len(names))
		for _, n := range names {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			c := readChannelConfig(n)
			if c.Error != "" {
				w.add("%s: %s", n, c.Error)
			}
			out = append(out, c)
		}
		return map[string]any{"channels": out}, nil
	})
	cfgSrc.Meta.Privilege = collector.PrivUser

	// Byte-for-byte copies of the .evtx files on disk (shared read, raw NTFS fallback). EvtExportLog rewrites record
	// headers, so these keep the original chunk layout for carving and header-level analysis. Archive-*.evtx files are
	// rotated logs that no live channel exports, so they are the only copy of that history.
	logsDir := windowsDir() + `\System32\winevt\Logs`
	isArchive := func(n string) bool { return strings.HasPrefix(strings.ToLower(n), "archive-") }
	isEvtx := func(n string) bool { return strings.HasSuffix(strings.ToLower(n), ".evtx") }
	rawMeta := baseMeta("Event log files (byte copy, archived logs)", "Archive-*.evtx files created by log auto-backup: rotated history that is no longer part of any live channel",
		"eventlogs", collector.PrivAdmin, collector.InStdFull, "execution/evtx-4688-process-created.md")
	archives := requiresAdmin(walkGroup("evtx-archive-files", rawMeta, logsDir, walkSpec{
		Roots: staticRoots(logsDir), MaxDepth: -1, MaxFiles: 2000, FileMax: 2 << 30,
		Match: func(_, n string) bool { return isEvtx(n) && isArchive(n) }}))
	rawAll := baseMeta("Event log files (byte copy)", "Every .evtx file in winevt\\Logs copied as it is on disk, in addition to the API export (original headers and chunk layout preserved)",
		"eventlogs", collector.PrivAdmin, collector.InFullOnly, "execution/evtx-4688-process-created.md")
	rawFiles := requiresAdmin(walkGroup("evtx-raw-files", rawAll, logsDir, walkSpec{
		Roots: staticRoots(logsDir), MaxDepth: -1, MaxFiles: 4000, FileMax: 2 << 30,
		Match: func(_, n string) bool { return isEvtx(n) && !isArchive(n) }}))
	return []collector.Source{core, all, cfgSrc, archives, rawFiles}
}

func evtxChannelSource(name string, parent collector.Meta) collector.Source {
	m := parent
	m.Name, m.SourceType, m.SourcePath = name, "eventlog", name
	m.DestPath = "eventlogs/" + channelFileName(name)
	m.Profiles = 0
	return collector.Source{
		ID: "evtx-" + safeID(name), Kind: "windows.evtx", Locator: "eventlog://" + name, Method: "EvtExportLog/v1 (EvtExportLogChannelPath)", MaxBytes: 4 << 30, Meta: m,
		Open: func(ctx context.Context) (io.ReadCloser, error) {
			rc, err := exportLog(ctx, name)
			if err != nil {
				if errors.Is(err, syscall.Errno(15007)) { // ERROR_EVT_CHANNEL_NOT_FOUND
					return nil, fmt.Errorf("%w: %v", collector.ErrNotPresent, err)
				}
				return nil, classifyErr(err)
			}
			return rc, nil
		},
	}
}
