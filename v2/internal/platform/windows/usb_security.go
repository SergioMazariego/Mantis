//go:build windows

package windows

import (
	"strings"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
)

// usbSources acquires removable-media evidence. The raw SYSTEM hive (registry module) is the
// authoritative source; these live dumps and logs make the device history directly usable.
// No first/last connection time is inferred here: the raw property keys and logs are kept.
func usbSources() []collector.Source {
	um := func(name, desc string, p collector.ProfileMask, priv collector.Privilege) collector.Meta {
		return baseMeta(name, desc, "usb", priv, p)
	}
	return []collector.Source{
		regSnapshotSource("usb-device-history", um("USB and removable storage registry history", "USBSTOR/USB enumeration (device ids, serials, friendly names and Properties keys with device timestamps), MountedDevices, Windows Portable Devices, EMDMgmt, DeviceContainers",
			collector.InStdFull, collector.PrivUser), `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR | USB | MountedDevices | ...`, func() []regTarget {
			return []regTarget{hklm(`SYSTEM\CurrentControlSet\Enum\USBSTOR`, true, 0), hklm(`SYSTEM\CurrentControlSet\Enum\USB`, true, 0),
				hklm(`SYSTEM\CurrentControlSet\Enum\SCSI`, true, 3), hklm(`SYSTEM\CurrentControlSet\Enum\WpdBusEnumRoot`, true, 0),
				hklm(`SYSTEM\MountedDevices`, false, 0), hklm(`SOFTWARE\Microsoft\Windows Portable Devices\Devices`, true, 2),
				hklm(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`, true, 2), hklm(`SYSTEM\CurrentControlSet\Control\usbflags`, true, 2),
				hklm(`SYSTEM\CurrentControlSet\Services\USBSTOR`, true, 2), hklm(`SYSTEM\CurrentControlSet\Control\StorageDevicePolicies`, true, 2),
				hklm(`SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\PnpResources`, false, 0)}
		}),
		regSnapshotSource("usb-user-mountpoints", um("MountPoints2 and drive history per user", "Volumes each user mounted (links a user session to a volume GUID)", collector.InStdFull, collector.PrivUser),
			`HKU\<SID>\...\Explorer\MountPoints2`, func() []regTarget {
				return perLoadedUser(`Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`, true, 2)
			}),
		walkGroup("usb-setupapi-logs", um("SetupAPI device installation logs", "setupapi.dev.log and rotated logs: first time a device was installed (driver installation timestamps)", collector.InStdFull, collector.PrivUser),
			windowsDir()+`\INF\setupapi*.log`, walkSpec{Roots: staticRoots(windowsDir() + `\INF`), MaxDepth: -1, MaxFiles: 200, FileMax: 256 << 20,
				Match: func(_, n string) bool {
					l := strings.ToLower(n)
					return strings.HasPrefix(l, "setupapi") && strings.HasSuffix(l, ".log")
				}}),
	}
}

// securitySources: Defender, firewall logs, audit policy, Sysmon configuration, Security Center.
func securitySources() []collector.Source {
	sm := func(name, desc string, p collector.ProfileMask, priv collector.Privilege, art ...string) collector.Meta {
		return baseMeta(name, desc, "security", priv, p, art...)
	}
	pd := expandEnv(`%ProgramData%`) + `\Microsoft\Windows Defender`
	return []collector.Source{
		regSnapshotSource("security-defender-config", sm("Microsoft Defender configuration and exclusions", "Defender settings, exclusions (paths/processes/extensions), real-time protection state, signature versions and policy overrides",
			collector.InAll, collector.PrivAdmin, "file-activity/detectionhistory.md"), `HKLM\SOFTWARE\Microsoft\Windows Defender`, func() []regTarget {
			return []regTarget{hklm(`SOFTWARE\Microsoft\Windows Defender`, true, 6), hklm(`SOFTWARE\Policies\Microsoft\Windows Defender`, true, 6),
				hklm(`SOFTWARE\Microsoft\Windows Advanced Threat Protection`, true, 3), hklm(`SOFTWARE\Microsoft\Windows Security Health`, true, 4),
				hklm(`SOFTWARE\Microsoft\Security Center`, true, 3)}
		}),
		requiresAdmin(walkGroup("security-defender-detection-history", sm("Defender DetectionHistory and scan history", "DetectionHistory records (threat names, paths, actions) and service scan results. Quarantined file contents are NOT collected",
			collector.InAll, collector.PrivAdmin, "file-activity/detectionhistory.md"), pd+`\Scans\History`, walkSpec{
			Roots: staticRoots(pd + `\Scans\History`), MaxDepth: 8, MaxFiles: 20000, FileMax: 64 << 20})),
		walkGroup("security-defender-logs", sm("Defender support logs (MPLog)", "MPLog-*.log, MpCmdRun and support traces: scan activity, detections, exclusion reads, ASR events", collector.InStdFull, collector.PrivAdmin),
			pd+`\Support`, walkSpec{Roots: staticRoots(pd + `\Support`), MaxDepth: 2, MaxFiles: 2000, FileMax: 512 << 20,
				Match: func(_, n string) bool {
					l := strings.ToLower(n)
					return strings.HasSuffix(l, ".log") || strings.HasSuffix(l, ".etl") || strings.HasSuffix(l, ".txt")
				}}),
		walkGroup("security-firewall-logs", sm("Windows Firewall text logs", "pfirewall.log when file logging is enabled (dropped/allowed connections)", collector.InStdFull, collector.PrivAdmin, "network/evtx-5156-wfp-permitted.md"),
			windowsDir()+`\System32\LogFiles\Firewall`, walkSpec{Roots: staticRoots(windowsDir() + `\System32\LogFiles\Firewall`), MaxDepth: -1, MaxFiles: 50, FileMax: 1 << 30}),
		walkGroup("security-audit-policy-files", sm("Advanced audit policy file", "Local audit.csv from the Group Policy audit configuration (effective policy is in the SECURITY hive)", collector.InAll, collector.PrivAdmin),
			windowsDir()+`\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit`, walkSpec{Roots: staticRoots(windowsDir() + `\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit`), MaxDepth: -1, MaxFiles: 20, FileMax: 8 << 20}),
		regSnapshotSource("security-sysmon-config", sm("Sysmon driver/service configuration (if installed)", "Sysmon rules blob and options from the service parameters, as configuration evidence. The Sysmon event channel is in the event-log module",
			collector.InAll, collector.PrivUser), `HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters`, func() []regTarget {
			return []regTarget{hklm(`SYSTEM\CurrentControlSet\Services\SysmonDrv`, true, 2), hklm(`SYSTEM\CurrentControlSet\Services\Sysmon`, true, 2), hklm(`SYSTEM\CurrentControlSet\Services\Sysmon64`, true, 2)}
		}),
		regSnapshotSource("security-eventlog-config", sm("Event log service configuration", "Per-channel registry configuration (retention, max size, file path) of the classic event logs and ETW autologgers (logging gaps/tampering indicators)", collector.InAll, collector.PrivUser),
			`HKLM\SYSTEM\CurrentControlSet\Services\EventLog | WMI\Autologger`, func() []regTarget {
				return []regTarget{hklm(`SYSTEM\CurrentControlSet\Services\EventLog`, true, 2), hklm(`SYSTEM\CurrentControlSet\Control\WMI\Autologger`, true, 2)}
			}),
	}
}

// groupPolicySources: applied policy files, history and registry policy artifacts.
func groupPolicySources() []collector.Source {
	gm := func(name, desc string, p collector.ProfileMask, priv collector.Privilege, art ...string) collector.Meta {
		return baseMeta(name, desc, "group-policy", priv, p, art...)
	}
	win := windowsDir()
	return []collector.Source{
		walkGroup("gpo-local-policy-files", gm("Local Group Policy files", "Registry.pol, scripts, audit and security templates under System32\\GroupPolicy and GroupPolicyUsers", collector.InStdFull, collector.PrivAdmin),
			win+`\System32\GroupPolicy*`, walkSpec{Roots: staticRoots(win+`\System32\GroupPolicy`, win+`\System32\GroupPolicyUsers`), MaxDepth: 8, MaxFiles: 3000, FileMax: 64 << 20}),
		walkGroup("gpo-history-files", gm("Group Policy history (cached applied GPOs)", "Cached copies of applied policy under ProgramData\\Microsoft\\Group Policy\\History", collector.InStdFull, collector.PrivAdmin),
			expandEnv(`%ProgramData%`)+`\Microsoft\Group Policy`, walkSpec{Roots: staticRoots(expandEnv(`%ProgramData%`) + `\Microsoft\Group Policy`), MaxDepth: 8, MaxFiles: 3000, FileMax: 64 << 20}),
		regSnapshotSource("gpo-applied-registry", gm("Applied Group Policy registry state", "Group Policy history (GPO list, extension status, last processing) and policy-delivered registry values for machine and loaded users", collector.InStdFull, collector.PrivUser),
			`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy | Policies`, func() []regTarget {
				t := []regTarget{hklm(`SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy`, true, 0), hklm(`SOFTWARE\Policies`, true, 0),
					hklm(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies`, true, 3), hklm(`SOFTWARE\Microsoft\PolicyManager`, true, 4)}
				t = append(t, perLoadedUser(`Software\Microsoft\Windows\CurrentVersion\Group Policy`, true, 0)...)
				t = append(t, perLoadedUser(`Software\Policies`, true, 0)...)
				return t
			}),
	}
}
