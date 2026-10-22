//go:build windows

package windows

import (
	"strings"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
)

// Action types per source: what activity each artifact can evidence, kept apart from its source type.
// Sources that are not activity evidence (configuration, inventories) carry none.

var eventActions = []string{
	collector.ActionSystemStarted, collector.ActionSystemShutdown, collector.ActionSleep, collector.ActionResume,
	collector.ActionNetConnected, collector.ActionNetDisconnect, collector.ActionSoftwareCrash, collector.ActionSoftwareHang,
	collector.ActionBlueScreen, collector.ActionUserLogon, collector.ActionUserLogoff, collector.ActionRestorePoint,
	collector.ActionInstallerStart, collector.ActionInstallerEnd, collector.ActionWifiConnected, collector.ActionWifiDisconnect,
	collector.ActionTaskRun, collector.ActionSoftwareInst,
}

var sourceActions = map[string][]string{
	"execution-prefetch":         {collector.ActionRunExe},
	"execution-userassist":       {collector.ActionRunExe},
	"execution-bam-dam":          {collector.ActionRunExe},
	"execution-amcache":          {collector.ActionRunExe},
	"execution-shimcache-live":   {collector.ActionRunExe},
	"execution-compat-assistant": {collector.ActionRunExe},
	"execution-srum":             {collector.ActionRunExe},
	"execution-srum-registry":    {collector.ActionRunExe},
	"execution-wer":              {collector.ActionSoftwareCrash, collector.ActionSoftwareHang},
	"execution-crash-dumps":      {collector.ActionBlueScreen},
	"users-recent-lnk":           {collector.ActionOpenFile},
	"users-jump-lists":           {collector.ActionOpenFile},
	"users-explorer-activity":    {collector.ActionOpenSaveDialog, collector.ActionOpenFile, collector.ActionViewFolder},
	"system-software":            {collector.ActionSoftwareInst},
	"network-profiles":           {collector.ActionNetConnected, collector.ActionNetDisconnect},
	"vss-snapshots":              {collector.ActionRestorePoint},
	"evtx-archive-files":         eventActions,
	"evtx-raw-files":             eventActions,
	// legacy v1-parity sources
	"userassist":  {collector.ActionRunExe},
	"prefetch":    {collector.ActionRunExe},
	"user-recent": {collector.ActionOpenFile},
}

// channelActions lists the activity an event channel evidences.
func channelActions(channel string) []string {
	switch strings.ToLower(channel) {
	case "system":
		return []string{collector.ActionSystemStarted, collector.ActionSystemShutdown, collector.ActionSleep, collector.ActionResume, collector.ActionBlueScreen, collector.ActionRestorePoint}
	case "application":
		return []string{collector.ActionSoftwareCrash, collector.ActionSoftwareHang, collector.ActionInstallerStart, collector.ActionInstallerEnd, collector.ActionSoftwareInst, collector.ActionRestorePoint}
	case "security":
		return []string{collector.ActionUserLogon, collector.ActionUserLogoff}
	case "microsoft-windows-networkprofile/operational":
		return []string{collector.ActionNetConnected, collector.ActionNetDisconnect}
	case "microsoft-windows-wlan-autoconfig/operational":
		return []string{collector.ActionWifiConnected, collector.ActionWifiDisconnect}
	case "microsoft-windows-taskscheduler/operational":
		return []string{collector.ActionTaskRun}
	case "microsoft-windows-kernel-power/thermal-operational", "microsoft-windows-power-troubleshooter/operational":
		return []string{collector.ActionSleep, collector.ActionResume}
	}
	return nil
}
