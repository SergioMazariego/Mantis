package collector

import (
	"context"
	"errors"
	"strings"
)

// Profile identifies an acquisition profile. Custom has no members of its own:
// the operator picks individual sources.
type Profile string

const (
	ProfileQuick    Profile = "quick"
	ProfileStandard Profile = "standard"
	ProfileFull     Profile = "full"
	ProfileCustom   Profile = "custom"
)

// ProfileMask records which built-in profiles include a source.
type ProfileMask uint8

const (
	InQuick ProfileMask = 1 << iota
	InStandard
	InFull
)

// Common masks. Quick implies Standard implies Full for sources marked InAll.
const (
	InAll      = InQuick | InStandard | InFull
	InStdFull  = InStandard | InFull
	InFullOnly = InFull
)

// Has reports whether the mask includes profile p (Custom is never "included").
func (m ProfileMask) Has(p Profile) bool {
	switch p {
	case ProfileQuick:
		return m&InQuick != 0
	case ProfileStandard:
		return m&InStandard != 0
	case ProfileFull:
		return m&InFull != 0
	}
	return false
}

// ParseProfile accepts the CLI spelling of a profile.
func ParseProfile(s string) (Profile, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "quick", "quick-triage", "triage":
		return ProfileQuick, true
	case "standard", "standard-dfir", "dfir":
		return ProfileStandard, true
	case "full", "full-forensic", "forensic":
		return ProfileFull, true
	case "custom":
		return ProfileCustom, true
	}
	return "", false
}

// Privilege is the minimum privilege a source needs to be acquired completely.
type Privilege string

const (
	PrivUser  Privilege = "user"
	PrivAdmin Privilege = "admin" // elevated administrator (SeBackupPrivilege / raw volume access)
	PrivDebug Privilege = "debug" // administrator with SeDebugPrivilege (process inspection)
)

// Meta is the forensic description of a source: where its evidence lives and
// how it is acquired. It is carried into the evidence package manifest.
type Meta struct {
	Name        string      // short human name
	Description string      // forensic purpose
	Category    string      // package folder: system, registry, persistence, ...
	SourceType  string      // file, registry, api, eventlog, ntfs-metadata, memory, ...
	SourcePath  string      // original path, channel or API (not the package path)
	DestPath    string      // slash-separated path inside the package (empty: derived)
	Windows     string      // supported Windows versions, free text
	Privilege   Privilege   // minimum privilege for a complete acquisition
	Profiles    ProfileMask // built-in profiles that include this source
	SideEffects string      // documented live-response side effects, if any
	Sensitive   bool        // needs explicit operator confirmation before collection
	Artifacts   []string    // coverage-catalog IDs this source satisfies
	ActionTypes []string    // user/system activity this source can evidence (the ActionX vocabulary), apart from SourceType
	DataVersion int         // version of the structure of this source's JSON data; bumped whenever its fields change shape
}

// AvailState is the result of a read-only availability probe.
type AvailState string

const (
	Available    AvailState = "available"
	NotPresent   AvailState = "not_present"   // source does not exist on this host
	NotSupported AvailState = "not_supported" // host/OS/filesystem cannot provide it
	NeedsAdmin   AvailState = "needs_admin"   // exists but requires elevation
	Unknown      AvailState = "unknown"
)

// Availability is what a probe learned without acquiring the source.
type Availability struct {
	State  AvailState
	Reason string
}

// Typed acquisition outcomes. They have different forensic meanings and must
// not be collapsed into a generic failure.
var (
	ErrNotPresent   = errors.New("source not present on this host")
	ErrNotSupported = errors.New("source not supported on this host")
	ErrAccessDenied = errors.New("access denied")
	ErrLocked       = errors.New("source is locked by another process")
)

// Disposition is the final, forensic classification of one acquired item.
type Disposition string

const (
	Collected         Disposition = "collected"
	CollectedWarnings Disposition = "collected_with_warnings"
	Empty             Disposition = "empty"
	DispNotPresent    Disposition = "not_present"
	DispNotSupported  Disposition = "not_supported"
	DispAccessDenied  Disposition = "access_denied"
	DispFailed        Disposition = "failed"
	DispCancelled     Disposition = "cancelled"
)

// Classify derives the disposition of an item from what actually happened.
func (it ItemResult) Classify() Disposition {
	switch {
	case it.Err == nil && it.Result.Ready:
		if it.Result.Blob.SizeBytes == 0 {
			return Empty
		}
		if w := it.Notes["warnings"]; w != "" && w != "0" {
			return CollectedWarnings
		}
		return Collected
	case errors.Is(it.Err, context.Canceled):
		return DispCancelled
	case errors.Is(it.Err, ErrNotPresent), errors.Is(it.Err, ErrNoSources):
		return DispNotPresent
	case errors.Is(it.Err, ErrNotSupported):
		return DispNotSupported
	case errors.Is(it.Err, ErrAccessDenied):
		return DispAccessDenied
	}
	return DispFailed
}

// MethodReporter lets a reader report the acquisition method it actually used
// (a source may fall back from a direct read to a raw volume read).
type MethodReporter interface{ AcquisitionMethod() string }

// NotesReporter lets a reader attach structured notes (offsets, warnings) that
// are recorded with the item after the bytes were read.
type NotesReporter interface{ AcquisitionNotes() map[string]string }

// Activity (action type) vocabulary. A source type says where evidence comes from (registry key, event log,
// shortcut file...); an action type says what happened (a program ran, a file was opened...). The names follow
// the common activity-timeline vocabulary so analysts can filter the manifest by action.
const (
	ActionRunExe         = "Run .EXE file"
	ActionOpenSaveDialog = "Select file in open/save dialog-box"
	ActionOpenFile       = "Open file or folder"
	ActionViewFolder     = "View Folder in Explorer"
	ActionSoftwareInst   = "Software Installation"
	ActionSystemStarted  = "System Started"
	ActionSystemShutdown = "System Shutdown"
	ActionSleep          = "Sleep"
	ActionResume         = "Resumed from sleep"
	ActionNetConnected   = "Network Connected"
	ActionNetDisconnect  = "Network Disconnected"
	ActionSoftwareCrash  = "Software Crash"
	ActionSoftwareHang   = "Software stopped responding (hang)"
	ActionBlueScreen     = "Blue Screen"
	ActionUserLogon      = "User Logon"
	ActionUserLogoff     = "User Logoff"
	ActionRestorePoint   = "Restore Point Created"
	ActionInstallerStart = "Windows Installer Started"
	ActionInstallerEnd   = "Windows Installer Ended"
	ActionWifiConnected  = "Wireless Network Connected"
	ActionWifiDisconnect = "Wireless Network Disconnected"
	ActionTaskRun        = "Task Run"
)
