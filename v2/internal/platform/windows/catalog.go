//go:build windows

package windows

import (
	"sort"
	"strings"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
)

// categoryOrder is the execution/display order of evidence categories, following the order of
// volatility: memory, processes and network first, then system state, then persisted artifacts.
var categoryOrder = []string{"memory", "processes", "network", "system", "persistence", "registry", "eventlogs", "ntfs", "execution", "users",
	"remote-access", "usb", "browsers", "security", "group-policy", "shadow-copies"}

// Sources returns the complete Windows collector registry. Every entry is a named, reviewed
// source; nothing is registered that the code does not implement. Groups (Expand) become
// per-file items when run, so each raw artifact has its own hash and manifest record.
func Sources() []collector.Source {
	prepareAcquisition()
	var all []collector.Source
	all = append(all, systemSources()...)
	all = append(all, registrySources()...)
	all = append(all, persistenceSources()...)
	all = append(all, processSources()...)
	all = append(all, networkSources()...)
	all = append(all, eventlogSources()...)
	all = append(all, ntfsSources()...)
	all = append(all, executionSources()...)
	all = append(all, usersSources()...)
	all = append(all, remoteSources()...)
	all = append(all, usbSources()...)
	all = append(all, browserSources()...)
	all = append(all, securitySources()...)
	all = append(all, groupPolicySources()...)
	all = append(all, vssSources()...)
	all = append(all, memorySources()...)
	all = append(all, tempSources()...)
	all = append(all, annotateLegacy(legacySources())...)

	seen := map[string]bool{}
	out := all[:0]
	for _, s := range all {
		if seen[s.ID] {
			continue
		}
		seen[s.ID] = true
		if s.Meta.Name == "" {
			s.Meta.Name = s.ID
		}
		if s.Meta.Privilege == collector.PrivAdmin || s.Meta.Privilege == collector.PrivDebug {
			s = requiresAdmin(s) // so availability reports needs_admin instead of "available" when not elevated
		}
		if s.Meta.Privilege == "" {
			s.Meta.Privilege = collector.PrivUser
		}
		if s.Meta.Windows == "" {
			s.Meta.Windows = "Windows 10, Windows 11 (build 19041+); Server not tested"
		}
		out = append(out, s)
	}
	rank := map[string]int{}
	for i, c := range categoryOrder {
		rank[c] = i
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := rank[out[i].Meta.Category], rank[out[j].Meta.Category]
		if ri != rj {
			return ri < rj
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// tempSources restores v1's Windows Temp acquisition with raw file copies (v1 used xcopy).
func tempSources() []collector.Source {
	m := baseMeta("Windows Temp folder", "Files in %SystemRoot%\\Temp: transient installers, dropped tools and staging artifacts (v1 parity, with per-file hashes)", "execution", collector.PrivUser, collector.InStdFull)
	return []collector.Source{walkGroup("execution-windows-temp", m, windowsDir()+`\Temp`, walkSpec{
		Roots: staticRoots(windowsDir() + `\Temp`), MaxDepth: 6, MaxFiles: 8000, FileMax: 128 << 20})}
}

// annotateLegacy keeps the original v1-parity collectors (stable IDs) available for custom
// selection, but excludes them from built-in profiles: each has a more complete replacement.
func annotateLegacy(legacy []collector.Source) []collector.Source {
	type info struct{ category, replacement string }
	table := map[string]info{
		"process-snapshot":   {"processes", "processes-detailed"},
		"tcp-connections":    {"network", "network-connections"},
		"autorun-registry":   {"persistence", "persistence-autorun-registry"},
		"disk-inventory":     {"system", "system-disks"},
		"userassist":         {"execution", "execution-userassist"},
		"powershell-history": {"users", "users-psreadline-history"},
		"system-temp":        {"execution", "execution-windows-temp"},
		"prefetch":           {"execution", "execution-prefetch"},
		"user-recent":        {"users", "users-recent-lnk"},
	}
	for i := range legacy {
		s := &legacy[i]
		cat, repl := "eventlogs", "evtx-all"
		if t, ok := table[s.ID]; ok {
			cat, repl = t.category, t.replacement
		}
		if strings.HasPrefix(s.ID, "evtx-") {
			s.ID = "legacy-" + s.ID // keeps legacy ids from colliding with the per-channel ids of evtx-all
		}
		s.Meta.Category = cat
		s.Meta.Name = "v1 parity: " + s.ID
		s.Meta.Description = "Original Mantis v2 foundation collector kept for custom selection and regression; superseded by " + repl
		s.Meta.Profiles = 0
		s.Meta.Privilege = collector.PrivUser
		if strings.HasPrefix(s.ID, "legacy-evtx-") {
			s.Meta.Privilege = collector.PrivAdmin
		}
		if s.Meta.SourcePath == "" {
			s.Meta.SourcePath = s.Locator
		}
	}
	return legacy
}
