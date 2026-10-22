//go:build windows

package main

import (
	"time"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"github.com/SergioMazariego/Mantis/v2/internal/platform/windows"
)

func platformConfigure(o platformOptions) error {
	filter, err := windows.NormalizeFileFilter(windows.FileFilter{
		Extensions: o.TempExtensions, Types: o.TempTypes, MaxFileBytes: o.TempMaxFileMB << 20,
		MaxFiles: o.TempMaxFiles, MaxDepth: o.TempMaxDepth})
	if err != nil {
		return err
	}
	if o.TempModifiedDays > 0 {
		filter.ModifiedSince = time.Now().UTC().AddDate(0, 0, -o.TempModifiedDays)
	}
	windows.Configure(windows.Options{TempDir: o.TempDir, MemoryPIDs: o.MemoryPIDs, TempFilter: filter})
	return nil
}

func platformSources() []collector.Source { return windows.Sources() }

// platformFilterNote states the Temp filter that shaped the evidence, or "" when none was set.
func platformFilterNote() string { return windows.TempFilterReport() }

// platformHost describes the endpoint and reports whether Mantis runs elevated.
func platformHost() (map[string]string, bool) { return windows.HostInfo(), windows.IsElevated() }

func platformFreeBytes(dir string) (uint64, bool) {
	n, err := windows.FreeBytes(dir)
	return n, err == nil
}
