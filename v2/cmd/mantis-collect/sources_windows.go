//go:build windows

package main

import (
	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"github.com/SergioMazariego/Mantis/v2/internal/platform/windows"
)

func platformConfigure(o platformOptions) {
	windows.Configure(windows.Options{TempDir: o.TempDir, MemoryPIDs: o.MemoryPIDs})
}

func platformSources() []collector.Source { return windows.Sources() }

// platformHost describes the endpoint and reports whether Mantis runs elevated.
func platformHost() (map[string]string, bool) { return windows.HostInfo(), windows.IsElevated() }

func platformFreeBytes(dir string) (uint64, bool) {
	n, err := windows.FreeBytes(dir)
	return n, err == nil
}
