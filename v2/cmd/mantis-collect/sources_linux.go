//go:build linux

package main

import (
	"bufio"
	"os"
	"runtime"
	"syscall"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"github.com/SergioMazariego/Mantis/v2/internal/platform/linux"
)

func platformConfigure(platformOptions) error { return nil }

func platformFilterNote() string { return "" }

func platformSources() []collector.Source {
	sources := linux.Sources()
	for i := range sources {
		if sources[i].Meta.Category == "" {
			sources[i].Meta.Category = "linux"
		}
	}
	return sources
}

func platformHost() (map[string]string, bool) {
	host, _ := os.Hostname()
	return map[string]string{"hostname": host, "os": runtime.GOOS, "arch": runtime.GOARCH}, os.Geteuid() == 0
}

func platformFreeBytes(dir string) (uint64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, false
	}
	return st.Bavail * uint64(st.Bsize), true
}

func selectPlatformSources(sources []collector.Source, input *bufio.Reader, output *os.File) ([]collector.Source, error) {
	return selectSourcesCLI(sources, input, output)
}
