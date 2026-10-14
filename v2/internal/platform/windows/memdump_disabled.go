//go:build windows && !memdump

package windows

import (
	"context"
	"fmt"
	"io"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
)

const memdumpCompiled = false

// dumpProcess is not available in the default build; see memdump_enabled.go.
func dumpProcess(context.Context, uint32) (io.ReadCloser, error) {
	return nil, fmt.Errorf("%w: process memory dumping is not compiled into this binary (build with -tags memdump)", collector.ErrNotSupported)
}

// memoryDumpSource in the default build is only a documented placeholder.
func memoryDumpSource() collector.Source {
	m := baseMeta("Process memory acquisition (optional build feature)", "Not compiled into this binary. An opt-in build variant exists for authorized investigations; it is excluded by default", "memory", collector.PrivDebug, collector.InFullOnly)
	m.Sensitive = true
	return collector.Source{
		ID: "memory-process-dumps", Kind: "windows.memory_group", Locator: "(optional build feature)", Method: "unsupported", MaxBytes: 1, Meta: m,
		Detect: func(context.Context) collector.Availability {
			return collector.Availability{State: collector.NotSupported, Reason: "not compiled into this binary"}
		},
		Open: func(context.Context) (io.ReadCloser, error) {
			return nil, fmt.Errorf("%w: not compiled into this binary", collector.ErrNotSupported)
		},
	}
}
