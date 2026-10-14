//go:build windows

package pkgexport

import (
	"path/filepath"
	"strings"
)

// longPath adds the extended-length prefix so deep original paths preserved in
// the package do not hit MAX_PATH. Relative paths are made absolute first.
func longPath(p string) string {
	if p == "" || strings.HasPrefix(p, `\\?\`) {
		return p
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if strings.HasPrefix(abs, `\\`) { // UNC
		return `\\?\UNC\` + abs[2:]
	}
	return `\\?\` + abs
}
