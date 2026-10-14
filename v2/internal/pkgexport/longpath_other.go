//go:build !windows

package pkgexport

func longPath(p string) string { return p }
