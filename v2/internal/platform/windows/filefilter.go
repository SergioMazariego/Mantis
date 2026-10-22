//go:build windows

package windows

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// FileFilter narrows which files of the Windows Temp folder are acquired. A file is kept when it satisfies every
// condition that is set; Extensions and Types together form one condition (a file matches if either does).
// The zero value keeps everything.
type FileFilter struct {
	Extensions    []string  // ".exe", ".dll": matched on the file name
	Types         []string  // executable, library, script, archive, document, shortcut: matched on the name or on the content signature
	MaxFileBytes  int64     // 0: no limit beyond the collector's own
	ModifiedSince time.Time // zero: any age
	MaxFiles      int       // 0: collector default
	MaxDepth      int       // 0: collector default
}

// fileTypeExtensions maps a type to the extensions that identify it by name.
var fileTypeExtensions = map[string][]string{
	"executable": {".exe", ".scr", ".com", ".pif", ".cpl", ".msi", ".msp"},
	"library":    {".dll", ".sys", ".ocx", ".drv"},
	"script":     {".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".py", ".sh"},
	"archive":    {".zip", ".rar", ".7z", ".cab", ".iso", ".img", ".gz", ".tar", ".jar"},
	"document":   {".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".xlsb", ".ppt", ".pptx", ".pptm", ".rtf", ".pdf", ".one"},
	"shortcut":   {".lnk", ".url"},
}

// signatures identify a type by the first bytes of the file, so a payload renamed to .tmp or .dat is still found.
var signatures = []struct {
	magic []byte
	types []string
}{
	{[]byte("MZ"), []string{"executable", "library"}}, // PE: the header does not tell an EXE from a DLL without parsing it
	{[]byte("PK\x03\x04"), []string{"archive", "document"}},
	{[]byte("Rar!"), []string{"archive"}},
	{[]byte("7z\xbc\xaf\x27\x1c"), []string{"archive"}},
	{[]byte("MSCF"), []string{"archive"}},
	{[]byte{0x1f, 0x8b}, []string{"archive"}},
	{[]byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}, []string{"document"}}, // OLE2: legacy Office, MSI
	{[]byte("%PDF"), []string{"document"}},
	{[]byte("{\\rtf"), []string{"document"}},
	{[]byte{'L', 0, 0, 0, 0x01, 0x14, 0x02, 0}, []string{"shortcut"}},
	{[]byte("#!"), []string{"script"}},
}

// KnownFileTypes lists the type names a FileFilter accepts.
func KnownFileTypes() []string {
	out := make([]string, 0, len(fileTypeExtensions))
	for t := range fileTypeExtensions {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Active reports whether any condition narrows the selection.
func (f FileFilter) Active() bool {
	return len(f.Extensions) > 0 || len(f.Types) > 0 || f.MaxFileBytes > 0 || !f.ModifiedSince.IsZero() || f.MaxFiles > 0 || f.MaxDepth > 0
}

// Describe is the human-readable statement of what was asked for, recorded with the evidence.
func (f FileFilter) Describe() string {
	var parts []string
	if len(f.Extensions) > 0 {
		parts = append(parts, "extensions "+strings.Join(f.Extensions, ","))
	}
	if len(f.Types) > 0 {
		parts = append(parts, "types "+strings.Join(f.Types, ",")+" (by name or content signature)")
	}
	if f.MaxFileBytes > 0 {
		parts = append(parts, fmt.Sprintf("files up to %d MiB", f.MaxFileBytes>>20))
	}
	if !f.ModifiedSince.IsZero() {
		parts = append(parts, "modified since "+f.ModifiedSince.UTC().Format(time.RFC3339))
	}
	if f.MaxFiles > 0 {
		parts = append(parts, fmt.Sprintf("at most %d files", f.MaxFiles))
	}
	if f.MaxDepth > 0 {
		parts = append(parts, fmt.Sprintf("depth %d", f.MaxDepth))
	}
	return strings.Join(parts, "; ")
}

// NormalizeFileFilter validates the names and returns the filter in canonical form.
func NormalizeFileFilter(f FileFilter) (FileFilter, error) {
	seen := map[string]bool{}
	var exts []string
	for _, e := range f.Extensions {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		if strings.ContainsAny(e[1:], `.\/*?`) || len(e) < 2 {
			return f, fmt.Errorf("invalid file extension %q", e)
		}
		if !seen[e] {
			seen[e] = true
			exts = append(exts, e)
		}
	}
	var types []string
	for _, t := range f.Types {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		if _, ok := fileTypeExtensions[t]; !ok {
			return f, fmt.Errorf("unknown file type %q (use %s)", t, strings.Join(KnownFileTypes(), ", "))
		}
		if !seen["type:"+t] {
			seen["type:"+t] = true
			types = append(types, t)
		}
	}
	f.Extensions, f.Types = exts, types
	return f, nil
}

// keep decides whether a file is acquired. Content is read only when the name alone cannot decide a type match.
func (f FileFilter) keep(path string, info os.FileInfo) bool {
	if f.MaxFileBytes > 0 && info.Size() > f.MaxFileBytes {
		return false
	}
	if !f.ModifiedSince.IsZero() && info.ModTime().Before(f.ModifiedSince) {
		return false
	}
	if len(f.Extensions) == 0 && len(f.Types) == 0 {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	for _, e := range f.Extensions {
		if e == ext {
			return true
		}
	}
	for _, t := range f.Types {
		for _, e := range fileTypeExtensions[t] {
			if e == ext {
				return true
			}
		}
	}
	if len(f.Types) == 0 || info.Size() == 0 {
		return false
	}
	head := readHead(path)
	for _, sig := range signatures {
		if !bytes.HasPrefix(head, sig.magic) {
			continue
		}
		for _, st := range sig.types {
			for _, want := range f.Types {
				if st == want {
					return true
				}
			}
		}
	}
	return false
}

// readHead returns the first bytes of a file with a shared read; empty when it cannot be read.
func readHead(path string) []byte {
	h, err := directOpen(path)
	if err != nil {
		return nil
	}
	defer h.Close()
	buf := make([]byte, 8)
	n, _ := io.ReadFull(h, buf)
	return buf[:n]
}

// tempFilterSeen records, per file path, whether the Temp filter kept it, so the package states how much was left out.
var tempFilterSeen sync.Map

// TempFilterReport describes the Temp filter and its effect, or "" when no filter was applied.
func TempFilterReport() string {
	f := currentOptions().TempFilter
	if !f.Active() {
		return ""
	}
	var seen, kept int
	tempFilterSeen.Range(func(_, v any) bool {
		seen++
		if v.(bool) {
			kept++
		}
		return true
	})
	if seen == 0 {
		return "Windows Temp filter configured (" + f.Describe() + "); the folder was not enumerated"
	}
	return fmt.Sprintf("Windows Temp acquired with a filter (%s): %d of %d files met it, %d were left out on purpose", f.Describe(), kept, seen, seen-kept)
}
