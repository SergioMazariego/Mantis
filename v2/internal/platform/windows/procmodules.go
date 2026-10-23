//go:build windows

package windows

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"golang.org/x/sys/windows"
)

// processes-module-images describes every distinct file loaded as a module by any process: hashes, Authenticode
// verdict and signer, company, product, version and import hash, plus which processes loaded it. Unsigned or
// user-writable-path DLLs, side-loading and rare hashes are found here, which the per-process module list cannot show.

// normalizeModulePath removes the \\?\ prefix and expands 8.3 short names so one file has one key.
func normalizeModulePath(p string) string {
	p = strings.TrimPrefix(p, `\\?\`)
	if !strings.Contains(p, "~") {
		return p
	}
	src, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return p
	}
	buf := make([]uint16, 1024)
	n, err := windows.GetLongPathName(src, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || int(n) > len(buf) {
		return p
	}
	return string(utf16.Decode(buf[:n]))
}

type moduleImage struct {
	*enrichedImage
	LoadedByCount int      `json:"loaded_by_count"`
	LoadedBy      []string `json:"loaded_by,omitempty"` // first processes that loaded it, as pid:name
}

func processModuleImages(ctx context.Context, w *warnings) (any, error) {
	enablePrivilege("SeDebugPrivilege")
	names := processNames()
	loaded := map[string]*moduleImage{}
	display := map[string]string{} // lower-case key -> path as normalized
	unreadable := 0
	var failures []string
	for pid, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if pid == 0 || isCredentialProcess(name) { // the module list of lsass/lsaiso is read from its memory: never
			continue
		}
		mods, err := modulesOf(pid)
		if err != nil {
			unreadable++
			if len(failures) < 10 {
				failures = append(failures, fmt.Sprintf("%d:%s (%v)", pid, name, err))
			}
			continue
		}
		for _, m := range mods {
			path := normalizeModulePath(m.Path)
			key := strings.ToLower(path)
			mi := loaded[key]
			if mi == nil {
				mi = &moduleImage{}
				loaded[key] = mi
				display[key] = path
			}
			mi.LoadedByCount++
			if len(mi.LoadedBy) < 10 {
				mi.LoadedBy = append(mi.LoadedBy, fmt.Sprintf("%d:%s", pid, name))
			}
		}
	}
	if unreadable > 0 {
		w.add("modules of %d process(es) could not be listed; their modules are not described: %s", unreadable, strings.Join(failures, "; "))
	}
	keys := make([]string, 0, len(loaded))
	for k := range loaded {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	enr := &imageEnricher{seen: map[string]*enrichedImage{}}
	out := make([]*moduleImage, 0, len(keys))
	for _, k := range keys {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		mi := loaded[k]
		mi.enrichedImage = enr.describe(ctx, display[k])
		out = append(out, mi)
	}
	unsigned := 0
	for _, mi := range out {
		if mi.Exists && !strings.HasPrefix(mi.Authenticode, "valid") {
			unsigned++
		}
	}
	return map[string]any{
		"note":         "every distinct file loaded as a module by a readable process, described once; loaded_by lists up to 10 loading processes",
		"image_count":  len(out),
		"not_verified": unsigned,
		"images":       out}, nil
}

func processModuleImagesSource() collector.Source {
	m := baseMeta("Loaded module images (hashes and signatures)", "Every distinct file loaded as a module by any process, with SHA-256 and other hashes, Authenticode verdict and signer, company, product, version, import hash and the processes that loaded it",
		"processes", collector.PrivDebug, collector.InStdFull)
	m.SideEffects = "lists the modules of other processes (lsass/lsaiso are skipped); reads the module files to hash them (can update last-access times); remote (UNC) modules are recorded, never opened"
	return withDetect(jsonSource("processes-module-images", m, "toolhelp-modules+hash+wintrust", "api://process-module-images", processModuleImages), available)
}
