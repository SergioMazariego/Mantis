//go:build windows

package windows

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	defaultFileMax int64 = 4 << 30   // single-file ceiling (hives, EVTX, databases)
	smallFileMax   int64 = 256 << 20 // logs, lnk, xml, small databases
)

func short(s string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(s)))
	return hex.EncodeToString(sum[:4])
}

func baseMeta(name, desc, category string, priv collector.Privilege, profiles collector.ProfileMask, artifacts ...string) collector.Meta {
	return collector.Meta{Name: name, Description: desc, Category: category, Privilege: priv, Profiles: profiles, Artifacts: artifacts,
		Windows: "Windows 10, Windows 11 (build 19041+); Server not tested"}
}

// ---- single files ----

// fileSource acquires one file or NTFS stream, preserving its original path in the package.
func fileSource(id string, m collector.Meta, path string, max int64) collector.Source {
	if max <= 0 {
		max = defaultFileMax
	}
	m.SourceType, m.SourcePath = "file", path
	if m.DestPath == "" {
		m.DestPath = destFor(m.Category, path)
	}
	return collector.Source{
		ID: id, Kind: "windows.file", Locator: path, Method: "file-copy/direct-or-raw", MaxBytes: max, Meta: m,
		Open: func(ctx context.Context) (io.ReadCloser, error) { return openFile(ctx, path) },
		Detect: func(context.Context) collector.Availability {
			ok, _, err := fileInfo(stripStream(path))
			switch {
			case err != nil:
				return collector.Availability{State: collector.Unknown, Reason: err.Error()}
			case !ok:
				return collector.Availability{State: collector.NotPresent, Reason: "file not found"}
			}
			return collector.Availability{State: collector.Available}
		},
		Estimate: func(context.Context) int64 {
			_, n, _ := fileInfo(stripStream(path))
			return n
		},
	}
}

func stripStream(path string) string {
	// "C:\x\file:stream": a colon after the drive designator marks an alternate data stream
	if len(path) > 2 {
		if i := strings.LastIndexByte(path[2:], ':'); i >= 0 {
			return path[:i+2]
		}
	}
	return path
}

// ---- directory groups ----

type walkSpec struct {
	Roots    func() []string                    // directories to walk (evaluated lazily)
	Match    func(rel string, name string) bool // select files by name; nil = every file
	MaxFiles int
	MaxDepth int
	FileMax  int64
	SkipDir  func(rel string) bool
	Filter   func(path string, info os.FileInfo) bool // operator-chosen narrowing applied after Match; nil keeps everything
}

// walkGroup creates a group source whose children are the matching files, each
// acquired as its own raw artifact. Truncation and unreadable directories are
// reported as explicit gap items, never silently dropped.
func walkGroup(id string, m collector.Meta, locator string, spec walkSpec) collector.Source {
	if spec.MaxFiles == 0 {
		spec.MaxFiles = 5000
	}
	if spec.MaxDepth == 0 {
		spec.MaxDepth = 12
	}
	if spec.FileMax == 0 {
		spec.FileMax = smallFileMax
	}
	m.SourceType = "file"
	if m.SourcePath == "" {
		m.SourcePath = locator
	}
	return collector.Source{
		ID: id, Kind: "windows.file_group", Locator: locator, Method: "directory-walk+file-copy/direct-or-raw", MaxBytes: spec.FileMax, Meta: m,
		Detect: func(context.Context) collector.Availability {
			for _, r := range spec.Roots() {
				if dirExists(r) {
					return collector.Availability{State: collector.Available}
				}
			}
			return collector.Availability{State: collector.NotPresent, Reason: "no matching directory on this host"}
		},
		Estimate: func(ctx context.Context) int64 {
			var total int64
			n := 0
			for _, r := range spec.Roots() {
				walkFiles(ctx, r, spec, func(_ string, size int64) bool {
					total += size
					n++
					return n < 2000
				})
			}
			return total
		},
		Expand: func(ctx context.Context) ([]collector.Source, error) {
			var out []collector.Source
			var gaps []string
			gapsDenied := true // stays true only while every gap is an access-denied directory
			count := 0
			for _, root := range spec.Roots() {
				truncated, denied := walkFilesStatus(ctx, root, spec, func(path string, _ int64) bool {
					count++
					if count > spec.MaxFiles {
						return false
					}
					cm := collector.Meta{Name: filepath.Base(path), Category: m.Category}
					child := fileSource(id+"-"+short(path), cm, path, spec.FileMax)
					out = append(out, child)
					return true
				})
				if truncated != "" {
					gaps = append(gaps, root+": "+truncated)
					if !denied {
						gapsDenied = false
					}
				}
			}
			if count > spec.MaxFiles {
				gaps = append(gaps, fmt.Sprintf("enumeration stopped after %d files (limit)", spec.MaxFiles))
				gapsDenied = false
			}
			if len(out) == 0 && len(gaps) == 0 {
				return nil, fmt.Errorf("%w: no matching files", collector.ErrNotPresent)
			}
			if len(gaps) > 0 {
				msg := strings.Join(gaps, "; ")
				out = append(out, collector.Source{ID: id + "-enumeration-gap", Kind: "windows.collection_gap", Locator: locator,
					Method: "directory-walk", MaxBytes: 1, Meta: collector.Meta{Name: m.Name + " (gap)", Category: m.Category, DestPath: m.Category + "/gaps/" + id + ".txt"},
					Open: func(context.Context) (io.ReadCloser, error) {
						if gapsDenied {
							return nil, fmt.Errorf("%w: enumeration incomplete: %s", collector.ErrAccessDenied, msg)
						}
						return nil, errors.New("enumeration incomplete: " + msg)
					}})
			}
			return out, nil
		},
	}
}

// walkFiles visits regular, non-reparse files under root. fn returns false to stop.
// It returns a non-empty string describing why enumeration was incomplete.
func walkFiles(ctx context.Context, root string, spec walkSpec, fn func(path string, size int64) bool) string {
	problems, _ := walkFilesStatus(ctx, root, spec, fn)
	return problems
}

// walkFilesStatus is walkFiles plus whether every recorded problem was an access-denied error,
// which the caller reports as access_denied (an expected outcome without elevation) rather than failed.
func walkFilesStatus(ctx context.Context, root string, spec walkSpec, fn func(path string, size int64) bool) (string, bool) {
	var problems []string
	deniedOnly := true
	note := func(format string, args ...any) {
		if len(problems) < 5 {
			problems = append(problems, fmt.Sprintf(format, args...))
		}
	}
	noteErr := func(err error, format string, args ...any) {
		if !errors.Is(classifyErr(err), collector.ErrAccessDenied) {
			deniedOnly = false
		}
		note(format, args...)
	}
	var walk func(dir string, depth int) bool
	walk = func(dir string, depth int) bool {
		if ctx.Err() != nil {
			return false
		}
		entries, err := os.ReadDir(extended(dir))
		if err != nil {
			if !errors.Is(classifyErr(err), collector.ErrNotPresent) {
				noteErr(err, "unreadable directory %s: %v", dir, err)
			}
			return true
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, e := range entries {
			path := filepath.Join(dir, e.Name())
			rel, _ := filepath.Rel(root, path)
			if e.IsDir() {
				if spec.MaxDepth < 0 {
					continue // flat by design: subdirectories are intentionally not part of this group
				}
				if depth >= spec.MaxDepth {
					deniedOnly = false
					note("depth limit reached at %s", path)
					continue
				}
				if e.Type()&os.ModeSymlink != 0 {
					continue
				}
				if reparse, err := reparseState(path); err != nil {
					noteErr(err, "cannot inspect %s: %v", path, err)
					continue
				} else if reparse {
					continue // junctions and mount points are never followed
				}
				if spec.SkipDir != nil && spec.SkipDir(rel) {
					continue
				}
				if !walk(path, depth+1) {
					return false
				}
				continue
			}
			if !e.Type().IsRegular() {
				continue
			}
			if spec.Match != nil && !spec.Match(rel, e.Name()) {
				continue
			}
			info, err := e.Info()
			if err != nil {
				noteErr(err, "unreadable entry %s: %v", path, err)
				continue
			}
			if spec.Filter != nil && !spec.Filter(path, info) {
				continue
			}
			if !fn(path, info.Size()) {
				return false
			}
		}
		return true
	}
	walk(root, 0)
	return strings.Join(problems, "; "), deniedOnly && len(problems) > 0
}

// reparseState reports whether path is a reparse point; an error means it could not be inspected.
func reparseState(path string) (bool, error) {
	p, err := windows.UTF16PtrFromString(extended(path))
	if err != nil {
		return false, err
	}
	a, err := windows.GetFileAttributes(p)
	if err != nil {
		return false, err
	}
	return a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0, nil
}

func isReparse(path string) bool {
	p, err := windows.UTF16PtrFromString(extended(path))
	if err != nil {
		return true
	}
	a, err := windows.GetFileAttributes(p)
	return err != nil || a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

// ---- user profiles ----

type userProfile struct {
	SID    string
	Name   string
	Path   string
	Loaded bool // HKEY_USERS\<SID> is loaded (live user registry available)
}

// userProfiles enumerates local profiles from ProfileList and C:\Users, merged by path.
func userProfiles() []userProfile {
	byPath := map[string]*userProfile{}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE); err == nil {
		defer k.Close()
		sids, _ := k.ReadSubKeyNames(-1)
		for _, sid := range sids {
			sk, err := registry.OpenKey(k, sid, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			p, _, _ := sk.GetStringValue("ProfileImagePath")
			sk.Close()
			if p == "" {
				continue
			}
			p = expandEnv(p)
			if !strings.HasPrefix(sid, "S-1-5-21") && !strings.HasPrefix(sid, "S-1-12-1") {
				continue // system service profiles are not user activity
			}
			byPath[strings.ToLower(p)] = &userProfile{SID: sid, Name: filepath.Base(p), Path: p}
		}
	}
	if entries, err := os.ReadDir(systemDrive() + `\Users`); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			switch strings.ToLower(e.Name()) {
			case "all users", "default user", "public", "desktop.ini":
				continue
			}
			p := filepath.Join(systemDrive()+`\Users`, e.Name())
			if _, ok := byPath[strings.ToLower(p)]; !ok && !isReparse(p) {
				byPath[strings.ToLower(p)] = &userProfile{Name: e.Name(), Path: p}
			}
		}
	}
	loaded := loadedUserSIDs()
	out := make([]userProfile, 0, len(byPath))
	for _, up := range byPath {
		up.Loaded = loaded[up.SID]
		out = append(out, *up)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func loadedUserSIDs() map[string]bool {
	out := map[string]bool{}
	k, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return out
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	for _, n := range names {
		if strings.HasSuffix(n, "_Classes") {
			continue
		}
		if strings.HasPrefix(n, "S-1-5-21") || strings.HasPrefix(n, "S-1-12-1") {
			out[n] = true
		}
	}
	return out
}

func expandEnv(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return s
	}
	buf := make([]uint16, 32768)
	n, err := windows.ExpandEnvironmentStrings(p, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || int(n) > len(buf) {
		return s
	}
	return windows.UTF16ToString(buf[:n])
}

// perUser returns "<profile>\<sub>" for every profile where the directory exists.
func perUser(sub string) []string {
	var out []string
	for _, up := range userProfiles() {
		p := filepath.Join(up.Path, sub)
		if dirExists(p) {
			out = append(out, p)
		}
	}
	return out
}

// perUserRoots returns lazily evaluated roots for walkSpec.
func perUserRoots(sub string) func() []string { return func() []string { return perUser(sub) } }

func staticRoots(paths ...string) func() []string {
	return func() []string { return paths }
}

// perUserFiles creates one raw-copy source per existing "<profile>\<rel>" file,
// resolved when the catalog is built. Files missing for every profile produce a
// single placeholder that reports not_present, so the gap is explicit.
func perUserFileGroup(id string, m collector.Meta, rels []string) collector.Source {
	m.SourceType = "file"
	return collector.Source{
		ID: id, Kind: "windows.file_group", Locator: `%USERPROFILE%\` + strings.Join(rels, " | "), Method: "per-profile-file-copy/direct-or-raw",
		MaxBytes: defaultFileMax, Meta: m,
		Detect: func(context.Context) collector.Availability {
			for _, up := range userProfiles() {
				for _, rel := range rels {
					if ok, _, _ := fileInfo(filepath.Join(up.Path, rel)); ok {
						return collector.Availability{State: collector.Available}
					}
				}
			}
			return collector.Availability{State: collector.NotPresent, Reason: "no profile has these files"}
		},
		Expand: func(context.Context) ([]collector.Source, error) {
			var out []collector.Source
			for _, up := range userProfiles() {
				for _, rel := range rels {
					p := filepath.Join(up.Path, rel)
					if ok, _, _ := fileInfo(p); ok {
						cm := collector.Meta{Name: up.Name + `\` + rel, Category: m.Category}
						out = append(out, fileSource(id+"-"+short(p), cm, p, defaultFileMax))
					}
				}
			}
			if len(out) == 0 {
				return nil, fmt.Errorf("%w: none of the files exist for any profile", collector.ErrNotPresent)
			}
			return out, nil
		},
	}
}

// ---- structured (JSON) snapshots ----

// warnings collects non-fatal problems while a structured snapshot is built, so a
// partial acquisition is visible instead of hidden behind a success status.
type warnings struct{ items []string }

func (w *warnings) add(format string, args ...any) {
	if len(w.items) < 200 {
		w.items = append(w.items, fmt.Sprintf(format, args...))
	}
}

type jsonDoc struct {
	Schema     string   `json:"schema"`
	Kind       string   `json:"kind"`
	CapturedAt string   `json:"captured_at_utc"`
	Host       string   `json:"host"`
	Data       any      `json:"data"`
	Warnings   []string `json:"warnings,omitempty"`
}

type jsonReader struct {
	*bytes.Reader
	method string
	notes  map[string]string
}

func (j *jsonReader) Close() error                        { return nil }
func (j *jsonReader) AcquisitionMethod() string           { return j.method }
func (j *jsonReader) AcquisitionNotes() map[string]string { return j.notes }

// jsonSource builds a source whose bytes are a JSON document produced by fn.
// fn may return a value together with warnings; a non-nil error fails the source.
func jsonSource(id string, m collector.Meta, method, locator string, fn func(ctx context.Context, w *warnings) (any, error)) collector.Source {
	m.SourceType = orStr(m.SourceType, "api")
	m.SourcePath = orStr(m.SourcePath, locator)
	if m.DestPath == "" {
		m.DestPath = m.Category + "/" + id + ".json"
	}
	return collector.Source{
		ID: id, Kind: "windows.snapshot", Locator: locator, Method: method, MaxBytes: 512 << 20, Meta: m,
		Open: func(ctx context.Context) (io.ReadCloser, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			w := &warnings{}
			data, err := fn(ctx, w)
			if err != nil {
				return nil, classifyErr(err)
			}
			host, _ := os.Hostname()
			raw, err := json.MarshalIndent(jsonDoc{Schema: "mantis.snapshot/1", Kind: id, CapturedAt: time.Now().UTC().Format(time.RFC3339Nano),
				Host: host, Data: data, Warnings: w.items}, "", " ")
			if err != nil {
				return nil, err
			}
			notes := map[string]string{"warnings": fmt.Sprint(len(w.items))}
			if len(w.items) > 0 {
				notes["warning_detail"] = strings.Join(w.items[:min(len(w.items), 5)], " | ")
			}
			return &jsonReader{Reader: bytes.NewReader(raw), method: method, notes: notes}, nil
		},
	}
}

func orStr(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// available is a Detect probe that always reports availability (API snapshots).
func available(context.Context) collector.Availability {
	return collector.Availability{State: collector.Available}
}

// withDetect attaches a probe to a source.
func withDetect(s collector.Source, d func(context.Context) collector.Availability) collector.Source {
	s.Detect = d
	return s
}

func requiresAdmin(s collector.Source) collector.Source {
	if s.Meta.Privilege != collector.PrivDebug {
		s.Meta.Privilege = collector.PrivAdmin
	}
	prev := s.Detect
	s.Detect = func(ctx context.Context) collector.Availability {
		if prev != nil {
			if a := prev(ctx); a.State != collector.Available {
				return a
			}
		}
		if !IsElevated() {
			return collector.Availability{State: collector.NeedsAdmin, Reason: "requires an elevated administrator token"}
		}
		return collector.Availability{State: collector.Available}
	}
	return s
}

// sensitiveFullOnly moves a source out of the default profiles: it is collected only when the
// operator selects it explicitly and confirms the stated risk.
func sensitiveFullOnly(s collector.Source, why string) collector.Source {
	s.Meta.Sensitive = true
	s.Meta.Profiles = collector.InFullOnly
	s.Meta.SideEffects = why
	return s
}
