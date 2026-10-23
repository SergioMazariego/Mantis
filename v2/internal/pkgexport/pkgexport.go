// Package pkgexport writes the portable, self-describing evidence package:
// category folders with the acquired artifacts, a versioned manifest, an
// acquisition report and error register, and a SHA-256 checksum file that is
// re-verified from disk before the package is declared consistent.
package pkgexport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
)

// Schema identifiers are versioned; consumers must check them.
const (
	ManifestSchema = "mantis.evidence-package/1"
	ReportSchema   = "mantis.acquisition-report/1"
	ErrorsSchema   = "mantis.acquisition-errors/1"
)

// Options describes one package to write.
type Options struct {
	Dir          string // package root; created if missing
	CaseID       string
	TenantID     string
	HostID       string
	Host         map[string]string // hostname, windows build, architecture, timezone...
	ToolVersion  string
	Profile      string
	Privilege    string // "admin" or "user": what the collector actually ran with
	StartedAt    time.Time
	FinishedAt   time.Time
	Items        []collector.ItemResult
	GlobalNotes  []string // run-level warnings (not elevated, skipped sources, limits)
	SelectedOnly bool     // true when the operator chose a subset (always recorded)
	CSV          bool     // also write csv/ views derived from the JSON snapshots (for analysts without a viewer)

	// Open returns a verified reader for a stored blob by SHA-256.
	Open func(ctx context.Context, sha256hex string) (io.ReadCloser, error)
}

// Artifact is one manifest record. Items that were not acquired are listed too,
// with their status and error, but never with a hash or destination.
type Artifact struct {
	ID          string            `json:"id"`
	Collector   string            `json:"collector_id"`
	Name        string            `json:"name,omitempty"`
	Category    string            `json:"category"`
	SourceType  string            `json:"source_type,omitempty"`
	ActionTypes []string          `json:"action_types,omitempty"`
	DataVersion int               `json:"data_version,omitempty"` // structure version of a JSON snapshot's data
	SourcePath  string            `json:"source_path,omitempty"`
	Destination string            `json:"destination,omitempty"`
	AcquiredUTC string            `json:"acquired_utc,omitempty"`
	SizeBytes   int64             `json:"size_bytes,omitempty"`
	SHA256      string            `json:"sha256,omitempty"`
	Method      string            `json:"method,omitempty"`
	Status      string            `json:"status"`
	Privilege   string            `json:"required_privilege,omitempty"`
	Windows     string            `json:"windows_versions,omitempty"`
	SideEffects string            `json:"side_effects,omitempty"`
	Coverage    []string          `json:"coverage_ids,omitempty"`
	Notes       map[string]string `json:"notes,omitempty"`
	Error       string            `json:"error,omitempty"`
}

// Summary is what the caller (CLI/GUI) needs after writing.
type Summary struct {
	Dir          string
	ByStatus     map[string]int
	ByCategory   map[string]int
	Files        int
	Bytes        int64
	Verified     bool
	VerifyErrors []string
}

type manifest struct {
	Schema      string            `json:"schema"`
	Tool        map[string]string `json:"tool"`
	CaseID      string            `json:"case_id"`
	TenantID    string            `json:"tenant_id,omitempty"`
	HostID      string            `json:"host_id"`
	Host        map[string]string `json:"host,omitempty"`
	Profile     string            `json:"profile"`
	Privilege   string            `json:"privilege"`
	StartedUTC  string            `json:"started_utc"`
	FinishedUTC string            `json:"finished_utc"`
	Hashing     string            `json:"hash_algorithm"`
	Artifacts   []Artifact        `json:"artifacts"`
	Derived     []Derived         `json:"derived,omitempty"` // files computed from artifacts (CSV views); not evidence
}

// Write exports the package and verifies it. A non-nil Summary is returned even
// on verification failure so the caller can show what went wrong.
func Write(ctx context.Context, o Options) (*Summary, error) {
	if o.Dir == "" || o.Open == nil {
		return nil, errors.New("pkgexport: directory and blob opener are required")
	}
	if err := os.MkdirAll(longPath(o.Dir), 0o755); err != nil {
		return nil, err
	}
	sum := &Summary{Dir: o.Dir, ByStatus: map[string]int{}, ByCategory: map[string]int{}}
	used := map[string]bool{}
	artifacts := make([]Artifact, 0, len(o.Items))
	var issues []map[string]any

	for _, it := range o.Items {
		if err := ctx.Err(); err != nil {
			return sum, err
		}
		disp := it.Classify()
		art := Artifact{
			ID: it.SourceID, Collector: it.SourceID, Name: it.Meta.Name, Category: orDefault(it.Meta.Category, "other"),
			SourceType: it.Meta.SourceType, SourcePath: orDefault(it.Meta.SourcePath, it.Locator), Method: it.Method,
			Status: string(disp), Privilege: string(it.Meta.Privilege), Windows: it.Meta.Windows,
			SideEffects: it.Meta.SideEffects, Coverage: it.Meta.Artifacts, ActionTypes: it.Meta.ActionTypes, DataVersion: it.Meta.DataVersion, Notes: it.Notes,
		}
		if !it.AcquiredAt.IsZero() {
			art.AcquiredUTC = it.AcquiredAt.UTC().Format(time.RFC3339Nano)
		}
		if it.Err != nil {
			art.Error = it.Err.Error()
		}
		if it.Err == nil && it.Result.Ready {
			dest := uniqueDest(art.Category, it, used)
			n, digest, err := copyVerified(ctx, o, filepath.Join(o.Dir, filepath.FromSlash(dest)), it.Result.Blob.SHA256)
			if err != nil {
				art.Status, art.Error = string(collector.DispFailed), "package export: "+err.Error()
				issues = append(issues, issue(art, err.Error()))
			} else {
				art.Destination, art.SizeBytes, art.SHA256 = dest, n, digest
				sum.Files++
				sum.Bytes += n
			}
		} else if disp != collector.Empty {
			issues = append(issues, issue(art, art.Error))
		}
		if disp == collector.CollectedWarnings {
			issues = append(issues, issue(art, "collected with warnings: "+it.Notes["warnings"]+" "+it.Notes["warning_detail"]))
		}
		sum.ByStatus[art.Status]++
		sum.ByCategory[art.Category]++
		artifacts = append(artifacts, art)
	}
	sort.SliceStable(artifacts, func(i, j int) bool {
		if artifacts[i].Category != artifacts[j].Category {
			return artifacts[i].Category < artifacts[j].Category
		}
		return artifacts[i].ID < artifacts[j].ID
	})

	var derived []Derived
	if o.CSV {
		d, err := writeCSVViews(ctx, o.Dir, artifacts)
		derived = d
		if err != nil { // the evidence is complete without the views: record the problem, keep the package
			o.GlobalNotes = append(o.GlobalNotes, "CSV views incomplete: "+err.Error())
		}
		if len(derived) > 0 {
			o.GlobalNotes = append(o.GlobalNotes, fmt.Sprintf("%d CSV views were derived from the JSON snapshots into csv/; they are a convenience, not evidence (see derived in manifest.json)", len(derived)))
		}
	}

	tool := map[string]string{"name": "mantis-collect", "version": o.ToolVersion}
	man := manifest{Schema: ManifestSchema, Tool: tool, CaseID: o.CaseID, TenantID: o.TenantID, HostID: o.HostID, Host: o.Host,
		Profile: o.Profile, Privilege: o.Privilege, StartedUTC: o.StartedAt.UTC().Format(time.RFC3339Nano),
		FinishedUTC: o.FinishedAt.UTC().Format(time.RFC3339Nano), Hashing: "SHA-256", Artifacts: artifacts, Derived: derived}
	report := map[string]any{
		"schema": ReportSchema, "case_id": o.CaseID, "host_id": o.HostID, "profile": o.Profile, "privilege": o.Privilege,
		"started_utc": man.StartedUTC, "finished_utc": man.FinishedUTC,
		"duration_seconds":         o.FinishedAt.Sub(o.StartedAt).Seconds(),
		"totals":                   map[string]any{"artifacts": len(artifacts), "files": sum.Files, "bytes": sum.Bytes, "by_status": sum.ByStatus, "by_category": sum.ByCategory, "derived_files": len(derived)},
		"operator_selected_subset": o.SelectedOnly,
		"notes":                    o.GlobalNotes,
		"statement": "This package contains only the sources listed in manifest.json. Every source is reported with its own status; " +
			"a finished run does not imply that the endpoint was completely collected. Sources with a status other than 'collected' " +
			"are gaps and are detailed in acquisition-errors.json.",
	}
	errorsDoc := map[string]any{"schema": ErrorsSchema, "case_id": o.CaseID, "issues": issues, "global_notes": o.GlobalNotes}

	for name, doc := range map[string]any{"manifest.json": man, "acquisition-report.json": report, "acquisition-errors.json": errorsDoc} {
		if err := writeJSON(filepath.Join(o.Dir, name), doc); err != nil {
			return sum, err
		}
	}
	if err := writeFile(filepath.Join(o.Dir, "README-PACKAGE.txt"), []byte(readme)); err != nil {
		return sum, err
	}

	checks, err := writeChecksums(ctx, o.Dir)
	if err != nil {
		return sum, err
	}
	sum.VerifyErrors = verify(ctx, o.Dir, checks)
	sum.VerifyErrors = append(sum.VerifyErrors, crossCheck(checks, artifacts, derived)...)
	sum.Verified = len(sum.VerifyErrors) == 0
	ver := map[string]any{"schema": "mantis.package-verification/1", "verified_utc": time.Now().UTC().Format(time.RFC3339Nano),
		"files_checked": len(checks), "ok": sum.Verified, "errors": sum.VerifyErrors}
	if err := writeJSON(filepath.Join(o.Dir, "verification.json"), ver); err != nil {
		return sum, err
	}
	if !sum.Verified {
		return sum, fmt.Errorf("package verification failed for %d file(s)", len(sum.VerifyErrors))
	}
	return sum, nil
}

func issue(a Artifact, msg string) map[string]any {
	return map[string]any{"id": a.ID, "category": a.Category, "status": a.Status, "source": a.SourcePath, "method": a.Method, "message": msg}
}

func orDefault(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}

// ---- destinations ----

var reserved = map[string]bool{"CON": true, "PRN": true, "AUX": true, "NUL": true}

func init() {
	for i := 1; i <= 9; i++ {
		reserved[fmt.Sprintf("COM%d", i)] = true
		reserved[fmt.Sprintf("LPT%d", i)] = true
	}
}

// SanitizeComponent makes one path component safe on Windows and rejects traversal.
func SanitizeComponent(c string) string {
	var b strings.Builder
	for _, r := range c {
		switch {
		case r < 0x20, strings.ContainsRune(`<>:"|?*\/`, r):
			b.WriteRune('_')
		default:
			b.WriteRune(r)
		}
	}
	out := strings.TrimRight(b.String(), ". ")
	if out == "" || out == "." || out == ".." {
		out = "_"
	}
	if len(out) > 150 { // cut on a character boundary: a split UTF-8 sequence becomes U+FFFD on disk and two names collide
		cut := 150
		for cut > 0 && !utf8.RuneStart(out[cut]) {
			cut--
		}
		out = strings.TrimRight(out[:cut], ". ")
		if out == "" {
			out = "_"
		}
	}
	base := strings.ToUpper(out)
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	if reserved[base] {
		out = "_" + out
	}
	return out
}

// SanitizePath sanitizes every component of a slash-separated relative path.
func SanitizePath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	parts := strings.Split(p, "/")
	clean := parts[:0]
	for _, c := range parts {
		if c == "" || c == "." {
			continue
		}
		clean = append(clean, SanitizeComponent(c))
	}
	return strings.Join(clean, "/")
}

func uniqueDest(category string, it collector.ItemResult, used map[string]bool) string {
	dest := SanitizePath(it.Meta.DestPath)
	if dest == "" {
		dest = SanitizePath(category) + "/" + SanitizeComponent(it.SourceID) + ".bin"
	}
	if !used[strings.ToLower(dest)] {
		used[strings.ToLower(dest)] = true
		return dest
	}
	ext := path.Ext(dest)
	stem := strings.TrimSuffix(dest, ext)
	tag := it.Result.Blob.SHA256
	if len(tag) > 8 {
		tag = tag[:8]
	}
	cand := stem + "~" + tag + ext
	for n := 2; used[strings.ToLower(cand)]; n++ {
		cand = fmt.Sprintf("%s~%s-%d%s", stem, tag, n, ext)
	}
	used[strings.ToLower(cand)] = true
	return cand
}

// ---- files ----

func copyVerified(ctx context.Context, o Options, dst, wantSHA string) (int64, string, error) {
	src, err := o.Open(ctx, wantSHA)
	if err != nil {
		return 0, "", err
	}
	defer src.Close()
	if err := os.MkdirAll(longPath(filepath.Dir(dst)), 0o755); err != nil {
		return 0, "", err
	}
	// a destination must never be replaced: two artifacts mapping to one file would leave the manifest describing
	// the first and the disk holding the second
	if _, err := os.Lstat(longPath(dst)); err == nil {
		return 0, "", fmt.Errorf("destination %s already exists in the package", dst)
	}
	tmp, err := stagingPath(o.Dir)
	if err != nil {
		return 0, "", err
	}
	out, err := os.OpenFile(longPath(tmp), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return 0, "", err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(out, h), &ctxReader{ctx: ctx, r: src})
	closeErr := out.Close()
	digest := hex.EncodeToString(h.Sum(nil))
	switch {
	case copyErr != nil:
		os.Remove(longPath(tmp))
		return 0, "", copyErr
	case closeErr != nil:
		os.Remove(longPath(tmp))
		return 0, "", closeErr
	case !strings.EqualFold(digest, wantSHA):
		os.Remove(longPath(tmp))
		return 0, "", fmt.Errorf("blob digest mismatch while exporting: stored %s, exported %s", wantSHA, digest)
	}
	if err := os.Rename(longPath(tmp), longPath(dst)); err != nil {
		os.Remove(longPath(tmp))
		return 0, "", err
	}
	return n, digest, nil
}

var stagingSeq atomic.Int64

// stagingPath returns a fresh temporary file inside the package's own .mantis folder: staged files live outside
// the evidence tree, so no name copied from the examined host can clash with them or hide from the checksums.
func stagingPath(root string) (string, error) {
	dir := filepath.Join(root, ".mantis", "staging")
	if err := os.MkdirAll(longPath(dir), 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, fmt.Sprintf("%d-%d.part", os.Getpid(), stagingSeq.Add(1))), nil
}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

func writeFile(p string, data []byte) error {
	if err := os.MkdirAll(longPath(filepath.Dir(p)), 0o755); err != nil {
		return err
	}
	return os.WriteFile(longPath(p), data, 0o644)
}

func writeJSON(p string, doc any) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(p, append(data, '\n'))
}

// ---- checksums ----

type checkEntry struct{ rel, sha string }

func hashFile(ctx context.Context, p string) (string, error) {
	f, err := os.Open(longPath(p))
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, &ctxReader{ctx: ctx, r: f}); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// listFiles returns every package file except the checksum and verification files.
func listFiles(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			// only the package's own case store is excluded; a ".mantis" folder copied from the host is evidence
			if rel == ".mantis" {
				return filepath.SkipDir
			}
			return nil
		}
		switch rel {
		case "checksums.sha256", "verification.json":
			return nil
		}
		out = append(out, rel)
		return nil
	})
	sort.Strings(out)
	return out, err
}

func writeChecksums(ctx context.Context, dir string) ([]checkEntry, error) {
	files, err := listFiles(dir)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	entries := make([]checkEntry, 0, len(files))
	for _, rel := range files {
		sha, err := hashFile(ctx, filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return nil, fmt.Errorf("checksum %s: %w", rel, err)
		}
		entries = append(entries, checkEntry{rel, sha})
		fmt.Fprintf(&b, "%s *%s\n", sha, rel)
	}
	return entries, writeFile(filepath.Join(dir, "checksums.sha256"), []byte(b.String()))
}

// verify re-reads every file from disk and compares it with the recorded digest,
// and checks that no file appeared or vanished since the checksums were written.
func verify(ctx context.Context, dir string, entries []checkEntry) []string {
	var problems []string
	known := map[string]bool{}
	for _, e := range entries {
		known[e.rel] = true
		sha, err := hashFile(ctx, filepath.Join(dir, filepath.FromSlash(e.rel)))
		switch {
		case err != nil:
			problems = append(problems, e.rel+": "+err.Error())
		case sha != e.sha:
			problems = append(problems, e.rel+": digest changed after export")
		}
	}
	if now, err := listFiles(dir); err == nil {
		for _, rel := range now {
			if !known[rel] {
				problems = append(problems, rel+": file appeared after checksums were written")
			}
		}
	}
	return problems
}

// crossCheck ties the manifest to the disk: every exported artifact and derived file must be in the checksums
// with the digest the manifest records, and every checksummed file must be one the manifest accounts for.
// Without it, a replaced file or a leftover from another run would still verify.
func crossCheck(entries []checkEntry, arts []Artifact, derived []Derived) []string {
	disk := make(map[string]string, len(entries))
	for _, e := range entries {
		disk[e.rel] = e.sha
	}
	known := map[string]bool{"manifest.json": true, "acquisition-report.json": true, "acquisition-errors.json": true, "README-PACKAGE.txt": true}
	var problems []string
	expect := func(rel, sha, what string) {
		known[rel] = true
		got, ok := disk[rel]
		switch {
		case !ok:
			problems = append(problems, rel+": "+what+" in the manifest but missing from the package")
		case !strings.EqualFold(got, sha):
			problems = append(problems, rel+": "+what+" digest on disk differs from the manifest")
		}
	}
	for _, a := range arts {
		if a.Destination != "" {
			expect(a.Destination, a.SHA256, "artifact "+a.ID)
		}
	}
	for _, d := range derived {
		expect(d.Path, d.SHA256, "derived file")
	}
	for _, e := range entries {
		if !known[e.rel] {
			problems = append(problems, e.rel+": file in the package that the manifest does not account for")
		}
	}
	return problems
}

const readme = `MANTIS EVIDENCE PACKAGE
=======================

This folder is a portable acquisition package produced by mantis-collect.

  manifest.json            every source with status, original path, destination, size, SHA-256 and method
  acquisition-report.json  totals by status/category, run metadata and the completeness statement
  acquisition-errors.json  gaps: sources that were not collected, failed, were denied, or collected with warnings
  checksums.sha256         SHA-256 of every file in this package (sha256sum format: "<hex> *<path>")
  verification.json        result of re-hashing the package from disk after export
  <category>/...           the acquired artifacts, preserved byte-for-byte where the method allows
  csv/                     (only with --csv) flat tables derived from the JSON snapshots, for reading without a viewer;
                           not evidence: each row names its source artifact, that artifact's SHA-256 and the element it came from

Verify integrity (PowerShell):   Get-Content checksums.sha256 | ForEach-Object { $h,$p = $_ -split ' \*',2; (Get-FileHash $p -Algorithm SHA256).Hash -ieq $h }
Verify integrity (Linux/macOS):  sha256sum -c checksums.sha256

Status meanings: collected, collected_with_warnings, empty, not_present, not_supported, access_denied, failed, cancelled.
A source that is not 'collected' is a gap; it is never silently omitted.
This package does not interpret the evidence. Parsing and analysis belong to a later stage.
`
