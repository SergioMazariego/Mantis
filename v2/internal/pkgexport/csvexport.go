package pkgexport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CSV views are a convenience for analysts who have no viewer: flat tables derived from the JSON snapshots that
// were just written into the package. They are not evidence. Every row names the artifact it comes from, that
// artifact's SHA-256 and the exact element it was read from, so any cell can be traced back to the JSON.

// Derived describes a file that was computed from artifacts of the package (it is not acquired evidence).
type Derived struct {
	Path          string   `json:"path"`
	Kind          string   `json:"kind"`
	FromArtifacts []string `json:"from_artifacts"`
	Rows          int      `json:"rows"`
	SizeBytes     int64    `json:"size_bytes"`
	SHA256        string   `json:"sha256"`
}

type csvCol struct{ Header, Path string }

type csvTable struct {
	Name    string   // file name without extension
	Source  string   // artifact ID, or
	Method  string   // every artifact acquired with this method (registry dumps)
	Rows    string   // dotted path of the array of rows inside the document
	Explode string   // field of each row that holds an array: one CSV row per element (the outer row fills Parent)
	Parent  []csvCol // columns from the outer row when exploding
	Columns []csvCol // columns from the row (or from the element when exploding; Path "" is the element itself)
}

func cols(paths ...string) []csvCol {
	out := make([]csvCol, len(paths))
	for i, p := range paths {
		out[i] = csvCol{Header: strings.ReplaceAll(p, ".", "_"), Path: p}
	}
	return out
}

var imageCols = []string{"path", "exists", "size_bytes", "modified_utc", "md5", "sha1", "sha256", "pe_sha1", "pe_sha256", "imphash",
	"authenticode", "authenticode_result", "signer", "company", "description", "product_name", "file_version", "file_version_numeric", "original_filename", "error"}

var csvTables = []csvTable{
	{Name: "processes", Source: "processes-detailed", Rows: "data.processes", Columns: cols("pid", "parent_pid", "parent_state", "parent_name", "name",
		"image_path", "command_line", "created_utc", "collected_utc", "session_id", "user", "user_sid", "integrity_level", "token_elevated", "token_type",
		"impersonation_level", "elevation_type", "logon_session_id", "app_container", "privileges_enabled", "protection", "architecture",
		"current_directory", "peb_image_path", "peb_image_matches", "window_title", "threads", "handle_count", "working_set_bytes", "private_bytes",
		"image.sha256", "image.md5", "image.sha1", "image.imphash", "image.authenticode", "image.signer", "image.company", "image.product_name",
		"image.file_version", "image.original_filename", "inaccessible")},
	{Name: "process_modules", Source: "processes-detailed", Rows: "data.processes", Explode: "modules",
		Parent: []csvCol{{"pid", "pid"}, {"process", "name"}}, Columns: cols("name", "path", "base", "size")},
	{Name: "process_performance", Source: "processes-performance", Rows: "data.processes", Columns: cols("pid", "parent_pid", "name", "base_priority",
		"threads", "handle_count", "session_id", "created_utc", "user_time_100ns", "kernel_time_100ns", "virtual_bytes", "private_bytes",
		"working_set_bytes", "page_faults", "hard_faults", "io_read_bytes", "io_write_bytes", "io_other_bytes")},
	{Name: "process_threads", Source: "processes-performance", Rows: "data.processes", Explode: "thread_detail",
		Parent: []csvCol{{"pid", "pid"}, {"process", "name"}}, Columns: cols("tid", "state", "wait_reason", "priority", "base_priority",
			"context_switches", "start_address", "win32_start_address", "stack_base", "stack_limit", "teb_base", "created_utc",
			"user_time_100ns", "kernel_time_100ns")},
	{Name: "process_handles", Source: "processes-handles", Rows: "data.handles", Columns: cols("pid", "process", "handle", "type", "access",
		"access_flags", "name", "target_pid", "target_process", "flags")},
	{Name: "process_memory_regions", Source: "processes-memory-map", Rows: "data.processes", Explode: "executable",
		Parent: []csvCol{{"pid", "pid"}, {"process", "name"}}, Columns: cols("base", "size", "type", "protect", "alloc_protect", "file", "rwx",
			"unbacked_executable", "mz_header")},
	{Name: "module_images", Source: "processes-module-images", Rows: "data.images", Columns: cols(append(append([]string{}, imageCols...), "loaded_by_count", "loaded_by")...)},
	{Name: "persistence_entries", Source: "persistence-enriched", Rows: "data.entries", Columns: cols("category", "location", "entry", "profile",
		"enabled", "launch_string", "image_path", "launcher_path", "time_utc", "key_time_utc", "entry_description")},
	{Name: "persistence_images", Source: "persistence-enriched", Rows: "data.images", Columns: cols(imageCols...)},
	{Name: "services", Source: "system-services", Rows: "data.services", Columns: cols("name", "display_name", "service_type", "current_state",
		"process_id", "start_type", "binary_path", "service_start_name", "description", "error")},
	{Name: "drivers", Source: "system-loaded-drivers", Rows: "data.drivers", Columns: cols("image_base", "path")},
	{Name: "software", Source: "system-software", Rows: "data.entries", Columns: cols("source", "key", "last_write_utc", "values.DisplayName",
		"values.DisplayVersion", "values.Publisher", "values.InstallDate", "values.InstallLocation", "values.InstallSource", "values.UninstallString")},
	{Name: "network_connections", Source: "network-connections", Rows: "data.sockets", Columns: cols("protocol", "family", "state",
		"local_address", "local_port", "remote_address", "remote_port", "pid", "process")},
	{Name: "network_interfaces", Source: "network-interfaces", Rows: "data.adapters", Columns: cols("name", "description", "index", "mac", "mtu",
		"if_type", "oper_status", "dns_suffix", "unicast_addresses", "dns_servers", "gateways", "dhcpv4_enabled")},
	{Name: "dns_cache", Source: "network-dns-cache", Rows: "data.entries", Columns: cols("name", "type", "type_name", "data_length", "flags")},
	{Name: "dns_answers", Source: "network-dns-cache", Rows: "data.entries", Explode: "records",
		Parent: []csvCol{{"cache_name", "name"}}, Columns: cols("name", "type_name", "ttl_seconds", "address", "target")},
	{Name: "registry_values", Method: "registry-api-dump", Rows: "data.keys", Explode: "values",
		Parent:  []csvCol{{"key_path", "path"}, {"key_last_write_utc", "last_write_utc"}},
		Columns: cols("name", "type", "size", "text", "strings", "number", "redacted", "truncated")},
}

// maxCSVSourceBytes bounds the JSON a view decodes in memory; larger snapshots are left to a streaming viewer.
const maxCSVSourceBytes = 256 << 20

// writeCSVViews writes csv/<view>.csv for every view whose source artifacts were collected into dir. A view that
// fails is reported and skipped; the others are still written.
func writeCSVViews(ctx context.Context, dir string, arts []Artifact) ([]Derived, error) {
	var out []Derived
	var errs []error
	for _, t := range csvTables {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		var src []Artifact
		for _, a := range arts {
			if a.Destination == "" || !strings.HasSuffix(a.Destination, ".json") {
				continue
			}
			if (t.Source != "" && a.ID == t.Source) || (t.Method != "" && a.Method == t.Method) {
				src = append(src, a)
			}
		}
		if len(src) == 0 {
			continue
		}
		sort.Slice(src, func(i, j int) bool { return src[i].ID < src[j].ID })
		d, err := writeCSVTable(ctx, dir, t, src)
		if err != nil {
			errs = append(errs, fmt.Errorf("csv %s: %w", t.Name, err))
			continue
		}
		out = append(out, d)
	}
	return out, errors.Join(errs...)
}

// writeCSVTable writes one view to a staging file and moves it into csv/ only when complete, so a failed view
// never leaves a partial file in the package.
func writeCSVTable(ctx context.Context, dir string, t csvTable, src []Artifact) (Derived, error) {
	rel := "csv/" + t.Name + ".csv"
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(longPath(filepath.Dir(path)), 0o755); err != nil {
		return Derived{}, err
	}
	tmp, err := stagingPath(dir)
	if err != nil {
		return Derived{}, err
	}
	f, err := os.OpenFile(longPath(tmp), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return Derived{}, err
	}
	done := false
	defer func() {
		f.Close()
		if !done {
			os.Remove(longPath(tmp))
		}
	}()
	h := sha256.New()
	counter := &countingWriter{w: io.MultiWriter(f, h)}
	if _, err := counter.Write([]byte("\xEF\xBB\xBF")); err != nil { // UTF-8 BOM so spreadsheet tools keep the accents
		return Derived{}, err
	}
	w := csv.NewWriter(counter)
	w.UseCRLF = true // RFC 4180
	header := []string{"source_artifact_id", "source_sha256", "source_pointer"}
	for _, c := range t.Parent {
		header = append(header, c.Header)
	}
	for _, c := range t.Columns {
		header = append(header, c.Header)
	}
	if err := w.Write(header); err != nil {
		return Derived{}, err
	}
	d := Derived{Path: rel, Kind: "csv"}
	for _, a := range src {
		if err := ctx.Err(); err != nil {
			return Derived{}, err
		}
		if a.SizeBytes > maxCSVSourceBytes {
			return Derived{}, fmt.Errorf("%s: %d bytes is above the %d MiB a CSV view decodes in memory", a.ID, a.SizeBytes, maxCSVSourceBytes>>20)
		}
		doc, err := readJSONDoc(filepath.Join(dir, filepath.FromSlash(a.Destination)))
		if err != nil {
			return Derived{}, fmt.Errorf("%s: %w", a.ID, err)
		}
		d.FromArtifacts = append(d.FromArtifacts, a.ID)
		rv := lookupPath(doc, t.Rows)
		rows, isList := rv.([]any)
		if !isList && rv != nil {
			// a changed structure must fail loudly: an empty table would read as "nothing was found"
			return Derived{}, fmt.Errorf("%s: %s is not a list (data_version %d)", a.ID, t.Rows, a.DataVersion)
		}
		for i, row := range rows {
			if t.Explode == "" {
				rec := []string{a.ID, a.SHA256, fmt.Sprintf("%s[%d]", t.Rows, i)}
				for _, c := range t.Columns {
					rec = append(rec, cell(lookupPath(row, c.Path)))
				}
				if err := w.Write(rec); err != nil {
					return Derived{}, err
				}
				d.Rows++
				continue
			}
			inner, _ := lookupPath(row, t.Explode).([]any)
			for j, el := range inner {
				rec := []string{a.ID, a.SHA256, fmt.Sprintf("%s[%d].%s[%d]", t.Rows, i, t.Explode, j)}
				for _, c := range t.Parent {
					rec = append(rec, cell(lookupPath(row, c.Path)))
				}
				for _, c := range t.Columns {
					rec = append(rec, cell(lookupPath(el, c.Path)))
				}
				if err := w.Write(rec); err != nil {
					return Derived{}, err
				}
				d.Rows++
			}
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return Derived{}, err
	}
	d.SizeBytes, d.SHA256 = counter.n, hex.EncodeToString(h.Sum(nil))
	if err := f.Close(); err != nil {
		return Derived{}, err
	}
	if _, err := os.Lstat(longPath(path)); err == nil {
		return Derived{}, fmt.Errorf("%s already exists in the package", rel)
	}
	if err := os.Rename(longPath(tmp), longPath(path)); err != nil {
		return Derived{}, err
	}
	done = true
	return d, nil
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func readJSONDoc(path string) (any, error) {
	raw, err := os.ReadFile(longPath(path))
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep 64-bit values (addresses, FILETIMEs, byte counts) exact
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// lookupPath walks a dotted path through decoded JSON objects; "" returns v itself.
func lookupPath(v any, path string) any {
	if path == "" {
		return v
	}
	for _, part := range strings.Split(path, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[part]
	}
	return v
}

// cell renders a JSON value as one CSV cell: scalars as text, arrays of scalars joined with "; ", objects as
// compact JSON. Line breaks are escaped and formula prefixes neutralized, because every value comes from the
// examined host and may have been crafted to run when the CSV is opened in a spreadsheet.
func cell(v any) string {
	var s string
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		s = x
	case json.Number: // a JSON number cannot carry a formula; a leading '-' is just a sign
		return x.String()
	case bool:
		if x {
			return "true"
		}
		return "false"
	case []any:
		parts := make([]string, 0, len(x))
		scalar := true
		for _, e := range x {
			switch e.(type) {
			case map[string]any, []any:
				scalar = false
			}
			parts = append(parts, fmt.Sprint(e))
		}
		if scalar {
			s = strings.Join(parts, "; ")
		} else {
			b, _ := json.Marshal(x)
			s = string(b)
		}
	default:
		b, _ := json.Marshal(x)
		s = string(b)
	}
	return neutralize(s)
}

// neutralize escapes line breaks and prefixes cells that a spreadsheet would evaluate as a formula.
func neutralize(s string) string {
	s = strings.NewReplacer("\r\n", `\n`, "\n", `\n`, "\r", `\r`).Replace(s)
	if s != "" && strings.ContainsRune("=+-@\t", rune(s[0])) {
		return "'" + s
	}
	return s
}
