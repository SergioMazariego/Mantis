// Package collector runs versioned, bounded source plans through the normal
// evidence ingest path. Platform providers supply only named, reviewed sources.
package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/SergioMazariego/Mantis/v2/internal/acquisition"
	"github.com/SergioMazariego/Mantis/v2/internal/casecore"
	"github.com/SergioMazariego/Mantis/v2/internal/ingest"
)

var (
	ErrInvalidPlan = errors.New("invalid collection plan")
	ErrNoSources   = errors.New("collection profile has no available sources")
)

const Version = 1

// maxPlanSources bounds the expanded plan. Full-profile groups (tasks, jump lists, recycle bin)
// can legitimately produce tens of thousands of items; overflow is recorded as a gap, never silently dropped.
const maxPlanSources = 200000

type Source struct {
	ID, Kind, Locator, Method string
	MaxBytes                  int64
	Open                      func(context.Context) (io.ReadCloser, error)
	Expand                    func(context.Context) ([]Source, error)

	// Optional forensic metadata and probes. They never change how bytes are
	// acquired; they describe the source and let the UI/package report on it.
	Meta     Meta
	Detect   func(context.Context) Availability
	Estimate func(context.Context) int64 // best-effort size in bytes; <=0 unknown
}

type Plan struct {
	ID, AssetID, Profile string
	MaxTotalBytes        int64
	Sources              []Source
}

type ItemResult struct {
	SourceID string
	Result   ingest.Result
	Err      error

	Meta    Meta              // metadata of the executed (possibly expanded) source
	Kind    string            // source kind
	Locator string            // original source locator
	Method  string            // acquisition method actually used
	Notes   map[string]string // structured notes reported by the reader (warnings, offsets)

	AcquiredAt time.Time // UTC time the item finished
}

func (p Plan) Digest() (string, error) {
	if p.ID == "" || p.AssetID == "" || p.Profile == "" || p.MaxTotalBytes <= 0 || len(p.Sources) == 0 || len(p.Sources) > maxPlanSources {
		return "", ErrInvalidPlan
	}
	type item struct {
		ID       string `json:"id"`
		Kind     string `json:"kind"`
		Locator  string `json:"locator"`
		Method   string `json:"method"`
		MaxBytes int64  `json:"max_bytes"`
	}
	items := make([]item, 0, len(p.Sources))
	seen := map[string]bool{}
	for _, src := range p.Sources {
		if src.ID == "" || seen[src.ID] || strings.TrimSpace(src.Kind) == "" || strings.TrimSpace(src.Locator) == "" || strings.TrimSpace(src.Method) == "" || src.MaxBytes <= 0 || src.MaxBytes > p.MaxTotalBytes || (src.Open == nil && src.Expand == nil) {
			return "", ErrInvalidPlan
		}
		seen[src.ID] = true
		items = append(items, item{src.ID, src.Kind, src.Locator, src.Method, src.MaxBytes})
	}
	data, err := json.Marshal(struct {
		Version       int    `json:"version"`
		ID            string `json:"id"`
		AssetID       string `json:"asset_id"`
		Profile       string `json:"profile"`
		MaxTotalBytes int64  `json:"max_total_bytes"`
		Sources       []item `json:"sources"`
	}{Version, p.ID, p.AssetID, p.Profile, p.MaxTotalBytes, items})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

type Runner struct{ ingest *ingest.Service }

func NewRunner(service *ingest.Service) (*Runner, error) {
	if service == nil {
		return nil, ingest.ErrUnavailable
	}
	return &Runner{ingest: service}, nil
}

// Run executes the plan. It is RunObserved without an observer.
func (r *Runner) Run(ctx context.Context, scope casecore.Scope, plan Plan) ([]ItemResult, error) {
	return r.RunObserved(ctx, scope, plan, nil)
}

// RunObserved executes the plan and reports lifecycle events to observe (may be
// nil). Events never alter acquisition behavior. Cancelling ctx stops before the
// next source and aborts the one in flight at its next read.
func (r *Runner) RunObserved(ctx context.Context, scope casecore.Scope, plan Plan, observe func(Event)) ([]ItemResult, error) {
	if r == nil || r.ingest == nil || ctx == nil || !scope.Valid() {
		return nil, ErrInvalidPlan
	}
	if plan.ID == "" || plan.AssetID == "" || plan.Profile == "" || plan.MaxTotalBytes <= 0 || len(plan.Sources) == 0 || len(plan.Sources) > maxPlanSources {
		return nil, ErrInvalidPlan
	}
	requested := plan.Sources
	plan.Sources = nil
	seenIDs := map[string]bool{}
	appendUnique := func(src Source) {
		if seenIDs[src.ID] { // overlapping groups may yield the same item; acquire it once
			return
		}
		seenIDs[src.ID] = true
		if src.MaxBytes > plan.MaxTotalBytes {
			src.MaxBytes = plan.MaxTotalBytes
		}
		plan.Sources = append(plan.Sources, src)
	}
	for _, source := range requested {
		if source.Expand == nil {
			appendUnique(source)
			continue
		}
		children, expandErr := source.Expand(ctx)
		if expandErr != nil {
			appendUnique(failedSource(source, expandErr))
			continue
		}
		if len(children) == 0 {
			appendUnique(failedSource(source, ErrNoSources))
			continue
		}
		overflow := false
		if room := maxPlanSources - len(plan.Sources); len(children) > room {
			if room < 0 {
				room = 0
			}
			children, overflow = children[:room], true
		}
		for _, child := range children {
			child.Meta = inheritMeta(source.Meta, child.Meta)
			appendUnique(child)
		}
		if overflow {
			capped := source
			capped.ID = source.ID + "-plan-limit-gap"
			capped.Expand = nil
			capped.Meta.Name = source.Meta.Name + " (plan size limit)"
			capped.Meta.DestPath = ""
			cause := fmt.Errorf("the expanded plan reached its limit of %d items; remaining items of %s were not acquired", maxPlanSources, source.ID)
			capped.Open = func(context.Context) (io.ReadCloser, error) { return nil, cause }
			appendUnique(capped)
		}
	}
	digest, err := plan.Digest()
	if err != nil {
		return nil, err
	}
	planned := make([]PlannedSource, len(plan.Sources))
	for i, src := range plan.Sources {
		planned[i] = PlannedSource{ID: src.ID, Kind: src.Kind, Locator: src.Locator}
	}
	emit := func(e Event) {
		if observe != nil {
			e.Time = time.Now()
			observe(e)
		}
	}
	emit(Event{Kind: EventPlanReady, Planned: planned})
	remaining := plan.MaxTotalBytes
	results := make([]ItemResult, 0, len(plan.Sources))
	for i, src := range plan.Sources {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		started := time.Now()
		emit(Event{Kind: EventSourceStarted, Index: i, Source: planned[i]})
		limit := src.MaxBytes
		if remaining < limit {
			limit = remaining
		}
		var reader io.ReadCloser
		var openErr error
		if limit <= 0 {
			// the budget is decided before Open so an exhausted budget never stages or leaks a reader
			limit = src.MaxBytes
			reader = errorReadCloser{err: ErrTotalBudgetExceeded}
			openErr = ErrTotalBudgetExceeded
		} else if reader, openErr = src.Open(ctx); openErr != nil {
			reader = errorReadCloser{err: openErr}
		}
		method := src.Method
		if m, ok := reader.(MethodReporter); ok && openErr == nil {
			if used := m.AcquisitionMethod(); used != "" {
				method = used
			}
		}
		tracked := &countingReader{reader: reader}
		id := fmt.Sprintf("%s-%02d-%d", plan.ID, i, time.Now().UTC().UnixNano())
		result, collectErr := r.ingest.CollectOne(ctx, scope, ingest.Request{
			ID: id, AssetID: plan.AssetID, PlanDigest: digest, SourceKind: clip(src.Kind, 128),
			SourceLocator: clip(src.Locator, 4096), SourceClock: acquisition.SourceClock{Status: "UNKNOWN", Description: "source clock not measured by collector v1"},
			Method: clip(method, 128), MaxBytes: limit,
		}, tracked)
		var notes map[string]string
		if n, ok := reader.(NotesReporter); ok {
			notes = n.AcquisitionNotes()
		}
		closeErr := reader.Close()
		if tracked.count > limit {
			remaining = 0
		} else {
			remaining -= tracked.count
		}
		// a failed Open reaches the ingest and Close paths again through errorReadCloser: report it once
		if openErr != nil {
			if errors.Is(collectErr, openErr) {
				collectErr = nil
			}
			if errors.Is(closeErr, openErr) {
				closeErr = nil
			}
		}
		item := ItemResult{SourceID: src.ID, Result: result, Err: errors.Join(openErr, collectErr, closeErr),
			Meta: src.Meta, Kind: src.Kind, Locator: src.Locator, Method: method, Notes: notes, AcquiredAt: time.Now().UTC()}
		results = append(results, item)
		emit(Event{Kind: EventSourceFinished, Index: i, Source: planned[i], Item: item, Duration: time.Since(started)})
	}
	return results, nil
}

func failedSource(source Source, cause error) Source {
	source.Open = func(context.Context) (io.ReadCloser, error) { return nil, cause }
	source.Expand = nil
	return source
}

var ErrTotalBudgetExceeded = errors.New("collection plan total byte budget exhausted")

type countingReader struct {
	reader io.Reader
	count  int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.count += int64(n)
	return n, err
}

type errorReadCloser struct{ err error }

func (r errorReadCloser) Read([]byte) (int, error) { return 0, r.err }
func (r errorReadCloser) Close() error             { return nil }

// inheritMeta fills empty fields of a child's metadata from its group parent.
func inheritMeta(parent, child Meta) Meta {
	if child.Category == "" {
		child.Category = parent.Category
	}
	if child.SourceType == "" {
		child.SourceType = parent.SourceType
	}
	if child.Windows == "" {
		child.Windows = parent.Windows
	}
	if child.Privilege == "" {
		child.Privilege = parent.Privilege
	}
	if child.Profiles == 0 {
		child.Profiles = parent.Profiles
	}
	if child.SideEffects == "" {
		child.SideEffects = parent.SideEffects
	}
	if child.Description == "" {
		child.Description = parent.Description
	}
	if len(child.Artifacts) == 0 {
		child.Artifacts = parent.Artifacts
	}
	if len(child.ActionTypes) == 0 {
		child.ActionTypes = parent.ActionTypes
	}
	child.Sensitive = child.Sensitive || parent.Sensitive
	return child
}

// clip bounds a string to the manifest field limit so one unusual path cannot fail an acquisition.
func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
