//go:build windows

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"github.com/SergioMazariego/Mantis/v2/internal/evidence"
	"github.com/SergioMazariego/Mantis/v2/internal/ingest"
	"golang.org/x/sys/windows"
)

func TestClassifyNeverReportsUnpublishedArtifactsAsCollected(t *testing.T) {
	ready := collector.ItemResult{SourceID: "a", Result: ingest.Result{Ready: true, Blob: evidence.Blob{SHA256: strings.Repeat("ab", 32), SizeBytes: 2048}}}
	cases := []struct {
		name string
		item collector.ItemResult
		want itemState
	}{
		{"published", ready, stDone},
		{"not ready without error", collector.ItemResult{SourceID: "b"}, stFailed},
		{"error beats ready flag", collector.ItemResult{SourceID: "c", Result: ready.Result, Err: errors.New("boom")}, stFailed},
		{"cancelled", collector.ItemResult{SourceID: "d", Err: context.Canceled}, stCancelled},
		{"empty group is skipped", collector.ItemResult{SourceID: "e", Err: collector.ErrNoSources}, stSkipped},
		{"budget exhausted is skipped", collector.ItemResult{SourceID: "f", Err: collector.ErrTotalBudgetExceeded}, stSkipped},
		{"access denied is an error", collector.ItemResult{SourceID: "g", Err: windows.ERROR_ACCESS_DENIED}, stFailed},
	}
	for _, tc := range cases {
		if got, _, _ := classify(tc.item); got != tc.want {
			t.Errorf("%s: state %d, want %d", tc.name, got, tc.want)
		}
	}
	if _, result, _ := classify(ready); !strings.Contains(result, "2.0 KB") || !strings.Contains(result, "abababababab") {
		t.Errorf("result should show size and hash prefix: %q", result)
	}
	if _, result, _ := classify(collector.ItemResult{Err: windows.ERROR_ACCESS_DENIED}); !strings.Contains(result, "administrador") {
		t.Errorf("access denied should be actionable: %q", result)
	}
}

func TestBuildCategoriesGroupsByMetaCategory(t *testing.T) {
	mk := func(id, cat string) pickRow {
		return pickRow{src: collector.Source{ID: id, Meta: collector.Meta{Category: cat}}}
	}
	p := &picker{rows: []pickRow{mk("a", "system"), mk("b", "system"), mk("c", "eventlogs"), mk("d", "")}}
	p.buildCategories()
	if len(p.cats) != 3 || p.cats[0].count != 2 || p.cats[0].name != "Sistema" || p.cats[1].name != "Event Logs" {
		t.Fatalf("unexpected categories: %+v", p.cats)
	}
	if p.rows[3].cat != 2 || p.cats[2].key != "other" {
		t.Fatalf("uncategorised sources must land in 'other': %+v", p.cats)
	}
}

func TestClassifyUsesForensicDispositions(t *testing.T) {
	cases := []struct {
		err  error
		want itemState
	}{
		{collector.ErrNotPresent, stSkipped}, {collector.ErrNotSupported, stSkipped}, {collector.ErrAccessDenied, stFailed}, {collector.ErrLocked, stFailed},
	}
	for _, tc := range cases {
		if got, _, _ := classify(collector.ItemResult{SourceID: "x", Err: tc.err}); got != tc.want {
			t.Errorf("%v: state %d, want %d", tc.err, got, tc.want)
		}
	}
	warn := collector.ItemResult{SourceID: "w", Result: ingest.Result{Ready: true, Blob: evidence.Blob{SHA256: strings.Repeat("cd", 32), SizeBytes: 10}}, Notes: map[string]string{"warnings": "2"}}
	if st, res, _ := classify(warn); st != stDone || !strings.Contains(res, "advertencias") {
		t.Errorf("collected with warnings must be visible: %d %q", st, res)
	}
}

func TestFormattingHelpers(t *testing.T) {
	if got := humanBytes(1536); got != "1.5 KB" {
		t.Errorf("humanBytes: %q", got)
	}
	if got := clock(75 * time.Second); got != "01:15" {
		t.Errorf("clock: %q", got)
	}
	if got := shortDur(1200 * time.Millisecond); got != "1.2 s" {
		t.Errorf("shortDur: %q", got)
	}
	if got := uniqueLines("a\nb\na\n\nb"); got != "a\nb" {
		t.Errorf("uniqueLines: %q", got)
	}
}
