package collector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/SergioMazariego/Mantis/v2/internal/evidence"
	"github.com/SergioMazariego/Mantis/v2/internal/ingest"
)

func TestClassifyDistinguishesForensicOutcomes(t *testing.T) {
	ready := func(size int64, notes map[string]string) ItemResult {
		return ItemResult{Result: ingest.Result{Ready: true, Blob: evidence.Blob{SizeBytes: size}}, Notes: notes}
	}
	cases := []struct {
		name string
		item ItemResult
		want Disposition
	}{
		{"collected", ready(10, nil), Collected},
		{"empty source", ready(0, nil), Empty},
		{"warnings", ready(10, map[string]string{"warnings": "3"}), CollectedWarnings},
		{"zero warnings is clean", ready(10, map[string]string{"warnings": "0"}), Collected},
		{"cancelled", ItemResult{Err: context.Canceled}, DispCancelled},
		{"not present", ItemResult{Err: fmt.Errorf("x: %w", ErrNotPresent)}, DispNotPresent},
		{"empty group is not present", ItemResult{Err: ErrNoSources}, DispNotPresent},
		{"not supported", ItemResult{Err: fmt.Errorf("x: %w", ErrNotSupported)}, DispNotSupported},
		{"access denied", ItemResult{Err: fmt.Errorf("x: %w", ErrAccessDenied)}, DispAccessDenied},
		{"locked is a failure, not absence", ItemResult{Err: ErrLocked}, DispFailed},
		{"generic error", ItemResult{Err: errors.New("boom")}, DispFailed},
		{"not ready without error", ItemResult{}, DispFailed},
		{"error beats ready flag", ItemResult{Result: ingest.Result{Ready: true}, Err: errors.New("late")}, DispFailed},
	}
	for _, tc := range cases {
		if got := tc.item.Classify(); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestSelectProfileNeverIncludesSensitiveWithoutConfirmation(t *testing.T) {
	mk := func(id string, mask ProfileMask, sensitive bool) Source {
		return Source{ID: id, Meta: Meta{Profiles: mask, Sensitive: sensitive}}
	}
	all := []Source{mk("quick", InAll, false), mk("std", InStdFull, false), mk("full", InFullOnly, false), mk("dump", InFullOnly, true), mk("custom", 0, false)}
	ids := func(s []Source) string {
		out := ""
		for _, x := range s {
			out += x.ID + ","
		}
		return out
	}
	if got := ids(SelectProfile(all, ProfileQuick, false)); got != "quick," {
		t.Errorf("quick: %s", got)
	}
	if got := ids(SelectProfile(all, ProfileStandard, true)); got != "quick,std," {
		t.Errorf("standard: %s", got)
	}
	if got := ids(SelectProfile(all, ProfileFull, false)); got != "quick,std,full," {
		t.Errorf("full without confirmation must skip sensitive: %s", got)
	}
	if got := ids(SelectProfile(all, ProfileFull, true)); got != "quick,std,full,dump," {
		t.Errorf("full with confirmation: %s", got)
	}
	if got := SelectProfile(all, ProfileCustom, true); len(got) != 0 {
		t.Errorf("custom has no members of its own: %v", got)
	}
	if p, ok := ParseProfile("Full-Forensic"); !ok || p != ProfileFull {
		t.Errorf("ParseProfile: %v %v", p, ok)
	}
	if _, ok := ParseProfile("nonsense"); ok {
		t.Error("unknown profile accepted")
	}
}

func TestRunnerDeduplicatesOverlappingGroupsAndClampsBudget(t *testing.T) {
	runner, scope := newObservedRunner(t)
	shared := fixtureSource("shared", "aa")
	groupA := Source{ID: "ga", Kind: "fixture.group", Locator: "fixture://ga", Method: "test", MaxBytes: 16, Meta: Meta{Category: "execution", Privilege: PrivAdmin, Profiles: InAll},
		Expand: func(context.Context) ([]Source, error) { return []Source{shared, fixtureSource("only-a", "bb")}, nil }}
	groupB := Source{ID: "gb", Kind: "fixture.group", Locator: "fixture://gb", Method: "test", MaxBytes: 16,
		Expand: func(context.Context) ([]Source, error) { return []Source{shared, fixtureSource("only-b", "cc")}, nil }}
	big := fixtureSource("big-limit", "dd")
	big.MaxBytes = 1 << 40 // larger than the plan budget: must be clamped, not rejected
	plan := Plan{ID: "plan-dedupe", AssetID: "host", Profile: "fixture", MaxTotalBytes: 64, Sources: []Source{groupA, groupB, big}}
	var started []string
	results, err := runner.RunObserved(context.Background(), scope, plan, func(e Event) {
		if e.Kind == EventSourceStarted {
			started = append(started, e.Source.ID)
		}
	})
	if err != nil {
		t.Fatalf("overlapping groups must not invalidate the plan: %v", err)
	}
	if len(results) != 4 || len(started) != 4 {
		t.Fatalf("expected shared item acquired once (4 items), got %d results, started %v", len(results), started)
	}
	for _, r := range results {
		if r.Classify() != Collected {
			t.Errorf("%s: %s (%v)", r.SourceID, r.Classify(), r.Err)
		}
		if r.Method == "" || r.Locator == "" {
			t.Errorf("%s: method/locator missing from the result", r.SourceID)
		}
		if r.AcquiredAt.IsZero() {
			t.Errorf("%s: acquisition time missing", r.SourceID)
		}
	}
	// metadata of the group parent is inherited by its children
	for _, r := range results {
		if r.SourceID == "only-a" && (r.Meta.Category != "execution" || r.Meta.Privilege != PrivAdmin) {
			t.Errorf("child did not inherit group metadata: %+v", r.Meta)
		}
	}
}

type reportingReader struct {
	io.Reader
	method string
	notes  map[string]string
}

func (r *reportingReader) Close() error                        { return nil }
func (r *reportingReader) AcquisitionMethod() string           { return r.method }
func (r *reportingReader) AcquisitionNotes() map[string]string { return r.notes }

func TestRunnerRecordsReaderReportedMethodAndNotes(t *testing.T) {
	runner, scope := newObservedRunner(t)
	src := Source{ID: "reported", Kind: "fixture.bytes", Locator: "fixture://reported", Method: "declared-method", MaxBytes: 64,
		Open: func(context.Context) (io.ReadCloser, error) {
			return &reportingReader{Reader: strings.NewReader("xyz"), method: "actual-method", notes: map[string]string{"warnings": "1", "warning_detail": "partial"}}, nil
		}}
	plan := Plan{ID: "plan-method", AssetID: "host", Profile: "fixture", MaxTotalBytes: 64, Sources: []Source{src}}
	results, err := runner.Run(context.Background(), scope, plan)
	if err != nil || len(results) != 1 {
		t.Fatalf("run: %v %v", results, err)
	}
	r := results[0]
	if r.Method != "actual-method" {
		t.Errorf("the method the reader actually used must be recorded, got %q", r.Method)
	}
	if r.Classify() != CollectedWarnings || r.Notes["warning_detail"] != "partial" {
		t.Errorf("reader notes must reach the item and mark it as collected with warnings: %s %v", r.Classify(), r.Notes)
	}
}
