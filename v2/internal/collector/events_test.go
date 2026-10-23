package collector

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"

	"github.com/SergioMazariego/Mantis/v2/internal/auth"
	"github.com/SergioMazariego/Mantis/v2/internal/casecore"
	"github.com/SergioMazariego/Mantis/v2/internal/evidence"
	"github.com/SergioMazariego/Mantis/v2/internal/ingest"
	"github.com/SergioMazariego/Mantis/v2/internal/storage/sqlite"
)

func newObservedRunner(t *testing.T) (*Runner, casecore.Scope) {
	t.Helper()
	tenant, _ := casecore.NewTenantID("tenant")
	caseID, _ := casecore.NewCaseID("events-test")
	actor, _ := casecore.NewActorID("analyst")
	scope, _ := casecore.NewScope(tenant, caseID, actor)
	dir := t.TempDir()
	db, err := sqlite.Open(filepath.Join(dir, "case.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.BootstrapCase(context.Background(), scope, "Events Test"); err != nil {
		t.Fatal(err)
	}
	authorizer, err := auth.NewAuthorizer(db)
	if err != nil {
		t.Fatal(err)
	}
	blobs, err := evidence.OpenStore(filepath.Join(dir, "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := ingest.New(context.Background(), authorizer, blobs, db)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewRunner(service)
	if err != nil {
		t.Fatal(err)
	}
	return runner, scope
}

func fixtureSource(id, data string) Source {
	return Source{ID: id, Kind: "fixture.bytes", Locator: "fixture://" + id, Method: "test", MaxBytes: 16, Open: func(context.Context) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader([]byte(data))), nil
	}}
}

func TestRunObservedReportsExpandedPlanAndEachSource(t *testing.T) {
	runner, scope := newObservedRunner(t)
	group := Source{ID: "group", Kind: "fixture.group", Locator: "fixture://group", Method: "test", MaxBytes: 16,
		Expand: func(context.Context) ([]Source, error) {
			return []Source{fixtureSource("group-01", "aa"), fixtureSource("group-02", "bb")}, nil
		}}
	plan := Plan{ID: "plan-events", AssetID: "host", Profile: "fixture", MaxTotalBytes: 64, Sources: []Source{fixtureSource("solo", "cc"), group}}
	var events []Event
	results, err := runner.RunObserved(context.Background(), scope, plan, func(e Event) { events = append(events, e) })
	if err != nil || len(results) != 3 {
		t.Fatalf("run: %+v %v", results, err)
	}
	if len(events) != 7 || events[0].Kind != EventPlanReady || len(events[0].Planned) != 3 {
		t.Fatalf("unexpected events: %+v", events)
	}
	if events[0].Planned[1].ID != "group-01" {
		t.Fatalf("group not expanded in plan: %+v", events[0].Planned)
	}
	for i := 0; i < 3; i++ {
		started, finished := events[1+2*i], events[2+2*i]
		if started.Kind != EventSourceStarted || finished.Kind != EventSourceFinished || started.Index != i || finished.Index != i {
			t.Fatalf("source %d events out of order: %+v %+v", i, started, finished)
		}
		if finished.Item.Err != nil || !finished.Item.Result.Ready {
			t.Fatalf("source %d not ready: %+v", i, finished.Item)
		}
	}
}

func TestRunObservedStopsOnCancellation(t *testing.T) {
	runner, scope := newObservedRunner(t)
	ctx, cancel := context.WithCancel(context.Background())
	plan := Plan{ID: "plan-cancel", AssetID: "host", Profile: "fixture", MaxTotalBytes: 64, Sources: []Source{fixtureSource("a", "11"), fixtureSource("b", "22"), fixtureSource("c", "33")}}
	finished := 0
	results, err := runner.RunObserved(ctx, scope, plan, func(e Event) {
		if e.Kind == EventSourceFinished {
			finished++
			cancel() // cancel after the first source completes
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if finished != 1 || len(results) != 3 || !results[0].Result.Ready {
		t.Fatalf("first source must be preserved and the others still reported: finished=%d results=%+v", finished, results)
	}
	// sources that never started are reported as cancelled, never silently dropped from the manifest
	for _, r := range results[1:] {
		if r.Classify() != DispCancelled || r.Result.Ready || r.Locator == "" {
			t.Errorf("unstarted source %s must be reported as cancelled: %+v", r.SourceID, r)
		}
	}
}

func TestPerSourceLimitDoesNotExhaustTheWholeBudget(t *testing.T) {
	runner, scope := newObservedRunner(t)
	big := fixtureSource("big", "0123456789")
	big.MaxBytes = 4 // fails on its own limit, far below the plan budget
	plan := Plan{ID: "plan-budget", AssetID: "host", Profile: "fixture", MaxTotalBytes: 1 << 20, Sources: []Source{big, fixtureSource("after", "22")}}
	results, err := runner.RunObserved(context.Background(), scope, plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].Result.Ready {
		t.Fatalf("the oversized source must fail: %+v", results)
	}
	if !results[1].Result.Ready || errors.Is(results[1].Err, ErrTotalBudgetExceeded) {
		t.Fatalf("a source after one that exceeded its own limit must still be collected: %+v", results[1])
	}
}
