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

func TestRunnerUsesCaseIngestAndTotalBudget(t *testing.T) {
	tenant, _ := casecore.NewTenantID("tenant")
	caseID, _ := casecore.NewCaseID("collector-test")
	actor, _ := casecore.NewActorID("analyst")
	scope, _ := casecore.NewScope(tenant, caseID, actor)
	dir := t.TempDir()
	db, err := sqlite.Open(filepath.Join(dir, "case.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.BootstrapCase(context.Background(), scope, "Collector Test"); err != nil {
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
	plan := Plan{ID: "plan-run", AssetID: "host-1", Profile: "fixture", MaxTotalBytes: 5, Sources: []Source{
		{ID: "one", Kind: "fixture.bytes", Locator: "fixture://one", Method: "test", MaxBytes: 5, Open: func(context.Context) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader([]byte("1234"))), nil
		}},
		{ID: "two", Kind: "fixture.bytes", Locator: "fixture://two", Method: "test", MaxBytes: 5, Open: func(context.Context) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader([]byte("5678"))), nil
		}},
	}}
	digestA, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	digestB, err := plan.Digest()
	if err != nil || digestA != digestB {
		t.Fatalf("plan digest changed: %s %s %v", digestA, digestB, err)
	}
	results, err := runner.Run(context.Background(), scope, plan)
	if err != nil || len(results) != 2 {
		t.Fatalf("run: %+v %v", results, err)
	}
	if !results[0].Result.Ready || results[0].Err != nil {
		t.Fatalf("first source not ingested: %+v", results[0])
	}
	if !errors.Is(results[1].Err, evidence.ErrTooLarge) || results[1].Result.Status != "FAILED" {
		t.Fatalf("budget overrun not recorded: %+v", results[1])
	}
}

func TestPlanRejectsDuplicateSources(t *testing.T) {
	source := Source{ID: "x", Kind: "fixture.bytes", Locator: "fixture://x", Method: "test", MaxBytes: 1, Open: func(context.Context) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(nil)), nil }}
	plan := Plan{ID: "p", AssetID: "a", Profile: "test", MaxTotalBytes: 1, Sources: []Source{source, source}}
	if _, err := plan.Digest(); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("duplicate source accepted: %v", err)
	}
}
