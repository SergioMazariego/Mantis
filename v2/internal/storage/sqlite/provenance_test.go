package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SergioMazariego/Mantis/v2/internal/acquisition"
	"github.com/SergioMazariego/Mantis/v2/internal/auth"
)

func TestCitationResolvesToManifestAndBlobDigest(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "cases.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	scope := ids(t, "tenant", "case", "lead")
	other := ids(t, "tenant", "other", "lead")
	if err := s.BootstrapCase(ctx, scope, "Case"); err != nil {
		t.Fatal(err)
	}
	if err := s.BootstrapCase(ctx, other, "Other"); err != nil {
		t.Fatal(err)
	}
	m := sampleManifest(acquisition.StatusCompleted)
	write := grant(t, s, scope, auth.ActionIngestEvidence)
	manifestDigest, err := s.PutManifest(ctx, write, scope, m)
	if err != nil {
		t.Fatal(err)
	}
	bad := Artifact{ID: "bad", AssetID: "host-1", AcquisitionID: m.ID,
		EvidenceSHA256: strings.Repeat("c", 64), ArtifactType: "windows.evtx", SourceLocator: "Security"}
	if err := s.PutArtifact(ctx, write, scope, bad); !errors.Is(err, ErrInvalidProvenance) {
		t.Fatalf("unlisted blob accepted: %v", err)
	}
	a := Artifact{ID: "artifact-1", AssetID: "host-1", AcquisitionID: m.ID,
		EvidenceSHA256: m.Outputs[0].EvidenceSHA256, ArtifactType: "windows.evtx", SourceLocator: "Security"}
	if err := s.PutArtifact(ctx, write, scope, a); err != nil {
		t.Fatal(err)
	}
	run := ParserRun{ID: "run-1", ArtifactID: a.ID, ParserName: "native-evtx",
		ParserVersion: "0.1.0", ConfigSHA256: strings.Repeat("d", 64), Status: "SUCCEEDED"}
	if err := s.PutParserRun(ctx, write, scope, run); err != nil {
		t.Fatal(err)
	}
	record := RecordProvenance{ID: "record-1", ParserRunID: run.ID,
		Locator: "record:42", RecordSHA256: strings.Repeat("e", 64)}
	if err := s.PutRecordProvenance(ctx, write, scope, record); err != nil {
		t.Fatal(err)
	}
	citation, err := s.ResolveCitation(ctx, grant(t, s, scope, auth.ActionReadCase), scope, record.ID)
	if err != nil || citation.RecordID != record.ID || citation.RecordLocator != record.Locator ||
		citation.EvidenceSHA256 != a.EvidenceSHA256 || citation.AcquisitionID != m.ID ||
		citation.ParserVersion != run.ParserVersion || citation.ManifestSHA256 != manifestDigest ||
		citation.PlanDigest != m.PlanDigest || citation.CaseID != scope.CaseID().String() {
		t.Fatalf("citation: %+v, %v", citation, err)
	}
	if _, err := s.ResolveCitation(ctx, grant(t, s, other, auth.ActionReadCase), other, record.ID); !errors.Is(err, ErrCitationNotFound) {
		t.Fatalf("cross-case citation: %v", err)
	}
	if _, err := s.ResolveCitation(ctx, grant(t, s, scope, auth.ActionReadCase), other, record.ID); !errors.Is(err, auth.ErrDenied) {
		t.Fatalf("wrong-scope grant: %v", err)
	}
	for _, table := range []string{"artifacts", "parser_runs", "record_provenance"} {
		if _, err := s.db.Exec("DELETE FROM " + table); err == nil {
			t.Fatalf("deleted %s", table)
		}
	}
}

func TestFailedParserCannotCreateRecord(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "cases.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	scope := ids(t, "tenant", "case", "lead")
	if err := s.BootstrapCase(ctx, scope, "Case"); err != nil {
		t.Fatal(err)
	}
	m := sampleManifest(acquisition.StatusCompleted)
	write := grant(t, s, scope, auth.ActionIngestEvidence)
	if _, err := s.PutManifest(ctx, write, scope, m); err != nil {
		t.Fatal(err)
	}
	a := Artifact{ID: "artifact-1", AssetID: m.AssetID, AcquisitionID: m.ID,
		EvidenceSHA256: m.Outputs[0].EvidenceSHA256, ArtifactType: "windows.evtx", SourceLocator: "Security"}
	if err := s.PutArtifact(ctx, write, scope, a); err != nil {
		t.Fatal(err)
	}
	run := ParserRun{ID: "run-1", ArtifactID: a.ID, ParserName: "native-evtx",
		ParserVersion: "0.1.0", ConfigSHA256: strings.Repeat("d", 64), Status: "FAILED"}
	if err := s.PutParserRun(ctx, write, scope, run); err != nil {
		t.Fatal(err)
	}
	err = s.PutRecordProvenance(ctx, write, scope, RecordProvenance{ID: "record-1", ParserRunID: run.ID,
		Locator: "record:42", RecordSHA256: strings.Repeat("e", 64)})
	if !errors.Is(err, ErrInvalidProvenance) {
		t.Fatalf("failed run yielded record: %v", err)
	}
}
