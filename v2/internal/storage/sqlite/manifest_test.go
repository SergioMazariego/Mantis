package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SergioMazariego/Mantis/v2/internal/acquisition"
	"github.com/SergioMazariego/Mantis/v2/internal/auth"
)

func sampleManifest(status acquisition.Status) acquisition.Manifest {
	m := acquisition.Manifest{
		Version: 1, Kind: "acquisition-manifest", ID: "acq-1", CaseID: "case", AssetID: "host-1", PlanDigest: strings.Repeat("a", 64),
		SourceKind: "windows.evtx", SourceLocator: "Security", SourceClock: acquisition.SourceClock{Status: "REPORTED", Description: "UTC from source"},
		Method: "native-copy-v1", Status: status, StartedAt: "2026-01-01T00:00:00Z",
		CompletedAt: "2026-01-01T00:00:01Z", Outputs: []acquisition.Output{{EvidenceSHA256: strings.Repeat("b", 64), SizeBytes: 6, SourceLocator: "Security"}},
	}
	if status == acquisition.StatusPartial {
		m.Errors = []string{"source read interrupted"}
	}
	if status == acquisition.StatusFailed {
		m.Outputs = nil
		m.Errors = []string{"source unavailable"}
	}
	return m
}

func TestManifestPersistsAndIsAppendOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cases.sqlite")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	scope := ids(t, "tenant", "case", "lead")
	if err := s.BootstrapCase(ctx, scope, "Case"); err != nil {
		t.Fatal(err)
	}
	m := sampleManifest(acquisition.StatusPartial)
	digest, err := s.PutManifest(ctx, grant(t, s, scope, auth.ActionIngestEvidence), scope, m)
	if err != nil || len(digest) != 64 {
		t.Fatalf("persist manifest: %q, %v", digest, err)
	}
	if _, err := s.PutManifest(ctx, grant(t, s, scope, auth.ActionIngestEvidence), scope, m); err == nil {
		t.Fatal("duplicate acquisition accepted")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.GetManifest(ctx, grant(t, s, scope, auth.ActionReadCase), scope, m.ID)
	if err != nil || got.Status != acquisition.StatusPartial || len(got.Errors) != 1 {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
	other := ids(t, "tenant", "other", "lead")
	if _, err := s.GetManifest(ctx, grant(t, s, scope, auth.ActionReadCase), other, m.ID); !errors.Is(err, auth.ErrDenied) {
		t.Fatalf("cross-case read: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE acquisition_manifests SET manifest_sha256='changed'`); err == nil {
		t.Fatal("manifest update accepted")
	}
	if _, err := s.db.Exec(`DELETE FROM acquisition_manifests`); err == nil {
		t.Fatal("manifest delete accepted")
	}
	events, err := s.VerifyAudit(ctx, grant(t, s, scope, auth.ActionReadCase), scope)
	if err != nil || len(events) != 2 {
		t.Fatalf("audit: %d, %v", len(events), err)
	}
}

func TestMigrateVersionOneToFive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`CREATE TABLE cases (tenant_id TEXT NOT NULL, case_id TEXT NOT NULL, title TEXT NOT NULL, PRIMARY KEY (tenant_id,case_id))`,
		`CREATE TABLE case_memberships (tenant_id TEXT, case_id TEXT, actor_id TEXT, role TEXT, active INTEGER, revision INTEGER)`,
		`CREATE TABLE audit_events (tenant_id TEXT, case_id TEXT, event_no INTEGER, actor_id TEXT, operation TEXT, target_id TEXT, occurred_at TEXT, previous_hash TEXT, event_hash TEXT)`,
		`PRAGMA user_version=1`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO cases(tenant_id,case_id,title) VALUES('tenant','case','Legacy case')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	backup := s.MigrationBackup()
	if backup.Path == "" || backup.SchemaVersion != 1 || len(backup.SHA256) != 64 {
		t.Fatalf("missing verified pre-migration backup: %+v", backup)
	}
	loaded, err := LoadBackupInfo(backup.Path)
	if err != nil || loaded != backup {
		t.Fatalf("persisted backup receipt: %+v, %v", loaded, err)
	}
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 5 {
		t.Fatalf("migration version %d, %v", version, err)
	}
	restored := filepath.Join(t.TempDir(), "restored.sqlite")
	if err := RestoreBackup(context.Background(), backup, restored); err != nil {
		t.Fatal(err)
	}
	if err := verifySQLiteFile(restored, 1); err != nil {
		t.Fatalf("restored snapshot: %v", err)
	}
	copyDB, err := sql.Open("sqlite", restored)
	if err != nil {
		t.Fatal(err)
	}
	defer copyDB.Close()
	var title string
	if err := copyDB.QueryRow(`SELECT title FROM cases WHERE tenant_id='tenant' AND case_id='case'`).Scan(&title); err != nil || title != "Legacy case" {
		t.Fatalf("restored data: %q, %v", title, err)
	}
	if err := RestoreBackup(context.Background(), backup, restored); !errors.Is(err, ErrInvalidRestoreTarget) {
		t.Fatalf("existing target overwritten: %v", err)
	}
}
