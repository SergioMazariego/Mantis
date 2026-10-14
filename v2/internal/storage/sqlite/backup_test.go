package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrationFailurePreservesSourceAndVerifiedBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "case.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`CREATE TABLE artifacts (id TEXT)`,
		`INSERT INTO artifacts(id) VALUES('preserved')`,
		`PRAGMA user_version=3`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("conflicting migration succeeded")
	}
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version int
	var preserved string
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 3 {
		t.Fatalf("source schema changed: %d, %v", version, err)
	}
	if err := db.QueryRow(`SELECT id FROM artifacts`).Scan(&preserved); err != nil || preserved != "preserved" {
		t.Fatalf("source data changed: %q, %v", preserved, err)
	}
	backups, err := filepath.Glob(filepath.Join(dir, ".case.sqlite.pre-v3-*.sqlite"))
	if err != nil || len(backups) != 1 {
		t.Fatalf("retained backup: %v, %v", backups, err)
	}
	if err := verifySQLiteFile(backups[0], 3); err != nil {
		t.Fatalf("backup invalid: %v", err)
	}
}

func TestRestoreRejectsTamperedBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "source.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE contents(value TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version=1`); err != nil {
		t.Fatal(err)
	}
	backup, err := makeMigrationBackup(db, path, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(backup.Path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("tamper")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "restored.sqlite")
	if err := RestoreBackup(context.Background(), backup, target); !errors.Is(err, ErrBackupIntegrity) {
		t.Fatalf("tampered backup restored: %v", err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("restore created target: %v", err)
	}
}

func TestBackupReceiptTamperRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "source.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version=1`); err != nil {
		t.Fatal(err)
	}
	backup, err := makeMigrationBackup(db, path, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup.Path+".sha256", []byte("1\n"+strings.Repeat("0", 64)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBackupInfo(backup.Path); !errors.Is(err, ErrBackupIntegrity) {
		t.Fatalf("tampered receipt accepted: %v", err)
	}
}
