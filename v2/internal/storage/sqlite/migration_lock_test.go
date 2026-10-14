package sqlite

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestMigrationLockBlocksConcurrentOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "case.sqlite")
	release, err := acquireMigrationLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); !errors.Is(err, ErrStoreBusy) {
		t.Fatalf("concurrent open should fail closed: %v", err)
	}
	release()
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}
