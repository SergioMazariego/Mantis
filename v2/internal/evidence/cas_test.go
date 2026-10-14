package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/SergioMazariego/Mantis/v2/internal/auth"
	"github.com/SergioMazariego/Mantis/v2/internal/casecore"
)

type membershipReader struct{}

func (membershipReader) LookupMembership(_ context.Context, tenant casecore.TenantID, caseID casecore.CaseID, actor casecore.ActorID) (auth.Membership, error) {
	return auth.Membership{TenantID: tenant, CaseID: caseID, ActorID: actor, Role: auth.RoleCaseLead, Active: true}, nil
}

func scopeFor(t *testing.T, tenant, caseID string) casecore.Scope {
	t.Helper()
	tid, err := casecore.NewTenantID(tenant)
	if err != nil {
		t.Fatal(err)
	}
	cid, err := casecore.NewCaseID(caseID)
	if err != nil {
		t.Fatal(err)
	}
	aid, err := casecore.NewActorID("analyst")
	if err != nil {
		t.Fatal(err)
	}
	scope, err := casecore.NewScope(tid, cid, aid)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func grantFor(t *testing.T, scope casecore.Scope, action auth.Action) auth.Grant {
	t.Helper()
	a, err := auth.NewAuthorizer(membershipReader{})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := a.Authorize(context.Background(), scope, action)
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func TestPutOpenImmutableAndScoped(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	scope := scopeFor(t, "tenant-a", "case-1")
	other := scopeFor(t, "tenant-b", "case-1")
	content := []byte("synthetic EVTX fixture bytes")
	digest := sha256.Sum256(content)
	write := grantFor(t, scope, auth.ActionIngestEvidence)
	read := grantFor(t, scope, auth.ActionReadEvidence)
	blob, err := store.Put(ctx, write, scope, bytes.NewReader(content), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if blob.SHA256 != hex.EncodeToString(digest[:]) || blob.SizeBytes != int64(len(content)) {
		t.Fatalf("wrong blob metadata: %+v", blob)
	}
	if _, err := store.Put(ctx, write, scope, bytes.NewReader(content), 1024); err != nil {
		t.Fatalf("idempotent put: %v", err)
	}
	file, err := store.Open(ctx, read, scope, blob.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(file)
	file.Close()
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("wrong bytes: %q, %v", got, err)
	}
	if _, err := store.Open(ctx, read, other, blob.SHA256); !errors.Is(err, auth.ErrDenied) {
		t.Fatalf("cross-tenant grant reuse: %v", err)
	}
	if _, err := store.Open(ctx, grantFor(t, other, auth.ActionReadEvidence), other, blob.SHA256); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cross-tenant blob exposure: %v", err)
	}
	if _, err := store.Open(ctx, write, scope, blob.SHA256); !errors.Is(err, auth.ErrDenied) {
		t.Fatalf("write grant used to read: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(store.root, "tenants", "tenant-a", "cases", "case-1", ".staging"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("staging not clean: %v, %v", entries, err)
	}
}

func TestBudgetFailureAndCorruption(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	scope := scopeFor(t, "tenant", "case")
	ctx := context.Background()
	write := grantFor(t, scope, auth.ActionIngestEvidence)
	if _, err := store.Put(ctx, write, scope, bytes.NewBufferString("123456"), 5); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("budget: %v", err)
	}
	blob, err := store.Put(ctx, write, scope, bytes.NewBufferString("123456"), 6)
	if err != nil {
		t.Fatal(err)
	}
	path := store.blobPath(scope, blob.SHA256)
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("123450"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(ctx, grantFor(t, scope, auth.ActionReadEvidence), scope, blob.SHA256); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("corruption accepted: %v", err)
	}
	if _, err := store.Put(ctx, write, scope, bytes.NewBufferString("123456"), 6); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("corrupt duplicate accepted: %v", err)
	}
}

func TestRejectsInvalidInputs(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	scope := scopeFor(t, "tenant", "case")
	ctx := context.Background()
	if _, err := store.Put(ctx, auth.Grant{}, scope, bytes.NewBufferString("x"), 1); !errors.Is(err, auth.ErrDenied) {
		t.Fatalf("zero grant: %v", err)
	}
	if _, err := store.Open(ctx, grantFor(t, scope, auth.ActionReadEvidence), scope, "../bad"); !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("invalid hash: %v", err)
	}
	closed, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.Put(closed, grantFor(t, scope, auth.ActionIngestEvidence), scope, bytes.NewBufferString("x"), 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled put: %v", err)
	}
}
