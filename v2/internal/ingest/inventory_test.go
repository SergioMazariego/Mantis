package ingest

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/SergioMazariego/Mantis/v2/internal/auth"
	"github.com/SergioMazariego/Mantis/v2/internal/casecore"
	"github.com/SergioMazariego/Mantis/v2/internal/evidence"
)

func TestRecoveryInventoryClassifiesAndScopes(t *testing.T) {
	service, _, scope, authorizer, root := setup(t)
	ctx := context.Background()
	known, err := service.CollectOne(ctx, scope, request("known", 1024), bytes.NewBufferString("known bytes"))
	if err != nil {
		t.Fatal(err)
	}
	grant, err := authorizer.Authorize(ctx, scope, auth.ActionIngestEvidence)
	if err != nil {
		t.Fatal(err)
	}
	blobs, err := evidence.OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	orphan, err := blobs.Put(ctx, grant, scope, bytes.NewBufferString("orphan bytes"), 1024)
	if err != nil {
		t.Fatal(err)
	}
	items, err := service.Inventory(ctx, scope)
	if err != nil || len(items) != 2 {
		t.Fatalf("inventory: %+v, %v", items, err)
	}
	states := map[string]string{}
	for _, item := range items {
		states[item.SHA256] = item.Reference + "/" + item.Integrity
	}
	if states[known.Blob.SHA256] != "REFERENCED/VERIFIED" || states[orphan.SHA256] != "ORPHAN/VERIFIED" {
		t.Fatalf("wrong classification: %+v", items)
	}
	otherID, _ := casecore.NewCaseID("other")
	other, _ := casecore.NewScope(scope.TenantID(), otherID, scope.ActorID())
	if _, err := service.Inventory(ctx, other); !errors.Is(err, auth.ErrDenied) {
		t.Fatalf("cross-case inventory: %v", err)
	}
	path := filepath.Join(root, "tenants", scope.TenantID().String(), "cases", scope.CaseID().String(), "blobs", "sha256", orphan.SHA256[:2], orphan.SHA256[2:4], orphan.SHA256)
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("altered"), 0600); err != nil {
		t.Fatal(err)
	}
	items, err = service.Inventory(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.SHA256 == orphan.SHA256 && item.Integrity != "CORRUPT" {
			t.Fatalf("corrupt orphan hidden: %+v", item)
		}
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("inventory deleted orphan: %v", err)
	}
}
