package state

import (
	"context"
	"testing"
)

// Moving items to a folder is one PUT /api/ciphers/move, after which the
// synced vault has them there; nil moves them to No Folder.
func TestMoveCiphersToAFolder(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	ctx := context.Background()

	if err := svc.MoveCiphers(ctx, []string{"c-1"}, nil); err != nil {
		t.Fatal(err)
	}
	if c, err := svc.GetCipher("c-1"); err != nil || c.FolderID != nil {
		t.Fatalf("after moving to No Folder: %+v, %v", c, err)
	}
	folder := "f-work"
	if err := svc.MoveCiphers(ctx, []string{"c-1"}, &folder); err != nil {
		t.Fatal(err)
	}
	if c, err := svc.GetCipher("c-1"); err != nil || c.FolderID == nil || *c.FolderID != folder {
		t.Fatalf("after moving to Work: %+v, %v", c, err)
	}
	env.mu.Lock()
	moves := env.moves
	env.mu.Unlock()
	if moves != 2 {
		t.Fatalf("%d move requests, want 2", moves)
	}
}
