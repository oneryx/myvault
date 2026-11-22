package state

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/crypto"
)

func TestService_EmptyTrashSkipsReadOnly(t *testing.T) {
	env := newVaultTestEnv(t)
	deleted := time.Now().UTC().Add(-time.Hour)
	no := false
	name, _ := crypto.EncryptString("Shared Old Note", env.userKey)
	env.ciphers["c-trash-ro"] = api.EncryptedCipher{
		ID: "c-trash-ro", Type: api.CipherTypeSecureNote, Name: name,
		DeletedDate: &deleted, Edit: &no, SecureNote: &api.EncryptedSecureNote{},
	}
	svc := loggedInTestService(t, env)

	res, err := svc.EmptyTrash(context.Background(), svc.TrashSelection())
	if err != nil || res.Deleted != 1 || res.ReadOnly != 1 {
		t.Fatalf("EmptyTrash = (%+v, %v)", res, err)
	}
	env.mu.Lock()
	_, gone := env.ciphers["c-trash"]
	_, kept := env.ciphers["c-trash-ro"]
	env.mu.Unlock()
	if gone || !kept {
		t.Fatalf("server state: c-trash present=%v, c-trash-ro present=%v", gone, kept)
	}
	trash := svc.Search("", SearchFilter{Category: FilterTrash})
	if len(trash) != 1 || trash[0].ID != "c-trash-ro" {
		t.Fatalf("trash after EmptyTrash = %+v", trash)
	}
	if active := svc.Search("", SearchFilter{}); len(active) != 1 {
		t.Fatalf("active items changed: %+v", active)
	}
}

func TestService_EmptyTrashKeepsItemsChangedAfterConfirmation(t *testing.T) {
	env := newVaultTestEnv(t)
	deleted := time.Now().UTC().Add(-time.Hour)
	rev := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	for _, id := range []string{"c-trash-2", "c-trash-3"} {
		name, _ := crypto.EncryptString(id, env.userKey)
		env.ciphers[id] = api.EncryptedCipher{ID: id, Type: api.CipherTypeSecureNote, Name: name, DeletedDate: &deleted, RevisionDate: &rev, SecureNote: &api.EncryptedSecureNote{}}
	}
	svc := loggedInTestService(t, env)
	sel := svc.TrashSelection()
	if len(sel.Items) != 3 {
		t.Fatalf("selection = %+v", sel.Items)
	}

	// After the confirmation, another device restores one item and edits another in Trash.
	later := rev.Add(time.Minute)
	env.mu.Lock()
	restored := env.ciphers["c-trash-2"]
	restored.DeletedDate, restored.RevisionDate = nil, &later
	env.ciphers["c-trash-2"] = restored
	edited := env.ciphers["c-trash-3"]
	edited.RevisionDate = &later
	env.ciphers["c-trash-3"] = edited
	env.mu.Unlock()

	res, err := svc.EmptyTrash(context.Background(), sel)
	if err != nil || res.Deleted != 1 || res.Skipped != 2 {
		t.Fatalf("EmptyTrash = (%+v, %v), want 1 deleted and 2 kept", res, err)
	}
	env.mu.Lock()
	defer env.mu.Unlock()
	if _, ok := env.ciphers["c-trash-2"]; !ok {
		t.Fatal("an item restored on another device was permanently deleted")
	}
	if _, ok := env.ciphers["c-trash-3"]; !ok {
		t.Fatal("an item changed after confirmation was permanently deleted")
	}
	if _, ok := env.ciphers["c-trash"]; ok {
		t.Fatal("the unchanged confirmed item was not deleted")
	}
}

func TestService_EmptyTrashRefusesASelectionFromAnotherAccount(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	sel := svc.TrashSelection()
	sel.AccountID = "someone-else"
	if _, err := svc.EmptyTrash(context.Background(), sel); !errors.Is(err, ErrAccountChanged) {
		t.Fatalf("EmptyTrash = %v, want ErrAccountChanged", err)
	}
	env.mu.Lock()
	defer env.mu.Unlock()
	if _, ok := env.ciphers["c-trash"]; !ok {
		t.Fatal("deleted under a confirmation from another account")
	}
}
