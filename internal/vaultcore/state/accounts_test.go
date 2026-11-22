package state

import (
	"context"
	"errors"
	"testing"

	"github.com/oneryx/myvault/internal/vaultcore/store"
)

func TestService_SwitchBetweenAccounts(t *testing.T) {
	envA := newVaultTestEnv(t)
	envB := newVaultTestEnv(t)
	envB.profileID, envB.accessTok = "acct-b", "tok-b"

	fileStore := store.NewFileStore(t.TempDir())
	secrets := newMemSecretStore()
	var statuses []LockStatus
	svc, err := NewService(ServiceConfig{
		Store: fileStore, Secrets: secrets, HTTPClient: envA.server.Client(),
		OnStatusChange: func(st LockStatus) { statuses = append(statuses, st) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := svc.Login(ctx, LoginRequest{ServerURL: envA.server.URL, Email: envA.email, MasterPassword: envA.password}); err != nil {
		t.Fatalf("Login A: %v", err)
	}

	// Adding an account locks A and leaves no account current.
	if err := svc.SwitchAccount(""); err != nil {
		t.Fatal(err)
	}
	if svc.Status() != StatusLoggedOut || svc.Account().ID != "" || len(svc.Search("", SearchFilter{})) != 0 {
		t.Fatalf("after SwitchAccount(\"\"): status=%v account=%+v", svc.Status(), svc.Account())
	}
	if err := svc.Login(ctx, LoginRequest{ServerURL: envB.server.URL, Email: envB.email, MasterPassword: envB.password}); err != nil {
		t.Fatalf("Login B: %v", err)
	}

	accts := svc.Accounts()
	if len(accts) != 2 {
		t.Fatalf("Accounts = %+v, want A and B", accts)
	}
	ids := map[string]bool{}
	for _, a := range accts {
		ids[a.ID] = true
	}
	if !ids["acct-1"] || !ids["acct-b"] {
		t.Fatalf("Accounts = %+v, want acct-1 and acct-b", accts)
	}

	// Switching to A locks B; A unlocks with its own password and server.
	if err := svc.SwitchAccount("acct-1"); err != nil {
		t.Fatal(err)
	}
	if svc.Status() != StatusLocked || svc.Account().ID != "acct-1" || len(svc.Search("", SearchFilter{})) != 0 {
		t.Fatalf("after switch to A: status=%v account=%+v", svc.Status(), svc.Account())
	}
	if got := statuses[len(statuses)-1]; got != StatusLocked {
		t.Fatalf("last reported status = %v, want locked", got)
	}
	if err := svc.UnlockWithPassword(ctx, envA.password); err != nil {
		t.Fatalf("unlock A: %v", err)
	}
	if svc.LocalOnly() {
		t.Fatal("A lost its saved sign-in when B signed in")
	}
	if err := svc.SyncNow(ctx); err != nil {
		t.Fatalf("sync A: %v", err)
	}

	// Logging out of A leaves B on the device.
	if err := svc.Logout(ctx, secrets); err != nil {
		t.Fatal(err)
	}
	if accts := svc.Accounts(); len(accts) != 1 || accts[0].ID != "acct-b" {
		t.Fatalf("after logout of A, Accounts = %+v", accts)
	}
	if _, ok, _ := secrets.Get(refreshTokenKeyPrefix + "acct-b"); !ok {
		t.Fatal("logout of A removed B's refresh token")
	}
	if err := svc.SwitchAccount("acct-b"); err != nil {
		t.Fatal(err)
	}
	if err := svc.UnlockWithPassword(ctx, envB.password); err != nil || svc.LocalOnly() {
		t.Fatalf("unlock B: err=%v localOnly=%v", err, svc.LocalOnly())
	}

	if err := svc.SwitchAccount("acct-missing"); !errors.Is(err, store.ErrSnapshotNotFound) {
		t.Fatalf("SwitchAccount(missing) = %v", err)
	}
	if svc.Status() != StatusUnlocked {
		t.Fatal("a failed switch locked the open vault")
	}
}
