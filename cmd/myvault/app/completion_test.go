package app

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oneryx/myvault/cmd/myvault/core"
	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

func TestDelayedFavoriteKeepsTheCurrentSelection(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers["c-mine"] = &state.Cipher{ID: "c-mine", Type: api.CipherTypeLogin, Name: "Mine", Login: &state.Login{Username: "b", Password: "my-secret"}}
	svc.order = append(svc.order, "c-mine")
	gate := make(chan struct{})
	svc.saveGate = gate
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})

	app.Post(func() { m.SelectCipher(root, "c-mine") })
	app.WaitUntil(2*time.Second, func() bool { c := m.ActiveCipher.Get(); return c != nil && c.ID == "c-mine" })
	app.Post(func() { m.ToggleFavorite() })
	app.Post(func() { m.SelectCipher(root, "c-github") })
	app.WaitUntil(2*time.Second, func() bool { c := m.ActiveCipher.Get(); return c != nil && c.ID == "c-github" })
	close(gate)
	app.WaitUntil(2*time.Second, func() bool { c, _ := svc.GetCipher("c-mine"); return c.Favorite })
	app.Settle()
	if c := m.ActiveCipher.Get(); c == nil || c.ID != "c-github" || m.SelectedID.Get() != "c-github" {
		t.Fatalf("after a delayed favorite: active %v, selected %q", c, m.SelectedID.Get())
	}
}

func TestUploadWithFailedLocalCopyIsDone(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.localCopyFails = true
	upload := filepath.Join(t.TempDir(), "invoice.pdf")
	if err := os.WriteFile(upload, []byte("%PDF-1.7"), 0o600); err != nil {
		t.Fatal(err)
	}
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})
	app.PickFiles = func(core.PickFilesOptions) []core.File {
		return []core.File{{Name: "invoice.pdf", Size: 8, Path: upload}}
	}
	app.Post(func() { m.SelectCipher(root, "c-github") })
	app.WaitFor("Attach File", 2*time.Second)
	app.Press("Attach File")
	app.WaitFor("invoice.pdf", 2*time.Second)
	if m.AttachmentBusy.Get() != "" {
		t.Fatal("upload still busy")
	}
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if svc.uploads != 1 {
		t.Fatalf("uploads = %d", svc.uploads)
	}
}

func TestRepromptVerifiesTheAccountCapturedOnTheUIThread(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	got := make(chan string, 1)
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() {
		m.Hooks.VerifyMasterPassword = func(accountID string, _ []byte) error { got <- accountID; return nil }
		m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.AccountID = "acct-9"; return p })
		m.openRepromptDialog("test", nil)
		m.RepromptPW.Set("pw")
		m.SubmitReprompt()
	})
	var id string
	app.WaitUntil(2*time.Second, func() bool {
		select {
		case id = <-got:
			return true
		default:
			return false
		}
	})
	// The account comes from the service, never from settings that may
	// still name an earlier account.
	if id != "acct-1" {
		t.Fatalf("verified account %q, want the open vault's", id)
	}
}
