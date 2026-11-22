package app

import (
	"testing"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/state"
)

func TestSaveWithFailedLocalCopyCannotCreateTwice(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})
	svc.mu.Lock()
	svc.localCopyFails = true
	svc.mu.Unlock()

	app.Post(func() { m.StartCreateCipher(root) })
	app.WaitUntil(2*time.Second, func() bool { return m.EditMode.Get() })
	app.Post(func() { m.MutateDraft(func(d *EditDraft) { d.Name = "Fresh" }) })
	app.Press("Save")
	app.WaitUntil(2*time.Second, func() bool { return !m.EditMode.Get() })

	if m.EditDraft.Get() != nil || m.SelectedID.Get() != "c-new" || m.EditError.Get() != "" {
		t.Fatalf("editor after a committed save: draft=%v selected=%q error=%q", m.EditDraft.Get(), m.SelectedID.Get(), m.EditError.Get())
	}
	if app.Exists("Save") {
		t.Fatal("Save is still available after the server created the item")
	}
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if svc.creates != 1 {
		t.Fatalf("creates = %d, want 1", svc.creates)
	}
}
