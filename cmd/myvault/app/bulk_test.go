package app

import (
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/oneryx/myvault/cmd/myvault/core"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

func deleted(svc *mockVaultService, id string) bool {
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	c, ok := svc.ciphers[id]
	return ok && c.DeletedDate != nil
}

func archived(svc *mockVaultService, id string) bool {
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	c, ok := svc.ciphers[id]
	return ok && c.ArchivedDate != nil
}

func gone(svc *mockVaultService, id string) bool {
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	_, ok := svc.ciphers[id]
	return !ok
}

// Two chosen items go to Trash from the detail pane after one
// confirmation, come back with Restore and are deleted for good.
func TestBulkTrashRestoreAndDelete(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	app, model := startApp(t, svc, PlatformHooks{}, 1100, 700)
	answers := []int{0, 1, 1}
	app.OnAlert = func(core.AlertConfig) int { a := answers[0]; answers = answers[1:]; return a }

	if err := app.tt.Click("GitHub"); err != nil {
		t.Fatal(err)
	}
	app.pump()
	if err := app.tt.ClickWith(ui.Cmd, "SSH Recovery Note"); err != nil {
		t.Fatal(err)
	}
	app.pump()
	app.Find("2 Items Selected")

	app.Press("Move to Trash…") // cancelled
	app.Settle()
	if deleted(svc, "c-github") {
		t.Fatal("moved to Trash without confirmation")
	}
	app.Press("Move to Trash…")
	app.WaitUntil(2*time.Second, func() bool { return deleted(svc, "c-github") && deleted(svc, "c-note") })
	app.WaitFor("Moved 2 items to Trash", 2*time.Second)
	if app.Exists("2 Items Selected") {
		t.Fatal("the selection stayed after the action")
	}

	ids := []string{"c-github", "c-note"}
	app.Post(func() { model.RestoreItems(ids) })
	app.WaitUntil(2*time.Second, func() bool { return !deleted(svc, "c-github") && !deleted(svc, "c-note") })
	app.WaitFor("Restored 2 items", 2*time.Second)

	app.Post(func() { model.ArchiveItems(model.Scope, ids, true) })
	app.WaitUntil(2*time.Second, func() bool { return archived(svc, "c-github") && archived(svc, "c-note") })

	svc.mu.Lock()
	now := time.Now()
	svc.ciphers["c-github"].DeletedDate = &now
	svc.ciphers["c-note"].DeletedDate = &now
	svc.mu.Unlock()
	app.Post(func() { model.RefreshVaultData(); model.DeleteItemsPermanently(model.Scope, ids) })
	app.WaitUntil(2*time.Second, func() bool { return gone(svc, "c-github") && gone(svc, "c-note") })
	app.WaitFor("Deleted 2 items", 2*time.Second)
}

// Offline the actions change nothing.
func TestBulkActionsWaitWhileOffline(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	app, model := startApp(t, svc, PlatformHooks{}, 1100, 700)
	app.OnAlert = func(core.AlertConfig) int { return 1 }
	app.Post(func() {
		model.SyncState.Set(SyncOffline)
		model.TrashItems(model.Scope, []string{"c-github", "c-note"})
		model.ArchiveItems(model.Scope, []string{"c-github", "c-note"}, true)
	})
	app.Settle()
	if deleted(svc, "c-github") || archived(svc, "c-github") {
		t.Fatal("changed items while offline")
	}
}
