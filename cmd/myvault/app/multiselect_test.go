package app

import (
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

// center returns the middle of the element named s in the list or sidebar
// (the first one not a plain text).
func center(t *testing.T, a *testApp, role ui.Role, s string) (float32, float32) {
	t.Helper()
	for _, info := range a.tt.AccessAll() {
		if info.Name == s && info.Role == role && !info.Offscreen && info.Bounds.W > 0 {
			b := info.Bounds
			return b.X + b.W/2, b.Y + b.H/2
		}
	}
	t.Fatalf("no %v named %q; texts: %q", role, s, a.tt.Texts())
	return 0, 0
}

func folderOf(svc *mockVaultService, id string) string {
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	if f := svc.ciphers[id].FolderID; f != nil {
		return *f
	}
	return ""
}

func TestMultiSelectAndDragIntoFolder(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	app, model := startApp(t, svc, PlatformHooks{}, 1100, 700)

	if err := app.tt.Click("GitHub"); err != nil {
		t.Fatal(err)
	}
	app.pump()
	if model.SelectedID.Get() != "c-github" {
		t.Fatalf("click chose %q", model.SelectedID.Get())
	}
	if err := app.tt.ClickWith(ui.Cmd, "SSH Recovery Note"); err != nil {
		t.Fatal(err)
	}
	app.pump()
	app.Find("2 Items Selected")

	gx, gy := center(t, app, ui.RoleListItem, "GitHub")
	wx, wy := center(t, app, ui.RoleButton, "Work")
	app.tt.Press(gx, gy)
	app.tt.Move(gx, gy+10)
	app.tt.Move(wx, wy)
	app.tt.Release(wx, wy)
	app.WaitUntil(2*time.Second, func() bool {
		return folderOf(svc, "c-github") == "f-work" && folderOf(svc, "c-note") == "f-work"
	})
	app.WaitFor("Moved 2 items to Work", 2*time.Second)

	// One item back to No Folder, dragged alone after a plain click.
	if err := app.tt.Click("SSH Recovery Note"); err != nil {
		t.Fatal(err)
	}
	app.pump()
	if app.Exists("2 Items Selected") {
		t.Fatal("a plain click kept the multiple selection")
	}
	nx, ny := center(t, app, ui.RoleListItem, "SSH Recovery Note")
	fx, fy := center(t, app, ui.RoleButton, "No Folder")
	app.tt.Press(nx, ny)
	app.tt.Move(nx, ny+10)
	app.tt.Move(fx, fy)
	app.tt.Release(fx, fy)
	app.WaitUntil(2*time.Second, func() bool { return folderOf(svc, "c-note") == "" })
	if folderOf(svc, "c-github") != "f-work" {
		t.Fatal("dragging one item moved the other")
	}
}

func TestMoveToFolderSkipsTrashAndOffline(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers["c-note"].DeletedDate = ptr(time.Now())
	app, model := startApp(t, svc, PlatformHooks{}, 1100, 700)

	app.Post(func() { model.MoveToFolder([]string{"c-github", "c-note"}, "f-work") })
	app.WaitUntil(2*time.Second, func() bool { return folderOf(svc, "c-github") == "f-work" })
	app.Settle()
	if folderOf(svc, "c-note") != "" {
		t.Fatal("an item in Trash moved")
	}

	app.Post(func() {
		model.SyncState.Set(SyncOffline)
		model.MoveToFolder([]string{"c-github"}, "")
	})
	app.Settle()
	if folderOf(svc, "c-github") != "f-work" {
		t.Fatal("moved while offline")
	}
}
