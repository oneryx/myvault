package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

func startApp(t *testing.T, svc *mockVaultService, hooks PlatformHooks, w, h int) (*testApp, *AppModel) {
	a := newTestApp(t, svc, hooks, w, h, func(m *AppModel) {
		m.MainWinVisible.Set(true)
		m.RefreshVaultData()
	})
	return a, a.m
}

func TestCoreStateTransitions(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	app, m := startApp(t, svc, PlatformHooks{}, 1100, 760)

	app.Find("Sign in to MyVault")
	app.Type("Server URL", "https://vault.example.com")
	app.Type("Email", "alice@example.com")
	app.Type("Master password", "master-password")
	app.Press("Sign In")
	app.WaitUntil(2*time.Second, func() bool { return m.LockState.Get() == state.StatusUnlocked && app.Exists("New Item") })

	app.Type("Search vault", "GitHub")
	app.WaitFor("GitHub", time.Second)
	if app.Exists("SSH Recovery Note") {
		t.Fatal("search kept a non-matching item")
	}
	app.Press("GitHub")
	app.WaitFor("alice@example.com", time.Second)

	app.Press("Edit")
	app.WaitFor("Edit Login", time.Second)
	app.Type("Name", "GitHub Enterprise")
	app.Press("Save")
	app.WaitUntil(2*time.Second, func() bool { return !m.EditMode.Get() })
	app.WaitFor("GitHub Enterprise", time.Second)
	if c, _ := svc.GetCipher("c-github"); c.Name != "GitHub Enterprise" {
		t.Fatalf("saved name = %q", c.Name)
	}

	app.Press("Lock vault")
	app.WaitFor("MyVault is Locked", 2*time.Second)
	app.Type("Master password", "master-password")
	app.Press("Unlock")
	app.WaitUntil(2*time.Second, func() bool { return m.LockState.Get() == state.StatusUnlocked && app.Exists("New Item") })
}

func TestLoginTwoFactorEmailVerify(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	svc.twoFactorCode = "654321"
	app, m := startApp(t, svc, PlatformHooks{}, 1100, 760)

	app.Type("Server URL", "https://vault.example.com")
	app.Type("Email", "alice@example.com")
	app.Type("Master password", "master-password")
	app.Press("Sign In")
	app.WaitFor("Two-step verification", 2*time.Second)

	app.Press("Email")
	app.WaitUntil(time.Second, func() bool { return m.TwoFactorProvider.Get() == api.TwoFactorEmail })
	app.Press("Send Code")
	app.WaitFor("A verification code was sent to a***@example.com.", 2*time.Second)

	app.Type("Verification Code", "111111")
	app.Press("Verify")
	app.WaitUntil(2*time.Second, func() bool { return m.LoginError.Get() != "" && !m.LoginBusy.Get() })

	app.Type("Verification Code", "654 321")
	app.Press("Remember this device")
	if !m.TwoFactorRemember.Get() {
		t.Fatal("Remember this device did not turn on")
	}
	app.Press("Verify")
	app.WaitUntil(2*time.Second, func() bool { return m.LockState.Get() == state.StatusUnlocked && app.Exists("New Item") })

	svc.mu.RLock()
	sends := svc.emailSends
	svc.mu.RUnlock()
	if sends != 1 {
		t.Fatalf("email sends = %d, want 1", sends)
	}
}

func TestTOTPTickerVisibilityGating(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	app, model := startApp(t, svc, PlatformHooks{}, 980, 640)

	if model.TOTPTickerActive() {
		t.Fatal("expected TOTP ticker stopped before selecting a TOTP item")
	}
	app.Post(func() { model.SelectCipher(model.Scope, "c-github") })
	app.WaitUntil(2*time.Second, func() bool { return model.TOTPTickerActive() && model.TOTPCode.Get() != "" })
	app.Post(func() { model.SelectCipher(model.Scope, "c-note") })
	app.WaitUntil(2*time.Second, func() bool { return !model.TOTPTickerActive() })
	app.Post(func() { model.SelectCipher(model.Scope, "c-github") })
	app.WaitUntil(2*time.Second, model.TOTPTickerActive)
	app.Post(func() { model.MainWinVisible.Set(false) })
	app.WaitUntil(2*time.Second, func() bool { return !model.TOTPTickerActive() })
	app.Post(func() { model.MainWinVisible.Set(true) })
	app.WaitUntil(2*time.Second, model.TOTPTickerActive)
	app.Post(model.Lock)
	app.WaitUntil(2*time.Second, func() bool { return !model.TOTPTickerActive() })
}

func TestTrayIconOffKeepsDockReachable(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	var trayCalls, dockCalls []bool
	app, model := startApp(t, svc, PlatformHooks{
		SetTrayVisible: func(on bool) { trayCalls = append(trayCalls, on) },
		SetDockVisible: func(on bool) { dockCalls = append(dockCalls, on) },
	}, 980, 640)

	if !model.Prefs.Get().ShowTrayIcon {
		t.Fatal("expected the tray icon to be shown by default")
	}
	app.Post(func() {
		model.UpdatePrefs(func(p UserPrefs) UserPrefs { p.HideDockIcon = true; return p })
		model.SetShowTrayIcon(false)
	})
	app.Settle()

	p := model.Prefs.Get()
	if p.ShowTrayIcon || p.HideDockIcon {
		t.Fatalf("expected tray off and Dock shown, got ShowTrayIcon=%v HideDockIcon=%v", p.ShowTrayIcon, p.HideDockIcon)
	}
	if len(trayCalls) != 1 || trayCalls[0] || len(dockCalls) != 1 || !dockCalls[0] {
		t.Fatalf("expected tray hidden and Dock shown, got tray=%v dock=%v", trayCalls, dockCalls)
	}
	raw, err := os.ReadFile(filepath.Join(app.StorageDir, DefaultPrefsKey+".json"))
	if err != nil || !strings.Contains(string(raw), `"showTrayIcon":false`) {
		t.Fatalf("expected showTrayIcon persisted, got %q, %v", raw, err)
	}
}

func TestSearchStaysInSectionUntilWidened(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers["c-github"].FolderID = ptr("f-work")
	app, model := startApp(t, svc, PlatformHooks{}, 1100, 640)

	noteType := api.CipherTypeSecureNote
	app.Post(func() { model.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll, Type: &noteType}) })
	app.Type("Search vault", "GitHub")
	app.Settle()
	if n := model.FilteredItems.Len(); n != 0 || model.SearchIsGlobal() {
		t.Fatalf("search left Secure Notes by default: %d items, global=%v", n, model.SearchIsGlobal())
	}
	app.Find("In Secure Notes")
	app.Find("Nothing in Secure Notes matches “GitHub”.")

	app.Press("Search All Items")
	app.WaitUntil(2*time.Second, func() bool {
		return model.FilteredItems.Len() == 1 && model.FilteredItems.KeyAt(0) == "c-github"
	})
	app.Find("In All Items")

	app.Press("Only Secure Notes")
	app.WaitUntil(2*time.Second, func() bool { return model.FilteredItems.Len() == 0 })

	app.Post(func() { model.SetSidebarFilter(state.SearchFilter{FolderID: "f-work"}) })
	app.WaitUntil(2*time.Second, func() bool {
		return model.FilteredItems.Len() == 1 && !model.SearchIsGlobal()
	})
	app.Find("In Work")
}

func TestLockOnSleepPreferenceAndSystemEvent(t *testing.T) {
	var legacy UserPrefs
	if err := json.Unmarshal([]byte(`{"autoLockMinutes":5}`), &legacy); err != nil || !legacy.LockOnSleep {
		t.Fatalf("legacy prefs LockOnSleep = %v (err %v), want true", legacy.LockOnSleep, err)
	}

	svc := newMockVaultService(state.StatusUnlocked)
	app := newTestApp(t, svc, PlatformHooks{SleepLockSupported: true}, 980, 900, func(m *AppModel) {
		m.MainWinVisible.Set(true)
		m.Route.Set(RouteSettings)
	})
	model := app.m

	app.Press("Lock on sleep or screen lock")
	app.WaitUntil(time.Second, func() bool { return !model.Prefs.Get().LockOnSleep })

	systemLock := func() bool {
		result := false
		app.Post(func() { result = model.LockOnSystemEvent() })
		return result
	}
	if systemLock() || svc.Status() != state.StatusUnlocked {
		t.Fatal("system event locked the vault with LockOnSleep off")
	}

	app.Press("Lock on sleep or screen lock")
	app.WaitUntil(time.Second, func() bool { return model.Prefs.Get().LockOnSleep })

	if !systemLock() {
		t.Fatal("system event did not lock the unlocked vault")
	}
	app.WaitFor("MyVault is Locked", 2*time.Second)
	if svc.Status() != state.StatusLocked || model.TOTPTickerActive() {
		t.Fatalf("after lock: status=%v ticker=%v", svc.Status(), model.TOTPTickerActive())
	}
	if systemLock() {
		t.Fatal("system event re-locked an already locked vault")
	}
}

func TestSidebarCollectionsFilterItems(t *testing.T) {
	personal := newMockVaultService(state.StatusUnlocked)
	app, _ := startApp(t, personal, PlatformHooks{}, 980, 900)
	app.WaitFor("GitHub", 2*time.Second)
	if app.Exists("Collections") {
		t.Fatal("personal-only vault shows a Collections section")
	}

	svc := newMockVaultService(state.StatusUnlocked)
	org := "org-1"
	svc.organizations = []state.Organization{{ID: org, Name: "Acme", Enabled: true}}
	svc.collections = []state.Collection{{ID: "col-eng", OrganizationID: org, Name: "Engineering", ReadOnly: true}}
	svc.ciphers["c-github"].OrganizationID = &org
	svc.ciphers["c-github"].CollectionIDs = []string{"col-eng"}
	app, _ = startApp(t, svc, PlatformHooks{}, 980, 900)

	app.WaitFor("Engineering", 2*time.Second)
	app.Press("Engineering")
	app.WaitForGone("SSH Recovery Note", 2*time.Second)
	app.Find("GitHub")

	app.Press("GitHub")
	app.WaitFor("Acme", 2*time.Second)
	app.Find("View only")
}
