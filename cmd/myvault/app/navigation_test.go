package app

import (
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/oneryx/myvault/cmd/myvault/core"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

func TestHealthFilterAndBackForward(t *testing.T) {
	svc := healthService(false)
	app, model := startApp(t, svc, PlatformHooks{}, 1100, 900)
	healthShown := "Checked on this device only. Nothing is sent to a server."

	if model.CanGoBack.Get() {
		t.Fatal("history not empty at start")
	}
	app.Press("Vault Health")
	app.WaitFor(healthShown, 2*time.Second)
	app.Find("Old Card")
	app.Press("Unsecured")
	app.WaitForGone("Old Card", 2*time.Second)
	app.Find("http://router.example.net")
	if model.HealthFilter.Get() != HealthUnsecured {
		t.Fatalf("HealthFilter = %q", model.HealthFilter.Get())
	}

	app.Press("Open Router")
	app.WaitUntil(2*time.Second, func() bool {
		return model.Route.Get() == RouteVault && model.SelectedID.Get() == "c-router"
	})
	app.Press("Back")
	app.WaitFor(healthShown, 2*time.Second)
	if model.HealthFilter.Get() != HealthUnsecured || app.Exists("Old Card") {
		t.Fatalf("Back lost the health filter: %q", model.HealthFilter.Get())
	}
	if !model.CanGoForward.Get() {
		t.Fatal("Forward unavailable after Back")
	}
	app.Key(ui.Cmd, ui.KeyBracketRight)
	app.WaitUntil(2*time.Second, func() bool {
		return model.Route.Get() == RouteVault && model.SelectedID.Get() == "c-router"
	})
	app.Post(model.GoBackFromSystem)
	app.WaitFor(healthShown, 2*time.Second)
	app.Press("Unsecured")
	app.WaitFor("Old Card", 2*time.Second)

	app.Post(model.Lock)
	app.WaitFor("MyVault is Locked", 2*time.Second)
	if model.CanGoBack.Get() || model.CanGoForward.Get() {
		t.Fatal("history survived lock")
	}
}

func TestLockDoesNotAutoPromptTouchID(t *testing.T) {
	if DefaultUserPrefs().AutoPromptBiometric {
		t.Fatal("AutoPromptBiometric defaults to on")
	}
	svc := newMockVaultService(state.StatusUnlocked)
	app := newTestApp(t, svc, PlatformHooks{Secrets: noSecrets{}}, 1100, 700, func(m *AppModel) {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs {
			p.AccountID, p.BiometricAccounts, p.AutoPromptBiometric = "acct", []string{"acct"}, true
			return p
		})
		m.SetMainWindowVisible(true)
		m.RefreshVaultData()
	})
	model := app.m
	app.BiometricAvailability = core.BiometricFingerprint
	app.BiometricAnswer = core.BiometricCancelled
	app.Post(model.RefreshBiometricAvailability)
	app.WaitUntil(2*time.Second, model.CanUseBiometric)
	app.Post(model.Lock)
	app.WaitFor("MyVault is Locked", 2*time.Second)
	app.Settle()
	if n := len(app.AuthenticationReasons); n != 0 {
		t.Fatalf("locking prompted Touch ID %d times", n)
	}
	app.Post(func() { model.SetMainWindowVisible(false) })
	app.Post(func() { model.SetMainWindowVisible(true) })
	app.WaitUntil(2*time.Second, func() bool { return len(app.AuthenticationReasons) == 1 })
}

type noSecrets struct{}

func (noSecrets) Get(string) (string, bool, error) { return "", false, nil }
func (noSecrets) Set(string, string) error         { return nil }
func (noSecrets) Delete(string) error              { return nil }

func TestBiometricUnlockWithoutSavedKeyTurnsItOff(t *testing.T) {
	svc := newMockVaultService(state.StatusLocked)
	app := newTestApp(t, svc, PlatformHooks{Secrets: noSecrets{}}, 1100, 700, func(m *AppModel) {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs {
			p.AccountID, p.BiometricAccounts = "acct", []string{"acct"}
			return p
		})
		m.SetMainWindowVisible(true)
	})
	model := app.m
	app.BiometricAvailability = core.BiometricFingerprint
	app.BiometricAnswer = core.BiometricSuccess
	app.Post(model.RefreshBiometricAvailability)
	app.WaitUntil(2*time.Second, model.CanUseBiometric)
	app.Post(func() { model.UnlockWithBiometric(model.Scope) })
	app.WaitUntil(2*time.Second, func() bool { return !model.Prefs.Get().BiometricEnabled() })
	if model.LockBusy.Get() || model.LockError.Get() == "" {
		t.Fatalf("busy %v, error %q", model.LockBusy.Get(), model.LockError.Get())
	}
}
