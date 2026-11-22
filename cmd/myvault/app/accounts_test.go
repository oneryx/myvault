package app

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/oneryx/myvault/cmd/myvault/core"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

// startTwoAccounts opens alice's vault, unlocked, with bob's vault also on
// the device.
func startTwoAccounts(t *testing.T) (*testApp, *AppModel, *mockVaultService) {
	t.Helper()
	svc := newMockVaultService(state.StatusUnlocked)
	svc.accounts = []state.Account{
		{ID: "acct-1", Email: "alice@example.com", ServerURL: "https://vault.example.com"},
		{ID: "acct-2", Email: "bob@example.com", ServerURL: "https://vault.example.org"},
	}
	svc.current = "acct-1"
	svc.trustedServer = "https://trusted.example"
	hooks := PlatformHooks{DiscoverSnapshot: func(id string) *AccountSnapshotMeta {
		for _, a := range svc.Accounts() {
			if a.ID == id {
				return &AccountSnapshotMeta{AccountID: a.ID, Email: a.Email, KDFSummary: "kdf of " + a.ID}
			}
		}
		return nil
	}}
	app, m, _ := startSecurityApp(t, svc, hooks)
	app.Post(func() {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs {
			p.AccountID, p.Email = "acct-1", "alice@example.com"
			p.SetBiometric("acct-1", true)
			return p
		})
	})
	return app, m, svc
}

func TestSwitchAccountLocksAndShowsTheOther(t *testing.T) {
	app, m, svc := startTwoAccounts(t)
	gen := m.LockGeneration()
	app.Post(func() {
		m.SelectCipher(m.Scope, "c-github")
		m.SwitchAccount("acct-2")
	})
	if m.LockState.Get() != state.StatusLocked || svc.Status() != state.StatusLocked {
		t.Fatalf("after switching: model %v, service %v", m.LockState.Get(), svc.Status())
	}
	p := m.Prefs.Get()
	if p.AccountID != "acct-2" || p.Email != "bob@example.com" || p.KDFSummary != "kdf of acct-2" {
		t.Fatalf("settings did not follow the account: %+v", p)
	}
	if p.ServerURL != "https://trusted.example" {
		t.Fatalf("server = %q, want the trusted sign-in record's", p.ServerURL)
	}
	if p.BiometricEnabled() || !slices.Contains(p.BiometricAccounts, "acct-1") {
		t.Fatalf("biometric unlock is not per account: %+v", p.BiometricAccounts)
	}
	if m.SelectedID.Get() != "" || m.LockGeneration() == gen {
		t.Fatal("the open vault's UI or pending actions survived the switch")
	}
	app.Find("bob@example.com")
	app.Find("MyVault is Locked")

	// A late report of the switch leaves the lock screen as it is.
	app.Post(func() { m.ServiceLeftUnlocked(state.StatusLocked) })
	if m.Prefs.Get().AccountID != "acct-2" {
		t.Fatal("the service's report undid the switch")
	}

	app.Post(func() { m.SwitchAccount("acct-1") })
	if p := m.Prefs.Get(); p.AccountID != "acct-1" || !p.BiometricEnabled() {
		t.Fatalf("switching back lost alice's settings: %+v", p)
	}
}

func TestAddAccountThenCancel(t *testing.T) {
	app, m, svc := startTwoAccounts(t)
	app.Post(m.AddAccount)
	if m.LockState.Get() != state.StatusLoggedOut || m.AddingFrom.Get() != "acct-1" {
		t.Fatalf("adding: state %v, from %q", m.LockState.Get(), m.AddingFrom.Get())
	}
	app.Find("Add an Account")
	if m.LoginEmail.Get() != "" {
		t.Fatalf("the form kept alice's email: %q", m.LoginEmail.Get())
	}
	app.Press("Cancel")
	if m.LockState.Get() != state.StatusLocked || m.Prefs.Get().AccountID != "acct-1" || m.AddingFrom.Get() != "" {
		t.Fatalf("cancel: state %v, account %q", m.LockState.Get(), m.Prefs.Get().AccountID)
	}
	// The logged-out report of Add Account arrives after Cancel.
	app.Post(func() { m.ServiceLeftUnlocked(state.StatusLoggedOut) })
	if p := m.Prefs.Get(); p.AccountID != "acct-1" || !p.BiometricEnabled() {
		t.Fatalf("a stale report forgot alice: %+v", p)
	}
	if !slices.Equal(svc.switches, []string{"", "acct-1"}) {
		t.Fatalf("switches = %q", svc.switches)
	}
}

func TestAddAccountSignsIn(t *testing.T) {
	app, m, _ := startTwoAccounts(t)
	app.Post(m.AddAccount)
	app.Post(func() {
		m.LoginServer.Set("https://vault.example.net")
		m.LoginEmail.Set("carol@example.com")
		m.LoginPassword.Set("master-password")
		m.Login()
	})
	app.WaitUntil(2*time.Second, func() bool { return m.LockState.Get() == state.StatusUnlocked })
	p := m.Prefs.Get()
	if p.AccountID != "acct-carol@example.com" || m.AddingFrom.Get() != "" || p.BiometricEnabled() {
		t.Fatalf("after adding: %+v, adding from %q", p, m.AddingFrom.Get())
	}
	if n := len(m.Accounts.Get()); n != 3 {
		t.Fatalf("accounts = %d, want 3", n)
	}
}

func TestLogoutOpensAnotherAccount(t *testing.T) {
	app, m, svc := startTwoAccounts(t)
	app.OnAlert = func(cfg core.AlertConfig) int { return 1 }
	app.Post(func() { m.Logout(m.Scope) })
	app.WaitUntil(2*time.Second, func() bool { return m.Prefs.Get().AccountID == "acct-2" })
	if m.LockState.Get() != state.StatusLocked || svc.Status() != state.StatusLocked {
		t.Fatalf("after logout: model %v, service %v", m.LockState.Get(), svc.Status())
	}
	if p := m.Prefs.Get(); len(p.BiometricAccounts) != 0 {
		t.Fatalf("alice's biometric setting survived her logout: %+v", p.BiometricAccounts)
	}
	if a := m.Accounts.Get(); len(a) != 1 || a[0].ID != "acct-2" {
		t.Fatalf("accounts = %+v", a)
	}

	// Logging out of the last account leaves the sign-in form.
	app.Post(func() { m.Logout(m.Scope) })
	app.WaitUntil(2*time.Second, func() bool { return m.LockState.Get() == state.StatusLoggedOut })
	if m.Prefs.Get().AccountID != "" || len(m.Accounts.Get()) != 0 {
		t.Fatalf("after the last logout: %+v", m.Prefs.Get())
	}
	app.Find("Sign in to MyVault")
}

func TestBiometricSettingMigrates(t *testing.T) {
	var p UserPrefs
	if err := json.Unmarshal([]byte(`{"accountId":"acct-1","biometricEnabled":true}`), &p); err != nil {
		t.Fatal(err)
	}
	if !p.BiometricEnabled() || !slices.Equal(p.BiometricAccounts, []string{"acct-1"}) {
		t.Fatalf("migrated = %+v", p.BiometricAccounts)
	}
	raw, _ := json.Marshal(p)
	var again UserPrefs
	if err := json.Unmarshal(raw, &again); err != nil || !slices.Equal(again.BiometricAccounts, []string{"acct-1"}) {
		t.Fatalf("round trip = %+v, %v", again.BiometricAccounts, err)
	}
}
