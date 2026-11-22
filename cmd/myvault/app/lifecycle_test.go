package app

import (
	"testing"
	"time"

	"github.com/oneryx/myvault/cmd/myvault/core"

	"github.com/oneryx/myvault/internal/vaultcore/state"
)

func TestServerLogoutClearsTheUnlockedUI(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.AccountID = "acct-1"; p.SetBiometric("acct-1", true); return p })
		m.StartCreateCipher(root)
		m.MutateDraft(func(d *EditDraft) { d.Name = "Secret draft"; d.Password = "typed secret" })
		m.openBackupDialog(BackupExport)
	})
	app.WaitUntil(2*time.Second, func() bool { return m.EditMode.Get() && m.BackupDialog.Get() == BackupExport })
	gen := m.LockGeneration()

	svc.mu.Lock()
	svc.status = state.StatusLoggedOut
	svc.mu.Unlock()
	app.Post(func() { m.ServiceLeftUnlocked(state.StatusLoggedOut) })
	app.WaitUntil(2*time.Second, func() bool { return m.LockState.Get() == state.StatusLoggedOut })

	if m.EditDraft.Get() != nil || m.EditMode.Get() || m.BackupDialog.Get() != BackupNone {
		t.Fatal("a draft or dialog survived the server logout")
	}
	if p := m.Prefs.Get(); p.AccountID != "" || len(p.BiometricAccounts) != 0 {
		t.Fatalf("account settings survived the server logout: %+v", p)
	}
	if m.StillUnlocked(gen) || m.LockGeneration() == gen {
		t.Fatal("pending actions were not revoked")
	}
}

func TestSleepDuringUnlockRevokesIt(t *testing.T) {
	svc := newMockVaultService(state.StatusLocked)
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	var gen uint64
	app.Post(func() {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.LockOnSleep = true; return p })
		m.LockBusy.Set(true)
		gen = m.LockGeneration()
		m.LockOnSystemEvent()
	})
	app.WaitUntil(2*time.Second, func() bool { return !m.LockBusy.Get() })
	if m.LockGeneration() == gen {
		t.Fatal("a sleep during unlock did not revoke the attempt")
	}
}

func TestDeviceIDExistsBeforeTheServiceStarts(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	var first, again string
	app.Post(func() {
		first = m.Prefs.Get().DeviceID
		again = EnsureDeviceID(m.Prefs).DeviceID
	})
	app.WaitUntil(2*time.Second, func() bool { return first != "" })
	if again != first {
		t.Fatalf("device id changed: %q then %q", first, again)
	}
}

func TestSleepDuringSignInRevokesTheAttempt(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.LockOnSleep = true; return p })
		m.LoginBusy.Set(true)
		m.TwoFactorSending.Set(true)
		m.LockOnSystemEvent()
	})
	app.WaitUntil(2*time.Second, func() bool { return !m.LoginBusy.Get() })
	if m.TwoFactorSending.Get() {
		t.Fatal("Send code stayed busy after the sleep")
	}
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if svc.revokes != 1 {
		t.Fatalf("revokes = %d, want the sign-in revoked", svc.revokes)
	}
}

func TestLocalOnlyVaultAsksToSignInAgainAndKeepsTheCache(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.localOnly = true
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(m.RefreshVaultData)
	app.Post(func() { m.SyncState.Set(SyncAuthExpired) })
	app.WaitFor("Sign in again to sync. Your vault is available offline until then.", 2*time.Second)
	app.Press("Sign In Again")
	app.WaitFor("Server URL", 2*time.Second)
	if !m.ReSignIn.Get() || svc.Status() != state.StatusLocked {
		t.Fatalf("sign in again: resignin %v, status %v", m.ReSignIn.Get(), svc.Status())
	}
	if _, err := svc.GetCipher("c-github"); err == nil {
		t.Fatal("locked vault still readable")
	}
	svc.mu.RLock()
	n := len(svc.ciphers)
	svc.mu.RUnlock()
	if n == 0 {
		t.Fatal("signing in again removed the local vault")
	}
}

func TestUnsavedCredentialsShowABanner(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.credsUnsaved = true
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(m.RefreshVaultData)
	app.WaitFor("Your sign-in could not be saved. Sign in again so MyVault can still sync after you lock.", 2*time.Second)
}

func TestSnapshotMetadataNeverSetsTheServer(t *testing.T) {
	svc := newMockVaultService(state.StatusLocked)
	hooks := PlatformHooks{DiscoverSnapshot: func(string) *AccountSnapshotMeta {
		return &AccountSnapshotMeta{AccountID: "acct-1", ServerURL: "https://attacker.example", Email: "a@b.c"}
	}}
	app, m, _ := startSecurityApp(t, svc, hooks)
	app.Post(func() {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.ServerURL = "https://vault.example"; return p })
		m.SyncAccountMetaFromSnapshot()
	})
	app.WaitUntil(2*time.Second, func() bool { return m.Prefs.Get().AccountID == "acct-1" })
	if got := m.Prefs.Get().ServerURL; got != "https://vault.example" {
		t.Fatalf("server in settings = %q, want the one the user signed in to", got)
	}
}

func TestSessionExitClearsDialogsAndTheGeneratedPassword(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() {
		m.FolderDialog.Set(FolderModal{Open: true, FolderID: "f-1", Name: "Secret project"})
		m.GenResult.Set("generated-secret")
	})
	app.WaitFor("Folder name", 2*time.Second)

	svc.mu.Lock()
	svc.status = state.StatusLoggedOut
	svc.mu.Unlock()
	app.Post(func() { m.ServiceLeftUnlocked(state.StatusLoggedOut) })
	app.WaitForGone("Folder name", 2*time.Second)
	if m.FolderDialog.Get().Open || m.FolderDialog.Get().Name != "" || m.GenResult.Get() != "" {
		t.Fatalf("after logout: folder dialog %+v, generated %q", m.FolderDialog.Get(), m.GenResult.Get())
	}

	// A dialog opened while locked is never mounted.
	app.Post(func() { m.FolderDialog.Set(FolderModal{Open: true, Name: "x"}) })
	app.Settle()
	if app.Exists("Folder name") {
		t.Fatal("a vault dialog is shown over the sign-in screen")
	}
}

func TestLateSaveLeavesANewerDraftAlone(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	gate := make(chan struct{})
	svc.saveGate = gate
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})
	app.OnAlert = func(core.AlertConfig) int { return 1 }

	app.Post(func() { m.StartCreateCipher(root) })
	app.WaitUntil(2*time.Second, func() bool { return m.EditMode.Get() })
	app.Post(func() { m.MutateDraft(func(d *EditDraft) { d.Name = "First" }); m.SaveDraft(root) })
	app.WaitUntil(2*time.Second, func() bool { return m.EditBusy.Get() })
	// While it saves, the user discards the editor and starts another item.
	app.Post(func() { m.EditMode.Set(false); m.EditDraft.Set(nil); m.EditDirty.Set(false) })
	app.Post(func() { m.StartCreateCipher(root) })
	var second uint64
	app.WaitUntil(2*time.Second, func() bool {
		d := m.EditDraft.Get()
		if d != nil {
			second = d.session
		}
		return d != nil && d.Name == ""
	})
	close(gate)
	app.WaitUntil(2*time.Second, func() bool { return !m.EditBusy.Get() })
	app.Settle()
	if d := m.EditDraft.Get(); d == nil || d.session != second || !m.EditMode.Get() {
		t.Fatalf("the newer draft was replaced: %+v", d)
	}
}

func TestEditsDuringASaveAreRefused(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	gate := make(chan struct{})
	svc.saveGate = gate
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() { m.StartCreateCipher(root) })
	app.WaitUntil(2*time.Second, func() bool { return m.EditMode.Get() })
	app.Post(func() { m.MutateDraft(func(d *EditDraft) { d.Name = "Submitted" }); m.SaveDraft(root) })
	app.WaitUntil(2*time.Second, func() bool { return m.EditBusy.Get() })
	app.Post(func() { m.MutateDraft(func(d *EditDraft) { d.Name = "Typed during save" }) })
	app.Settle()
	if d := m.EditDraft.Get(); d == nil || d.Name != "Submitted" {
		t.Fatalf("an edit was taken while saving, and would be lost: %+v", d)
	}
	close(gate)
	app.WaitUntil(2*time.Second, func() bool { return !m.EditBusy.Get() })
	if c, err := svc.GetCipher("c-new"); err != nil || c.Name != "Submitted" {
		t.Fatalf("saved %+v, %v", c, err)
	}
}

func TestLockDuringSaveClearsBusy(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.saveGate = make(chan struct{})
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() { m.StartCreateCipher(root) })
	app.WaitUntil(2*time.Second, func() bool { return m.EditMode.Get() })
	app.Post(func() { m.MutateDraft(func(d *EditDraft) { d.Name = "x" }); m.SaveDraft(root) })
	app.WaitUntil(2*time.Second, func() bool { return m.EditBusy.Get() })
	app.Post(m.Lock)
	app.WaitUntil(2*time.Second, func() bool { return m.LockState.Get() == state.StatusLocked })
	if m.EditBusy.Get() {
		t.Fatal("EditBusy survived the lock and would block every later save")
	}
	close(svc.saveGate)
}

func TestSignInAgainCanGoBackToUnlockLocalOnly(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.localOnly = true
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(m.RefreshVaultData)
	app.Post(func() { m.SyncState.Set(SyncAuthExpired) })
	app.WaitFor("Sign In Again", 2*time.Second)
	app.Press("Sign In Again")
	app.WaitFor("Back to Unlock", 2*time.Second)

	app.Press("Back to Unlock")
	app.WaitFor("MyVault is Locked", 2*time.Second)
	if m.ReSignIn.Get() || app.Exists("Sign in to MyVault") {
		t.Fatal("still on the sign-in form")
	}
	app.Post(func() { m.LockPassword.Set("master-password"); m.UnlockWithPassword() })
	app.WaitUntil(2*time.Second, func() bool { return m.LockState.Get() == state.StatusUnlocked })
	if c, err := svc.GetCipher("c-github"); err != nil || c.Name != "GitHub" {
		t.Fatalf("local vault after going back: %+v, %v", c, err)
	}
}

func TestFirstSignInHasNoWayBackToUnlock(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	app, _, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.WaitFor("Sign In", 2*time.Second)
	if app.Exists("Back to Unlock") {
		t.Fatal("a first sign-in offers Back to Unlock")
	}
}

func TestSignInAgainIsForTheSameAccountOnly(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.localOnly = true
	svc.trustedServer = "https://vault.example"
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.AccountID = "stale-account"; return p })
		m.RefreshVaultData()
		m.SyncState.Set(SyncAuthExpired)
	})
	app.WaitFor("Sign In Again", 2*time.Second)
	app.Press("Sign In Again")
	app.WaitFor("Server URL", 2*time.Second)
	if m.LoginServer.Get() != "https://vault.example" || m.LoginEmail.Get() != "alice@example.com" {
		t.Fatalf("form prefilled with %q / %q, want the vault's account", m.LoginServer.Get(), m.LoginEmail.Get())
	}
	app.Post(func() { m.LoginServer.Set("https://other.example"); m.LoginPassword.Set("master-password"); m.Login() })
	app.WaitUntil(2*time.Second, func() bool { return m.LockState.Get() == state.StatusUnlocked })
	svc.mu.RLock()
	req := svc.lastLogin
	svc.mu.RUnlock()
	if req.SameAccount == nil || req.SameAccount.ID != "acct-1" || req.ServerURL != "https://vault.example" || req.Email != "alice@example.com" {
		t.Fatalf("Sign In Again sent %+v, want the vault's account only", req)
	}
	if got := m.Prefs.Get().AccountID; got != "acct-1" {
		t.Fatalf("settings name account %q after sign-in, want the one the service signed in", got)
	}
}

func TestSleepBetweenUnlockCommitAndTheUIStaysLocked(t *testing.T) {
	svc := newMockVaultService(state.StatusLocked)
	committed := make(chan struct{})
	svc.unlockCommitted = committed
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.LockOnSleep = true; return p })
		m.LockPassword.Set("master-password")
		m.UnlockWithPassword()
	})
	app.WaitUntil(2*time.Second, func() bool {
		select {
		case <-committed:
			return true
		default:
			return false
		}
	})
	// The service is unlocked; the UI still shows the lock screen. Sleep.
	app.Post(func() { m.LockOnSystemEvent() })
	app.Settle()
	committed <- struct{}{}
	app.WaitUntil(2*time.Second, func() bool { return !m.LockBusy.Get() })
	app.Settle()
	if svc.Status() != state.StatusLocked || m.LockState.Get() == state.StatusUnlocked {
		t.Fatalf("after a sleep during unlock: service %v, UI %v", svc.Status(), m.LockState.Get())
	}
	if m.LockPassword.Get() != "" {
		t.Fatal("the master password field survived the sleep")
	}
}

func TestSignInAgainWithoutATrustedRecordAsksForTheServer(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.localOnly = true
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.ServerURL = "https://from-snapshot.example"; return p })
		m.RefreshVaultData()
		m.SyncState.Set(SyncAuthExpired)
	})
	app.WaitFor("Sign In Again", 2*time.Second)
	app.Press("Sign In Again")
	app.WaitFor("Server URL", 2*time.Second)
	if m.LoginServer.Get() != "" || m.ReSignInServer.Get() != "" {
		t.Fatalf("server prefilled with %q without a trusted record", m.LoginServer.Get())
	}
	app.Post(func() { m.LoginServer.Set("https://typed.example"); m.LoginPassword.Set("master-password"); m.Login() })
	app.WaitUntil(2*time.Second, func() bool { return m.LockState.Get() == state.StatusUnlocked })
	svc.mu.RLock()
	req := svc.lastLogin
	svc.mu.RUnlock()
	if req.ServerURL != "https://typed.example" || req.SameAccount == nil || req.SameAccount.ID != "acct-1" || req.SameAccount.ServerURL != "https://typed.example" {
		t.Fatalf("sign-in request = %+v, want the typed server and the vault's account", req)
	}
}

func TestSleepAfterTheUIShowsTheVaultClearsTheUnlockForm(t *testing.T) {
	svc := newMockVaultService(state.StatusLocked)
	committed := make(chan struct{})
	svc.unlockCommitted = committed
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.LockOnSleep = true; return p })
		m.LockPassword.Set("master-password")
		m.UnlockWithPassword()
	})
	app.WaitUntil(2*time.Second, func() bool {
		select {
		case <-committed:
			return true
		default:
			return false
		}
	})
	// The status callback reached the UI, the worker has not reported yet.
	app.Post(func() { m.LockState.Set(state.StatusUnlocked); m.TwoFactorSending.Set(true) })
	app.Post(func() { m.LockOnSystemEvent() })
	app.Settle()
	if m.TwoFactorSending.Get() {
		t.Fatal("Send code stayed busy after the sleep")
	}
	if m.LockPassword.Get() != "" || m.LockBusy.Get() || m.LockState.Get() != state.StatusLocked {
		t.Fatalf("after the sleep: password kept %v, busy %v, state %v", m.LockPassword.Get() != "", m.LockBusy.Get(), m.LockState.Get())
	}
	committed <- struct{}{}
	app.Settle()
	if m.LockState.Get() == state.StatusUnlocked {
		t.Fatal("the late unlock completion reopened the vault")
	}
}

func TestTheWholeEditorIsDisabledWhileSaving(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	gate := make(chan struct{})
	svc.saveGate = gate
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() { m.StartCreateCipher(root) })
	app.WaitFor("Show password", 2*time.Second)
	for _, id := range []string{"Name", "Password", "Show password", "Notes", "Username", "Cancel"} {
		if !app.Enabled(id) {
			t.Fatalf("%s disabled before saving", id)
		}
	}
	app.Post(func() { m.MutateDraft(func(d *EditDraft) { d.Name = "x" }); m.SaveDraft(root) })
	app.WaitUntil(2*time.Second, func() bool { return m.EditBusy.Get() })
	app.Settle()
	for _, id := range []string{"Name", "Password", "Show password", "Notes", "Username", "Cancel", "Add Website"} {
		if app.Enabled(id) {
			t.Fatalf("%s is editable while saving", id)
		}
	}
	close(gate)
	app.WaitUntil(2*time.Second, func() bool { return !m.EditBusy.Get() })
}

func TestLateTwoFactorEmailAfterSleepIsIgnored(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	svc.twoFactorCode = "123456"
	gate := make(chan struct{})
	svc.emailGate = gate
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.LockOnSleep = true; return p })
		m.LoginServer.Set("https://vault.example")
		m.LoginEmail.Set("alice@example.com")
		m.LoginPassword.Set("master-password")
		m.Login()
	})
	app.WaitUntil(2*time.Second, func() bool { return m.TwoFactor.Get() != nil })
	app.Post(func() { m.LoginPassword.Set("master-password"); m.SendTwoFactorEmail() })
	app.WaitUntil(2*time.Second, func() bool { return m.TwoFactorSending.Get() })
	app.Post(func() { m.LockOnSystemEvent() })
	app.WaitUntil(2*time.Second, func() bool { return !m.TwoFactorSending.Get() })
	close(gate)
	app.Settle()
	if m.TwoFactorNotice.Get() != "" || m.TwoFactorSending.Get() {
		t.Fatalf("a late email completion after sleep took effect: notice %q", m.TwoFactorNotice.Get())
	}
}
