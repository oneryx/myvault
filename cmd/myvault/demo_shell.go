package main

import (
	"time"

	vaultapp "github.com/oneryx/myvault/cmd/myvault/app"
	"github.com/oneryx/myvault/cmd/myvault/core"
	"github.com/oneryx/myvault/cmd/myvault/demo"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

// newDemoShell opens the app on an in-memory sample vault with its own
// settings, without a server.
func newDemoShell() *DesktopShell {
	scope := newScope()
	if dir := ensureDataDir(); dir != "" {
		core.SetStorageDir(dir)
	}
	shell := &DesktopShell{
		scope:     scope,
		clipboard: NewClipboardAdapter(),
	}
	hooks := shell.platformHooks(demo.NewSecretStore())
	hooks.PrefsKey = "myvault.demo.prefs"
	hooks.VerifyMasterPassword = func(_ string, password []byte) error {
		if len(password) == 0 {
			return state.ErrLocked
		}
		return nil
	}
	shell.model = vaultapp.NewAppModel(scope, demo.NewService(state.StatusUnlocked), hooks)
	shell.model.UpdatePrefs(func(p vaultapp.UserPrefs) vaultapp.UserPrefs {
		p.AccountID = demo.AccountID
		p.Email = demo.Email
		p.ServerURL = demo.ServerURL
		p.KDFSummary = demo.KDF
		p.SetBiometric(demo.AccountID, true)
		p.AutoPromptBiometric = false
		return p
	})
	shell.model.LastSync.Set(time.Now().Add(-2 * time.Minute))
	shell.model.LoginServer.Set(demo.ServerURL)
	shell.model.LoginEmail.Set(demo.Email)
	shell.model.RefreshVaultData()
	shell.model.SelectCipher(scope, "c-github")
	shell.finishSetup()
	return shell
}
