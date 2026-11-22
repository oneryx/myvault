package app

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/oneryx/myvault/cmd/myvault/core"
	"github.com/oneryx/myvault/internal/vaultcore/export"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

func TestExportRefusesAnIncompleteBackup(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.unreadable = []string{"c-blob"}
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() {
		m.openBackupDialog(BackupExport)
		m.BackupPW.Set("backup password")
		m.BackupPW2.Set("backup password")
		m.ConfirmBackupDialog(m.Scope)
	})
	app.WaitUntil(2*time.Second, func() bool { return m.BackupError.Get() != "" })
	if m.BackupBusy.Get() {
		t.Fatal("an incomplete backup was started")
	}
}

func TestUpdatingAProtectedItemOnImportAsksForTheMasterPassword(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers["c-github"].Reprompt = 1
	changed := *svc.ciphers["c-github"]
	login := *changed.Login
	login.Password = "backup-password-value"
	changed.Login = &login
	backup, _ := export.Build([]*state.Cipher{&changed}, nil)
	path := writeBackup(t, t.TempDir(), "plain.json", backup, "")
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.PickFiles = func(core.PickFilesOptions) []core.File {
		return []core.File{{Name: filepath.Base(path), Path: path}}
	}
	app.Post(func() { m.StartImport(m.Scope) })
	app.WaitFor("Review Import", 2*time.Second)
	idx := -1
	for i, e := range m.ImportSession.Get().Plan.Entries {
		if e.Item.Name == "GitHub" {
			idx = i
		}
	}

	app.Post(func() { m.SetImportAction(idx, export.ActionUpdate) })
	app.WaitUntil(2*time.Second, func() bool { return m.Reprompt.Get().Open })
	if m.ImportSession.Get().Plan.Entries[idx].Action == export.ActionUpdate {
		t.Fatal("Update was set before the master password was verified")
	}
	app.Post(func() { m.RepromptPW.Set("master-password"); m.SubmitReprompt() })
	app.WaitUntil(2*time.Second, func() bool {
		return m.ImportSession.Get().Plan.Entries[idx].Action == export.ActionUpdate
	})
	app.Press("Apply: 0 create, 1 update, 0 skipped")
	app.WaitUntil(2*time.Second, func() bool { return m.ImportSession.Get() == nil })
	if c, _ := svc.GetCipher("c-github"); c.Login.Password != "backup-password-value" {
		t.Fatal("verified update not applied")
	}
}
