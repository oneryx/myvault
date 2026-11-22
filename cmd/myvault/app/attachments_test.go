package app

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oneryx/myvault/cmd/myvault/core"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

func TestAttachmentsCardUploadDownloadDelete(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers["c-github"].Attachments = []state.Attachment{{ID: "att-1", FileName: "codes.txt", Size: 2048}}

	dir := t.TempDir()
	upload := filepath.Join(dir, "invoice.pdf")
	if err := os.WriteFile(upload, []byte("%PDF-1.7"), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := filepath.Join(dir, "saved.txt")

	app, model := startApp(t, svc, PlatformHooks{
		ChooseSavePath: func(_ string, done func(string, bool, error)) { done(saved, true, nil) },
	}, 1100, 900)
	root := model.Scope
	app.PickFiles = func(core.PickFilesOptions) []core.File {
		return []core.File{{Name: "invoice.pdf", Size: 8, Path: upload}}
	}
	app.OnAlert = func(core.AlertConfig) int { return 1 }

	app.Post(func() { model.SelectCipher(root, "c-github") })
	app.WaitFor("codes.txt", 2*time.Second)
	app.Find("2.0 KB")

	app.Press("Download codes.txt")
	app.WaitUntil(2*time.Second, func() bool {
		data, err := os.ReadFile(saved)
		fi, statErr := os.Stat(saved)
		return err == nil && string(data) == "contents of codes.txt" && statErr == nil && fi.Mode().Perm() == 0o600
	})

	app.Press("Attach File")
	app.WaitFor("invoice.pdf", 2*time.Second)

	app.Press("Delete codes.txt")
	app.WaitForGone("codes.txt", 2*time.Second)
	app.Find("invoice.pdf")
}
