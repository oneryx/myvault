package app

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/state"
)

func verifyReprompt(app *testApp, m *AppModel) {
	app.WaitUntil(2*time.Second, func() bool { return m.Reprompt.Get().Open })
	app.Post(func() {
		m.RepromptPW.Set("master-password")
		m.SubmitReprompt()
	})
	app.WaitUntil(2*time.Second, func() bool { return !m.Reprompt.Get().Open })
}

func TestRepromptGatesEditAndTOTP(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers["c-github"].Reprompt = 1
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})

	app.Post(func() { m.SelectCipher(root, "c-github") })
	app.WaitFor("Verification Code", 2*time.Second)
	app.WaitUntil(2*time.Second, func() bool { return m.TOTPCode.Get() != "" })
	code := m.TOTPCode.Get()
	if app.Contains(FormatTOTPCode(code)) {
		t.Fatal("live TOTP code shown before reprompt")
	}
	app.Find("••• •••")

	app.Press("Reveal verification code")
	verifyReprompt(app, m)
	app.WaitUntil(2*time.Second, func() bool { return m.TOTPRevealedID.Get() == "c-github" })

	app.Press("Edit")
	app.WaitUntil(2*time.Second, func() bool { return m.Reprompt.Get().Open })
	if m.EditMode.Get() || m.EditDraft.Get() != nil {
		t.Fatal("edit draft built before reprompt")
	}
	verifyReprompt(app, m)
	app.WaitUntil(2*time.Second, func() bool { return m.EditMode.Get() && m.EditDraft.Get() != nil })
}

func TestLockRevokesPendingSecretActions(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers["c-github"].Reprompt = 1
	svc.ciphers["c-github"].Attachments = []state.Attachment{{ID: "att-1", FileName: "codes.txt"}}
	var copies atomic.Int32
	var chooses atomic.Int32
	app, m, root := startSecurityApp(t, svc, PlatformHooks{
		CopySecret:     func(string, time.Duration) (bool, error) { copies.Add(1); return true, nil },
		ChooseSavePath: func(string, func(string, bool, error)) { chooses.Add(1) },
	})

	app.Post(func() { m.SelectCipher(root, "c-github") })
	app.WaitFor("Copy password", 2*time.Second)
	app.Press("Copy password")
	app.WaitUntil(2*time.Second, func() bool { return m.Reprompt.Get().Open })
	allow := m.Reprompt.Get().OnAllow
	app.Post(m.Lock)
	app.WaitFor("MyVault is Locked", 2*time.Second)
	if m.Reprompt.Get().Open {
		t.Fatal("reprompt dialog survived lock")
	}
	app.Post(allow)
	app.Post(func() {})
	if copies.Load() != 0 {
		t.Fatal("secret copied after lock")
	}

	svc.mu.Lock()
	svc.status = state.StatusUnlocked
	svc.ciphers["c-github"].Reprompt = 0
	svc.downloadGate = make(chan struct{})
	svc.mu.Unlock()
	app.Post(func() {
		m.LockState.Set(state.StatusUnlocked)
		m.RefreshVaultData()
		m.SelectCipher(root, "c-github")
	})
	app.WaitFor("Download codes.txt", 2*time.Second)
	app.Press("Download codes.txt")
	app.WaitUntil(2*time.Second, func() bool { return m.AttachmentBusy.Get() == "att-1" })
	app.Post(m.Lock)
	close(svc.downloadGate)
	time.Sleep(50 * time.Millisecond)
	app.Post(func() {})
	if chooses.Load() != 0 {
		t.Fatalf("save dialog opened after lock: %d", chooses.Load())
	}
}

func TestHiddenPasswordsHideAttachmentAndHiddenFields(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	c := svc.ciphers["c-github"]
	c.HidePassword = true
	c.Attachments = []state.Attachment{{ID: "att-1", FileName: "codes.txt"}}
	c.Fields = []state.CustomField{{Name: "Recovery", Value: "hidden-recovery-value", Type: 1}}
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})

	app.Post(func() { m.SelectCipher(root, "c-github") })
	app.WaitFor("codes.txt", 2*time.Second)
	if app.Exists("Download codes.txt") {
		t.Fatal("download offered for an item with hidden passwords")
	}
	app.Find("Recovery")
	if app.Exists("Reveal recovery") || app.Exists("Copy recovery") || app.Contains("hidden-recovery-value") || !app.Exists("Hidden by your organization") {
		t.Fatal("hidden custom field can be revealed or copied")
	}
}

func TestRevokedAttachmentSaveLeavesDestinationUntouched(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers["c-github"].Attachments = []state.Attachment{{ID: "att-1", FileName: "codes.txt"}}
	dir := t.TempDir()
	dest := filepath.Join(dir, "codes.txt")
	if err := os.WriteFile(dest, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	var pending func(string, bool, error)
	app, m, root := startSecurityApp(t, svc, PlatformHooks{
		ChooseSavePath: func(_ string, done func(string, bool, error)) { pending = done },
	})
	untouched := func(when string) {
		t.Helper()
		data, err := os.ReadFile(dest)
		entries, _ := os.ReadDir(dir)
		if err != nil || string(data) != "original" || len(entries) != 1 {
			t.Fatalf("%s: destination = (%q, %v), %d entries", when, data, err, len(entries))
		}
	}

	app.Post(func() { m.SelectCipher(root, "c-github") })
	app.WaitFor("Download codes.txt", 2*time.Second)
	app.Press("Download codes.txt")
	app.WaitUntil(2*time.Second, func() bool { return pending != nil })
	app.Post(m.Lock)
	pending(dest, true, nil)
	app.Post(func() {})
	time.Sleep(50 * time.Millisecond)
	untouched("save confirmed after lock")

	explicit := saveTarget{dir: dir, name: "codes.txt", replace: true}
	gen := m.LockGeneration()
	m.RevokePending()
	if _, published, err := m.savePrivateFile(gen, explicit, []byte("plaintext")); published || err != nil {
		t.Fatalf("revoked publish = (%v, %v)", published, err)
	}
	untouched("revoked before rename")

	if _, published, err := m.savePrivateFile(m.LockGeneration(), saveTarget{dir: filepath.Join(dir, "missing"), name: "x.txt", replace: true}, []byte("plaintext")); published || err == nil {
		t.Fatalf("failed write = (%v, %v)", published, err)
	}
	untouched("failed write")

	blocker := filepath.Join(dir, "blocker")
	if err := os.MkdirAll(filepath.Join(blocker, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, published, err := m.savePrivateFile(m.LockGeneration(), saveTarget{dir: dir, name: "blocker", replace: true}, []byte("plaintext")); published || err == nil {
		t.Fatalf("failed rename = (%v, %v)", published, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Fatalf("failed rename left a temporary file: %d entries", len(entries))
	}
	if err := os.RemoveAll(blocker); err != nil {
		t.Fatal(err)
	}

	path, published, err := m.savePrivateFile(m.LockGeneration(), saveTarget{dir: dir, name: "codes.txt"}, []byte("plaintext"))
	if !published || err != nil || path != filepath.Join(dir, "codes (2).txt") {
		t.Fatalf("no-replace publish = (%q, %v, %v)", path, published, err)
	}
	if data, _ := os.ReadFile(path); string(data) != "plaintext" {
		t.Fatalf("no-replace content = %q", data)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	untouched("folder fallback")

	if path, published, err := m.savePrivateFile(m.LockGeneration(), explicit, []byte("plaintext")); !published || err != nil || path != dest {
		t.Fatalf("publish = (%q, %v, %v)", path, published, err)
	}
	if data, _ := os.ReadFile(dest); string(data) != "plaintext" {
		t.Fatalf("published content = %q", data)
	}
	if fi, _ := os.Stat(dest); fi.Mode().Perm() != 0o600 {
		t.Fatalf("published mode = %v", fi.Mode().Perm())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("publish left a temporary file: %d entries", len(entries))
	}
}

func TestTOTPRevealBoundToCipher(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers["c-github"].Reprompt = 1
	other := *svc.ciphers["c-github"]
	other.ID, other.Name = "c-gitlab", "GitLab"
	login := *other.Login
	other.Login = &login
	svc.ciphers[other.ID] = &other
	svc.order = append(svc.order, other.ID)
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})

	app.Post(func() { m.SelectCipher(root, "c-github") })
	app.WaitFor("Reveal verification code", 2*time.Second)
	app.Press("Reveal verification code")
	app.WaitUntil(2*time.Second, func() bool { return m.Reprompt.Get().Open })
	app.Post(func() { m.SelectCipher(root, "c-gitlab") })
	app.WaitUntil(2*time.Second, func() bool { c := m.ActiveCipher.Get(); return c != nil && c.ID == "c-gitlab" })
	verifyReprompt(app, m)
	app.Post(func() {})
	if id := m.TOTPRevealedID.Get(); id != "" {
		t.Fatalf("approval for c-github revealed %q", id)
	}
	app.WaitUntil(2*time.Second, func() bool { return m.TOTPCode.Get() != "" })
	app.Find("••• •••")
}
