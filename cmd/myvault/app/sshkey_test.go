package app

import (
	"sync"
	"testing"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/gen"
	"github.com/oneryx/myvault/internal/vaultcore/sshagent"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

type fakeAgentHost struct {
	mu      sync.Mutex
	running bool
	keys    []sshagent.Key
}

func (h *fakeAgentHost) SocketPath() string { return "/tmp/myvault-test/ssh-agent.sock" }
func (h *fakeAgentHost) Start() error       { h.mu.Lock(); h.running = true; h.mu.Unlock(); return nil }
func (h *fakeAgentHost) Stop()              { h.mu.Lock(); h.running, h.keys = false, nil; h.mu.Unlock() }
func (h *fakeAgentHost) SetKeys(k []sshagent.Key) {
	h.mu.Lock()
	h.keys = k
	h.mu.Unlock()
}
func (h *fakeAgentHost) Clear() { h.SetKeys(nil) }

func (h *fakeAgentHost) state() (bool, []sshagent.Key) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.running, h.keys
}

func TestSSHAgentServesEligibleKeysWhileUnlocked(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	key, err := gen.GenerateEd25519SSHKey("deploy")
	if err != nil {
		t.Fatal(err)
	}
	deleted := time.Now()
	for _, c := range []*state.Cipher{
		{ID: "ssh-ok", Name: "Deploy Key"},
		{ID: "ssh-reprompt", Name: "Reprompt Key", Reprompt: 1},
		{ID: "ssh-hidden", Name: "Hidden Key", HidePassword: true},
		{ID: "ssh-trash", Name: "Old Key", DeletedDate: &deleted},
	} {
		c.Type = api.CipherTypeSSHKey
		c.SSHKey = &state.SSHKey{PrivateKey: key.PrivateKey, PublicKey: key.PublicKey, KeyFingerprint: key.KeyFingerprint}
		svc.ciphers[c.ID] = c
		svc.order = append(svc.order, c.ID)
	}
	svc.ciphers["c-github"].PasswordHistory = []state.PasswordHistoryEntry{{Password: "old-gh-password", LastUsedDate: deleted}}

	host := &fakeAgentHost{}
	app, model := startApp(t, svc, PlatformHooks{SSHAgent: host}, 1100, 900)
	root := model.Scope
	app.WaitFor("SSH Keys", 2*time.Second)
	if model.AllCounts.Get().SSHKey != 3 {
		t.Fatalf("SSHKey count = %d, want 3", model.AllCounts.Get().SSHKey)
	}
	if running, _ := host.state(); running {
		t.Fatal("ssh agent started while disabled")
	}

	app.Post(func() { model.SelectCipher(root, "ssh-ok") })
	app.WaitFor("Fingerprint", 2*time.Second)
	app.Find("Copy public key")
	app.Find("Reveal private key")

	app.Post(func() { model.SelectCipher(root, "c-github") })
	app.WaitFor("Password History (1)", 2*time.Second)
	app.Press("Password History (1)")
	app.WaitFor("Reveal old password", 2*time.Second)

	app.Post(func() { model.Route.Set(RouteSettings) })
	app.WaitFor("Enable SSH agent", 2*time.Second)
	app.Press("Enable SSH agent")
	app.WaitUntil(2*time.Second, func() bool {
		running, keys := host.state()
		return running && len(keys) == 1 && keys[0].Comment == "Deploy Key"
	})
	app.Find("Copy SSH_AUTH_SOCK")

	app.Press("Enable SSH agent")
	app.WaitUntil(2*time.Second, func() bool { running, _ := host.state(); return !running })
	app.Press("Enable SSH agent")
	app.WaitUntil(2*time.Second, func() bool { _, keys := host.state(); return len(keys) == 1 })

	app.Post(model.Lock)
	app.WaitUntil(2*time.Second, func() bool {
		running, keys := host.state()
		return running && len(keys) == 0
	})
}
