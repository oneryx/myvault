package state

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/crypto"
	"github.com/oneryx/myvault/internal/vaultcore/store"
)

func loggedInTestService(t *testing.T, env *vaultTestEnv) *Service {
	t.Helper()
	svc, err := NewService(ServiceConfig{
		Store:      store.NewFileStore(t.TempDir()),
		Secrets:    newMemSecretStore(),
		HTTPClient: env.server.Client(),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := svc.Login(context.Background(), LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	return svc
}

func TestService_PasswordHistoryOnPasswordChange(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	ctx := context.Background()
	before := time.Now().UTC().Add(-time.Second)

	c, _ := svc.GetCipher("c-1")
	c.Login.Password = "gh-new"
	saved, err := svc.SaveCipher(ctx, c)
	if err != nil {
		t.Fatalf("SaveCipher: %v", err)
	}
	if len(saved.PasswordHistory) != 1 || saved.PasswordHistory[0].Password != "gh-secret" || saved.PasswordHistory[0].LastUsedDate.Before(before) {
		t.Fatalf("history after change = %+v", saved.PasswordHistory)
	}
	if c.PasswordHistory != nil {
		t.Fatalf("SaveCipher mutated the caller's cipher")
	}

	env.mu.Lock()
	stored := env.ciphers["c-1"].PasswordHistory
	env.mu.Unlock()
	if len(stored) != 1 || strings.Contains(stored[0].Password, "gh-secret") {
		t.Fatalf("stored history not encrypted: %+v", stored)
	}
	if pw, err := crypto.DecryptString(stored[0].Password, env.cipherKey); err != nil || pw != "gh-secret" {
		t.Fatalf("stored history decrypt = (%q, %v)", pw, err)
	}

	saved.Name = "Renamed"
	same, err := svc.SaveCipher(ctx, saved)
	if err != nil || len(same.PasswordHistory) != 1 {
		t.Fatalf("unchanged password grew history: %+v, %v", same, err)
	}

	cur := same
	for i := range 6 {
		cur.Login.Password = "pw-" + string(rune('a'+i))
		if cur, err = svc.SaveCipher(ctx, cur); err != nil {
			t.Fatalf("SaveCipher #%d: %v", i, err)
		}
	}
	if len(cur.PasswordHistory) != maxPasswordHistory || cur.PasswordHistory[0].Password != "pw-e" || cur.PasswordHistory[4].Password != "pw-a" {
		t.Fatalf("capped history = %+v", cur.PasswordHistory)
	}
}

func TestService_SSHKeyCipherRoundTrip(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)

	key := &SSHKey{
		PrivateKey:     "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n",
		PublicKey:      "ssh-ed25519 AAAAC3Nza test",
		KeyFingerprint: "SHA256:fingerprint",
	}
	created, err := svc.SaveCipher(context.Background(), &Cipher{Type: api.CipherTypeSSHKey, Name: "Deploy Key", SSHKey: key})
	if err != nil {
		t.Fatalf("SaveCipher: %v", err)
	}
	if created.SSHKey == nil || created.SSHKey.PrivateKey != key.PrivateKey || created.SSHKey.PublicKey != key.PublicKey || created.SSHKey.KeyFingerprint != key.KeyFingerprint {
		t.Fatalf("created SSHKey = %+v", created.SSHKey)
	}

	env.mu.Lock()
	enc := env.ciphers[created.ID].SSHKey
	env.mu.Unlock()
	if enc == nil || enc.PrivateKey == nil || strings.Contains(*enc.PrivateKey, "OPENSSH") {
		t.Fatalf("private key not encrypted: %+v", enc)
	}

	sshType := api.CipherTypeSSHKey
	got := svc.Search("", SearchFilter{Type: &sshType})
	if len(got) != 1 || got[0].ID != created.ID || got[0].Subtitle != key.KeyFingerprint {
		t.Fatalf("Search(SSHKey) = %+v", got)
	}
	loginType := api.CipherTypeLogin
	if logins := svc.Search("", SearchFilter{Type: &loginType}); len(logins) != 1 {
		t.Fatalf("Search(Login) = %+v", logins)
	}
}
