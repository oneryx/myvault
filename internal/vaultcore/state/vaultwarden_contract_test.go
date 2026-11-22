package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/crypto"
)

// vaultwardenCipherData mirrors CipherData in Vaultwarden 1.37.5
// (src/api/core/ciphers.rs), which Rocket's Json guard deserializes every
// cipher create and update into; a body that does not fit is answered
// HTTP 422. Values Vaultwarden takes as serde_json::Value are left raw.
type vaultwardenCipherData struct {
	ID                    *string                      `json:"id"`
	FolderID              *string                      `json:"folderId"`
	OrganizationID        *string                      `json:"organizationId"`
	Key                   *string                      `json:"key"`
	EncryptedFor          string                       `json:"encryptedFor"`
	EncryptedByKeyID      *string                      `json:"encryptedByKeyId"`
	Type                  int32                        `json:"type"`
	Name                  string                       `json:"name"`
	Notes                 *string                      `json:"notes"`
	Fields                json.RawMessage              `json:"fields"`
	Login                 json.RawMessage              `json:"login"`
	SecureNote            json.RawMessage              `json:"secureNote"`
	Card                  json.RawMessage              `json:"card"`
	Identity              json.RawMessage              `json:"identity"`
	SSHKey                json.RawMessage              `json:"sshKey"`
	Favorite              *bool                        `json:"favorite"`
	Reprompt              *int32                       `json:"reprompt"`
	PasswordHistory       json.RawMessage              `json:"passwordHistory"`
	Attachments           json.RawMessage              `json:"attachments"`
	Attachments2          map[string]vaultwardenAttach `json:"attachments2"`
	LastKnownRevisionDate *string                      `json:"lastKnownRevisionDate"`
	ArchivedDate          *string                      `json:"archivedDate"`
}

type vaultwardenAttach struct {
	FileName string `json:"fileName"`
	Key      string `json:"key"`
}

// vaultwardenRequired are the CipherData fields with neither Option nor a
// serde default in 1.37.5: serde refuses a body without any of them.
var vaultwardenRequired = []string{"type", "name", "encryptedFor"}

// decodeAsVaultwarden decodes body the way Vaultwarden 1.37.5 does, and
// reports what it would refuse.
func decodeAsVaultwarden(body []byte) (vaultwardenCipherData, error) {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(body, &keys); err != nil {
		return vaultwardenCipherData{}, err
	}
	for _, k := range vaultwardenRequired {
		if v, ok := keys[k]; !ok || bytes.Equal(v, []byte("null")) {
			return vaultwardenCipherData{}, fmt.Errorf("missing field `%s`", k)
		}
	}
	var d vaultwardenCipherData
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&d); err != nil {
		return d, err
	}
	return d, nil
}

func TestVaultwardenAcceptsAPasswordChangeUpdate(t *testing.T) {
	env := newVaultTestEnv(t)
	seedSealedLogin(t, env) // history, URIs with checksums, fields, passkeys, unknown fields
	svc := loggedInTestService(t, env)
	c, err := svc.GetCipher("c-1")
	if err != nil {
		t.Fatal(err)
	}
	c.Login.Password = "a-brand-new-password"
	if _, err := svc.SaveCipher(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	env.mu.Lock()
	body := append([]byte(nil), env.lastBody...)
	env.mu.Unlock()

	d, err := decodeAsVaultwarden(body)
	if err != nil {
		t.Fatalf("Vaultwarden 1.37.5 would answer 422: %v\nbody: %s", err, body)
	}
	if d.EncryptedFor != env.profileID {
		t.Fatalf("encryptedFor = %q, want the signed-in user %q (Vaultwarden refuses any other)", d.EncryptedFor, env.profileID)
	}
	if d.Type != int32(api.CipherTypeLogin) || d.Name == "" || d.LastKnownRevisionDate == nil {
		t.Fatalf("decoded %+v", d)
	}
	if _, err := crypto.ParseEncString(d.Name); err != nil {
		t.Fatalf("name is not an EncString: %q", d.Name)
	}
}

func TestVaultwardenAcceptsACreate(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	if _, err := svc.SaveCipher(context.Background(), &Cipher{Type: api.CipherTypeSecureNote, Name: "New", SecureNote: &SecureNote{}}); err != nil {
		t.Fatal(err)
	}
	env.mu.Lock()
	body := append([]byte(nil), env.lastBody...)
	env.mu.Unlock()
	d, err := decodeAsVaultwarden(body)
	if err != nil {
		t.Fatalf("Vaultwarden 1.37.5 would answer 422 to a create: %v\nbody: %s", err, body)
	}
	if d.EncryptedFor != env.profileID {
		t.Fatalf("encryptedFor = %q, want %q", d.EncryptedFor, env.profileID)
	}
}

func TestVaultwardenAcceptsEveryKindOfItemWrite(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	ctx := context.Background()
	check := func(what string) {
		t.Helper()
		env.mu.Lock()
		body := append([]byte(nil), env.lastBody...)
		env.mu.Unlock()
		d, err := decodeAsVaultwarden(body)
		if err != nil || d.EncryptedFor != env.profileID {
			t.Fatalf("%s: Vaultwarden 1.37.5 would answer 422: %v (encryptedFor %q)", what, err, d.EncryptedFor)
		}
	}
	for what, change := range map[string]func(c *Cipher){
		"favorite":    func(c *Cipher) { c.Favorite = !c.Favorite },
		"folder move": func(c *Cipher) { c.FolderID = nil },
		"rename":      func(c *Cipher) { c.Name = "Renamed" },
	} {
		c, _ := svc.GetCipher("c-1")
		change(c)
		if _, err := svc.SaveCipher(ctx, c); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		check(what)
	}
	// A clone or an import creates a new item from a copy of another.
	c, _ := svc.GetCipher("c-1")
	c.ID, c.Key, c.Name = "", nil, "GitHub (Copy)"
	if _, err := svc.SaveCipher(ctx, c); err != nil {
		t.Fatal(err)
	}
	check("clone")
}

func TestEncryptedForIsTheSessionUser(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	if _, err := svc.SaveCipher(context.Background(), &Cipher{Type: api.CipherTypeSecureNote, Name: "x", SecureNote: &SecureNote{}}); err != nil {
		t.Fatal(err)
	}
	env.mu.Lock()
	body := append([]byte(nil), env.lastBody...)
	env.mu.Unlock()
	if d, err := decodeAsVaultwarden(body); err != nil || d.EncryptedFor != env.profileID {
		t.Fatalf("encryptedFor = %q, %v; want the profile ID %q", d.EncryptedFor, err, env.profileID)
	}
}

func TestEmailKeyedSessionGetsItsUserIDFromSync(t *testing.T) {
	env := newVaultTestEnv(t)
	env.profileID = "" // the server sent no profile ID at sign-in
	svc := loggedInTestService(t, env)
	if svc.accountID == "" {
		t.Fatal("no account")
	}

	// Without an ID from the server, nothing is written.
	if _, err := svc.SaveCipher(context.Background(), &Cipher{Type: api.CipherTypeSecureNote, Name: "x", SecureNote: &SecureNote{}}); !errors.Is(err, ErrAccountIDUnknown) {
		t.Fatalf("save without a server user ID = %v, want ErrAccountIDUnknown", err)
	}
	env.mu.Lock()
	sent := env.lastBody
	env.mu.Unlock()
	if sent != nil {
		t.Fatalf("a write was sent without encryptedFor: %s", sent)
	}

	// The server now sends it: the save syncs, learns it and sends it.
	env.mu.Lock()
	env.profileID = "uuid-of-alice"
	env.mu.Unlock()
	if _, err := svc.SaveCipher(context.Background(), &Cipher{Type: api.CipherTypeSecureNote, Name: "y", SecureNote: &SecureNote{}}); err != nil {
		t.Fatal(err)
	}
	env.mu.Lock()
	body := append([]byte(nil), env.lastBody...)
	env.mu.Unlock()
	if d, err := decodeAsVaultwarden(body); err != nil || d.EncryptedFor != "uuid-of-alice" {
		t.Fatalf("encryptedFor = %q, %v; want the ID the sync gave", d.EncryptedFor, err)
	}
	if svc.accountID == "uuid-of-alice" {
		t.Fatal("the local storage key changed; it must stay as the vault was saved")
	}
}
