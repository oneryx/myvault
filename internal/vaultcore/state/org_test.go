package state

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/crypto"
	"github.com/oneryx/myvault/internal/vaultcore/realtime"
	"github.com/oneryx/myvault/internal/vaultcore/store"
)

func testKey(t *testing.T, seed byte) (*crypto.SymmetricKey, []byte) {
	t.Helper()
	raw := make([]byte, 64)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	k, err := crypto.SymmetricKeyFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	return k, raw
}

func mustEnc(t *testing.T, plain string, key *crypto.SymmetricKey) *string {
	t.Helper()
	s, err := crypto.EncryptString(plain, key)
	if err != nil {
		t.Fatal(err)
	}
	return &s
}

func TestService_OrganizationCollectionsAndOrgCiphers(t *testing.T) {
	email := "alice@example.com"
	password := []byte("correct-horse-battery-staple")
	kdf := crypto.KDFConfig{Type: crypto.KDFPBKDF2, Iterations: 5000}
	masterKey, _ := crypto.DeriveMasterKey(password, email, kdf)
	stretched, _ := crypto.StretchMasterKey(masterKey)

	userKey, rawUser := testKey(t, 1)
	orgKey, rawOrg := testKey(t, 90)
	cipherKey, rawCipher := testKey(t, 160)
	protectedUserKey, _ := crypto.EncryptBytes(rawUser, stretched)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	encPriv, _ := crypto.EncryptBytes(der, userKey)
	encPrivStr := encPriv.String()
	encOrgKey, _ := crypto.EncryptRSA(rawOrg, &priv.PublicKey, crypto.EncRsa2048OaepSha1B64)
	encCipherKey, _ := crypto.EncryptBytes(rawCipher, orgKey)
	encCipherKeyStr := encCipherKey.String()

	orgID := "org-1"
	rev := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	orgCipher := api.EncryptedCipher{
		ID: "c-org", Type: api.CipherTypeLogin, OrganizationID: &orgID, Key: &encCipherKeyStr,
		Name: *mustEnc(t, "Shared AWS", cipherKey), RevisionDate: &rev,
		CollectionIDs: []string{"col-eng"},
		Login:         &api.EncryptedLogin{Username: mustEnc(t, "ops", cipherKey), Password: mustEnc(t, "s3cret", cipherKey)},
	}
	personal := api.EncryptedCipher{ID: "c-me", Type: api.CipherTypeLogin, Name: *mustEnc(t, "Personal Mail", userKey), RevisionDate: &rev}
	var lastPayload api.CipherPayload
	var lastBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/identity/accounts/prelogin":
			_ = json.NewEncoder(w).Encode(kdf)
		case r.URL.Path == "/identity/connect/token":
			_ = json.NewEncoder(w).Encode(api.TokenResponse{AccessToken: "tok", RefreshToken: "ref", Key: protectedUserKey.String()})
		case r.URL.Path == "/api/accounts/revision-date":
			_ = json.NewEncoder(w).Encode(rev.UnixMilli())
		case r.URL.Path == "/api/sync":
			mu.Lock()
			resp := api.SyncResponse{
				Profile: api.Profile{
					ID: "acct-1", Email: email, Key: protectedUserKey.String(), PrivateKey: &encPrivStr,
					Organizations: []api.ProfileOrganization{
						{ID: orgID, Name: "Acme", Key: encOrgKey.String(), Enabled: true, Status: api.OrganizationStatusConfirmed, Type: 2},
						{ID: "org-disabled", Name: "Old Co", Key: encOrgKey.String(), Enabled: false},
					},
				},
				Ciphers: []api.EncryptedCipher{personal, orgCipher},
				Collections: []api.EncryptedCollection{
					{ID: "col-eng", OrganizationID: orgID, Name: *mustEnc(t, "Engineering", orgKey), HidePasswords: true},
				},
			}
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(resp)
		case r.Method == http.MethodGet && r.URL.Path == "/api/ciphers/c-org":
			mu.Lock()
			out := orgCipher
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(out)
		case r.Method == http.MethodPut && r.URL.Path == "/api/ciphers/c-org":
			body, _ := io.ReadAll(r.Body)
			var p api.CipherPayload
			_ = json.Unmarshal(body, &p)
			mu.Lock()
			lastPayload = p
			lastBody = body
			orgCipher.Name = p.Name
			orgCipher.Login = p.Login
			orgCipher.Key = p.Key
			out := orgCipher
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(out)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	svc, err := NewService(ServiceConfig{Store: store.NewFileStore(t.TempDir()), Secrets: newMemSecretStore(), DeviceID: "dev-1", HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := svc.Login(ctx, LoginRequest{ServerURL: srv.URL, Email: email, MasterPassword: password}); err != nil {
		t.Fatalf("Login: %v", err)
	}

	orgs := svc.Organizations()
	if len(orgs) != 1 || orgs[0].Name != "Acme" {
		t.Fatalf("Organizations = %+v", orgs)
	}
	cols := svc.Collections()
	if len(cols) != 1 || cols[0].Name != "Engineering" || cols[0].OrganizationID != orgID || !cols[0].HidePasswords {
		t.Fatalf("Collections = %+v", cols)
	}

	if all := svc.Search("", SearchFilter{}); len(all) != 2 {
		t.Fatalf("global search = %+v, want personal + org items", all)
	}
	inCol := svc.Search("", SearchFilter{CollectionID: "col-eng"})
	if len(inCol) != 1 || inCol[0].Name != "Shared AWS" || inCol[0].OrganizationID == nil {
		t.Fatalf("collection filter = %+v", inCol)
	}
	if byOrg := svc.Search("aws", SearchFilter{OrganizationID: orgID}); len(byOrg) != 1 {
		t.Fatalf("org filter = %+v", byOrg)
	}

	for _, ac := range svc.AllCiphers() {
		if ac.ID == "c-org" && (!ac.HidePassword || ac.Login.Password != "") {
			t.Fatalf("AllCiphers leaks a collection-hidden password: %+v", ac.Login)
		}
	}

	c, err := svc.GetCipher("c-org")
	if err != nil || c.Login.Password != "s3cret" {
		t.Fatalf("GetCipher = %+v, %v", c, err)
	}
	c.Name = "Shared AWS Prod"
	c.OrganizationID = nil
	c.CollectionIDs = nil
	saved, err := svc.SaveCipher(ctx, c)
	if err != nil {
		t.Fatalf("SaveCipher: %v", err)
	}
	if saved.Name != "Shared AWS Prod" || saved.OrganizationID == nil || *saved.OrganizationID != orgID || len(saved.CollectionIDs) != 1 {
		t.Fatalf("saved = %+v", saved)
	}
	mu.Lock()
	payload := lastPayload
	// An organization item's update names the signed-in user as
	// encryptedFor too, as Bitwarden's clients do.
	orgBody := append([]byte(nil), lastBody...)
	if d, err := decodeAsVaultwarden(orgBody); err != nil || d.EncryptedFor != "acct-1" || d.OrganizationID == nil || *d.OrganizationID != orgID {
		t.Fatalf("Vaultwarden 1.37.5 would refuse the organization update: %v (encryptedFor %q)", err, d.EncryptedFor)
	}
	mu.Unlock()
	if payload.OrganizationID == nil || *payload.OrganizationID != orgID || len(payload.CollectionIDs) != 1 {
		t.Fatalf("payload org/collections = %v %v", payload.OrganizationID, payload.CollectionIDs)
	}
	if name, err := crypto.DecryptString(payload.Name, cipherKey); err != nil || name != "Shared AWS Prod" {
		t.Fatalf("payload name not encrypted with the org-wrapped cipher key: %q %v", name, err)
	}
	if _, err := crypto.DecryptString(*payload.Key, orgKey); err != nil {
		t.Fatalf("cipher key not wrapped with org key: %v", err)
	}

	if err := svc.HandleRealtimeEvent(ctx, realtime.Event{Type: realtime.SyncOrgKeys}); err != nil {
		t.Fatalf("SyncOrgKeys: %v", err)
	}

	svc.mu.Lock()
	svc.ciphers["c-org"].Attachments = []Attachment{{ID: "att-1", FileName: "keys.txt"}}
	svc.mu.Unlock()
	if _, _, err := svc.DownloadAttachment(ctx, "c-org", "att-1"); !errors.Is(err, ErrHiddenByOrganization) {
		t.Fatalf("download with hidden passwords = %v, want ErrHiddenByOrganization", err)
	}
	svc.mu.Lock()
	col := svc.collections["col-eng"]
	col.ReadOnly = true
	svc.collections["col-eng"] = col
	svc.mu.Unlock()
	ro, _ := svc.GetCipher("c-org")
	for name, call := range map[string]func() error{
		"SaveCipher":       func() error { _, err := svc.SaveCipher(ctx, ro); return err },
		"SoftDeleteCipher": func() error { return svc.SoftDeleteCipher(ctx, "c-org") },
		"RestoreCipher":    func() error { return svc.RestoreCipher(ctx, "c-org") },
		"HardDeleteCipher": func() error { return svc.HardDeleteCipher(ctx, "c-org") },
		"UploadAttachment": func() error { _, err := svc.UploadAttachment(ctx, "c-org", "x.txt", []byte("x")); return err },
		"DeleteAttachment": func() error { _, err := svc.DeleteAttachment(ctx, "c-org", "att-1"); return err },
	} {
		if err := call(); !errors.Is(err, ErrReadOnlyCipher) {
			t.Fatalf("%s on a read-only collection item = %v, want ErrReadOnlyCipher", name, err)
		}
	}

	svc.mu.RLock()
	held := svc.orgKeys[orgID]
	svc.mu.RUnlock()
	svc.Lock()
	if raw := held.Bytes(); raw != [64]byte{} {
		t.Fatal("org key not zeroed on Lock")
	}
	if svc.Collections() != nil || svc.Organizations() != nil {
		t.Fatal("collections visible while locked")
	}
}
