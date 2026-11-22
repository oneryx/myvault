package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/crypto"
)

// sealedFixture is what a newer Bitwarden server or client stores on a
// login and MyVault does not model: values that must come back byte for
// byte on every save under the same key.
type sealedFixture struct {
	passkey       json.RawMessage
	uriChecksum   string
	sealedLogin   string
	sealedTop     string
	sealedHistory string
}

func mustEncString(t *testing.T, plain string, key *crypto.SymmetricKey) string {
	t.Helper()
	enc, err := crypto.EncryptString(plain, key)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func checksumPlain(uri string) string {
	sum := sha256.Sum256([]byte(uri))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// seedSealedLogin replaces c-1 (encrypted with its own cipher key) with a
// login carrying a passkey, autofillOnPageLoad, a URI checksum and unknown
// fields at every nested level.
func seedSealedLogin(t *testing.T, env *vaultTestEnv) sealedFixture {
	t.Helper()
	k := env.cipherKey
	e := func(s string) string { return mustEncString(t, s, k) }
	fx := sealedFixture{
		uriChecksum:   e(checksumPlain("https://github.com")),
		sealedLogin:   e("future login secret"),
		sealedTop:     e("future cipher secret"),
		sealedHistory: e("future history secret"),
	}
	fx.passkey = json.RawMessage(fmt.Sprintf(
		`{"credentialId":%q,"keyType":%q,"keyAlgorithm":%q,"keyCurve":%q,"keyValue":%q,"rpId":%q,"userHandle":%q,"userName":%q,"counter":%q,"rpName":%q,"userDisplayName":%q,"discoverable":%q,"creationDate":"2026-03-14T10:22:00.000Z","futurePasskeyField":1}`,
		e("cred-id-1"), e("public-key"), e("ECDSA"), e("P-256"), e("private-key-material"), e("github.com"),
		e("user-handle"), e("alice"), e("0"), e("GitHub"), e("Alice"), e("true")))

	env.mu.Lock()
	defer env.mu.Unlock()
	c := env.ciphers["c-1"]
	var login api.EncryptedLogin
	loginJSON := fmt.Sprintf(`{"username":%q,"password":%q,"totp":null,"uris":[{"uri":%q,"match":null,"uriChecksum":%q,"futureUriField":7}],"fido2Credentials":[%s],"autofillOnPageLoad":true,"futureLoginField":{"nested":"plain"},"sealedLoginField":%q}`,
		*c.Login.Username, *c.Login.Password, *c.Login.URIs[0].URI, fx.uriChecksum, fx.passkey, fx.sealedLogin)
	if err := json.Unmarshal([]byte(loginJSON), &login); err != nil {
		t.Fatal(err)
	}
	c.Login = &login
	var field api.EncryptedField
	_ = json.Unmarshal([]byte(fmt.Sprintf(`{"name":%q,"value":%q,"type":0,"linkedId":null,"futureFieldField":"keep"}`, e("PIN"), e("1234"))), &field)
	c.Fields = []api.EncryptedField{field}
	var hist api.EncryptedPasswordHistory
	_ = json.Unmarshal([]byte(fmt.Sprintf(`{"password":%q,"lastUsedDate":"2025-01-02T03:04:05Z","futureHistoryField":%q}`, e("older-password"), fx.sealedHistory)), &hist)
	c.PasswordHistory = []api.EncryptedPasswordHistory{hist}
	c.Extra = map[string]json.RawMessage{
		"futureCipherField": json.RawMessage(`"plain"`),
		"sealedCipherField": json.RawMessage(fmt.Sprintf("%q", fx.sealedTop)),
	}
	env.ciphers["c-1"] = c
	return fx
}

type jsonObj = map[string]json.RawMessage

func obj(t *testing.T, raw json.RawMessage) jsonObj {
	t.Helper()
	var m jsonObj
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("not an object: %s", raw)
	}
	return m
}

func arr(t *testing.T, raw json.RawMessage) []json.RawMessage {
	t.Helper()
	var a []json.RawMessage
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatalf("not an array: %s", raw)
	}
	return a
}

func sameJSON(t *testing.T, what string, got json.RawMessage, want string) {
	t.Helper()
	if !bytes.Equal(got, []byte(want)) {
		t.Fatalf("%s = %s, want %s", what, got, want)
	}
}

func (env *vaultTestEnv) body(t *testing.T) jsonObj {
	t.Helper()
	env.mu.Lock()
	defer env.mu.Unlock()
	return obj(t, env.lastBody)
}

// assertSealedKept checks a save under the original key sent every sealed
// and unknown value back unchanged.
func assertSealedKept(t *testing.T, step string, body jsonObj, fx sealedFixture) {
	t.Helper()
	sameJSON(t, step+": futureCipherField", body["futureCipherField"], `"plain"`)
	sameJSON(t, step+": sealedCipherField", body["sealedCipherField"], fmt.Sprintf("%q", fx.sealedTop))
	login := obj(t, body["login"])
	sameJSON(t, step+": fido2Credentials", login["fido2Credentials"], "["+string(fx.passkey)+"]")
	sameJSON(t, step+": autofillOnPageLoad", login["autofillOnPageLoad"], `true`)
	sameJSON(t, step+": futureLoginField", login["futureLoginField"], `{"nested":"plain"}`)
	sameJSON(t, step+": sealedLoginField", login["sealedLoginField"], fmt.Sprintf("%q", fx.sealedLogin))
	uri := obj(t, arr(t, login["uris"])[0])
	sameJSON(t, step+": uriChecksum", uri["uriChecksum"], fmt.Sprintf("%q", fx.uriChecksum))
	sameJSON(t, step+": futureUriField", uri["futureUriField"], `7`)
	field := obj(t, arr(t, body["fields"])[0])
	sameJSON(t, step+": futureFieldField", field["futureFieldField"], `"keep"`)
	found := false
	for _, h := range arr(t, body["passwordHistory"]) {
		if v, ok := obj(t, h)["futureHistoryField"]; ok {
			sameJSON(t, step+": futureHistoryField", v, fmt.Sprintf("%q", fx.sealedHistory))
			found = true
		}
	}
	if !found {
		t.Fatalf("%s: password history lost its unknown field", step)
	}
}

func TestService_SavesKeepPasskeysAndUnknownNestedFields(t *testing.T) {
	env := newVaultTestEnv(t)
	fx := seedSealedLogin(t, env)
	svc := loggedInTestService(t, env)
	ctx := context.Background()

	c, err := svc.GetCipher("c-1")
	if err != nil || c.Login == nil || len(c.Login.Fido2Credentials) != 1 {
		t.Fatalf("GetCipher = %+v, %v", c, err)
	}
	if p := c.Login.Fido2Credentials[0]; p.RpID != "github.com" || p.RpName != "GitHub" || p.CreationDate != "2026-03-14T10:22:00.000Z" || p.KeyValue != "private-key-material" {
		t.Fatalf("decrypted passkey = %+v", p)
	}

	steps := []struct {
		name   string
		mutate func(c *Cipher)
	}{
		{"edit another field", func(c *Cipher) { c.Name = "GitHub (work)" }},
		{"toggle favorite", func(c *Cipher) { c.Favorite = !c.Favorite }},
		{"change password", func(c *Cipher) { c.Login.Password = "a-new-password" }},
	}
	for _, step := range steps {
		c, err := svc.GetCipher("c-1")
		if err != nil {
			t.Fatal(err)
		}
		step.mutate(c)
		if _, err := svc.SaveCipher(ctx, c); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		assertSealedKept(t, step.name, env.body(t), fx)
	}

	c, _ = svc.GetCipher("c-1")
	if len(c.PasswordHistory) != 2 || c.PasswordHistory[0].Password != "gh-secret" || c.PasswordHistory[1].Password != "older-password" {
		t.Fatalf("history after password change = %+v", c.PasswordHistory)
	}
}

func TestService_URIChecksumKeptOrRecomputed(t *testing.T) {
	env := newVaultTestEnv(t)
	fx := seedSealedLogin(t, env)
	svc := loggedInTestService(t, env)

	c, _ := svc.GetCipher("c-1")
	c.Login.URIs[0].URI = "https://github.com/login"
	c.Login.URIs = append(c.Login.URIs, LoginURI{URI: "https://gist.github.com"})
	if _, err := svc.SaveCipher(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	uris := arr(t, obj(t, env.body(t)["login"])["uris"])
	for i, want := range []string{"https://github.com/login", "https://gist.github.com"} {
		u := obj(t, uris[i])
		var cs string
		_ = json.Unmarshal(u["uriChecksum"], &cs)
		if cs == fx.uriChecksum {
			t.Fatalf("uri %d kept the checksum of the old text", i)
		}
		plain, err := crypto.DecryptString(cs, env.cipherKey)
		if err != nil || plain != checksumPlain(want) {
			t.Fatalf("uri %d checksum = (%q, %v), want base64 SHA-256 of %q", i, plain, err, want)
		}
	}
	sameJSON(t, "edited uri futureUriField", obj(t, uris[0])["futureUriField"], `7`)
}

func TestURIChecksumMatchesBitwarden(t *testing.T) {
	key, _ := crypto.GenerateSymmetricKey()
	cs, err := uriChecksum("https://test.com", key)
	if err != nil {
		t.Fatal(err)
	}
	// Vector from bitwarden/sdk-internal, LoginUriView::generate_checksum.
	if plain, err := crypto.DecryptString(*cs, key); err != nil || plain != "OWk2vQvwYD1nhLZdA+ltrpBWbDa2JmHyjUEWxRZSS8w=" {
		t.Fatalf("checksum = (%q, %v)", plain, err)
	}
}

func TestService_KeyChangeDropsSealedValuesOnly(t *testing.T) {
	env := newVaultTestEnv(t)
	fx := seedSealedLogin(t, env)
	svc := loggedInTestService(t, env)

	// A copy under another key: c-1 has its own cipher key; the copy is a
	// new personal item encrypted with the user key.
	c, _ := svc.GetCipher("c-1")
	c.ID, c.Key, c.Name = "", nil, "GitHub (Copy)"
	if _, err := svc.SaveCipher(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	body := env.body(t)
	login := obj(t, body["login"])
	if _, ok := login["fido2Credentials"]; ok {
		t.Fatal("a passkey sealed with the old key was sent with a copy")
	}
	for _, k := range []string{"sealedLoginField"} {
		if _, ok := login[k]; ok {
			t.Fatalf("login %s sealed with the old key was sent", k)
		}
	}
	if _, ok := body["sealedCipherField"]; ok {
		t.Fatal("cipher field sealed with the old key was sent")
	}
	sameJSON(t, "plaintext autofillOnPageLoad", login["autofillOnPageLoad"], `true`)
	sameJSON(t, "plaintext futureLoginField", login["futureLoginField"], `{"nested":"plain"}`)
	sameJSON(t, "plaintext futureCipherField", body["futureCipherField"], `"plain"`)
	uri := obj(t, arr(t, login["uris"])[0])
	sameJSON(t, "plaintext futureUriField", uri["futureUriField"], `7`)
	var cs string
	_ = json.Unmarshal(uri["uriChecksum"], &cs)
	if cs == fx.uriChecksum {
		t.Fatal("old-key URI checksum sent with a copy")
	}
	if plain, err := crypto.DecryptString(cs, env.userKey); err != nil || plain != checksumPlain("https://github.com") {
		t.Fatalf("copy checksum under the new key = (%q, %v)", plain, err)
	}
	for _, h := range arr(t, body["passwordHistory"]) {
		if _, ok := obj(t, h)["futureHistoryField"]; ok {
			t.Fatal("password history field sealed with the old key was sent")
		}
	}
}

func TestService_OtherTypesKeepUnknownFields(t *testing.T) {
	env := newVaultTestEnv(t)
	k := env.userKey
	e := func(s string) string { return mustEncString(t, s, k) }
	sealed := e("future secret")
	rev := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	nested := func(known string) string {
		return fmt.Sprintf(`{%s"futurePlain":"keep","futureSealed":%q}`, known, sealed)
	}
	items := map[string]struct {
		t    api.CipherType
		json string
		key  string
	}{
		"c-card":     {api.CipherTypeCard, nested(fmt.Sprintf(`"cardholderName":%q,"brand":null,"number":%q,"expMonth":null,"expYear":null,"code":null,`, e("Alice"), e("4111"))), "card"},
		"c-identity": {api.CipherTypeIdentity, nested(fmt.Sprintf(`"firstName":%q,"address2":%q,`, e("Alice"), e("Apt 4"))), "identity"},
		"c-note":     {api.CipherTypeSecureNote, nested(`"type":0,`), "secureNote"},
		"c-ssh":      {api.CipherTypeSSHKey, nested(fmt.Sprintf(`"privateKey":%q,"publicKey":%q,"keyFingerprint":%q,`, e("priv"), e("pub"), e("SHA256:x"))), "sshKey"},
	}
	env.mu.Lock()
	for id, it := range items {
		raw := fmt.Sprintf(`{"id":%q,"type":%d,"name":%q,"revisionDate":%q,%q:%s}`, id, it.t, e("Item "+id), rev.Format(time.RFC3339), it.key, it.json)
		var c api.EncryptedCipher
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			t.Fatal(err)
		}
		env.ciphers[id] = c
	}
	env.mu.Unlock()
	svc := loggedInTestService(t, env)

	for id, it := range items {
		c, err := svc.GetCipher(id)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		c.Name = "Renamed " + id
		if _, err := svc.SaveCipher(context.Background(), c); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		part := obj(t, env.body(t)[it.key])
		sameJSON(t, id+" futurePlain", part["futurePlain"], `"keep"`)
		sameJSON(t, id+" futureSealed", part["futureSealed"], fmt.Sprintf("%q", sealed))
	}
	if c, _ := svc.GetCipher("c-identity"); c.Identity.Address2 != "Apt 4" {
		t.Fatalf("identity address2 = %q", c.Identity.Address2)
	}
}

func TestService_ImportedPasskeyIsSealedWithTheNewItemKey(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	_, err := svc.SaveCipher(context.Background(), &Cipher{Type: api.CipherTypeLogin, Name: "Imported", Login: &Login{
		Username:         "alice",
		Fido2Credentials: []Fido2Credential{{CredentialID: "cred-1", KeyValue: "private-key", RpID: "example.com", CreationDate: "2026-03-14T10:22:00Z"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	pk := obj(t, arr(t, obj(t, env.body(t)["login"])["fido2Credentials"])[0])
	sameJSON(t, "creationDate stays plaintext", pk["creationDate"], `"2026-03-14T10:22:00Z"`)
	for field, want := range map[string]string{"credentialId": "cred-1", "keyValue": "private-key", "rpId": "example.com"} {
		var enc string
		_ = json.Unmarshal(pk[field], &enc)
		if got, err := crypto.DecryptString(enc, env.userKey); err != nil || got != want {
			t.Fatalf("%s = (%q, %v), want %q sealed with the item key", field, got, err, want)
		}
	}
}

func b64(n int) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, n)) }

// seedLoginExtra puts extra on c-1 (sealed with its own cipher key).
func seedLoginExtra(t *testing.T, env *vaultTestEnv, extra map[string]json.RawMessage) {
	t.Helper()
	seedSealedLogin(t, env)
	env.mu.Lock()
	defer env.mu.Unlock()
	c := env.ciphers["c-1"]
	login := *c.Login
	login.Extra = extra
	c.Login = &login
	env.ciphers["c-1"] = c
}

// copyUnderNewKey saves c-1 as a new personal item, under the user key.
func copyUnderNewKey(t *testing.T, svc *Service) error {
	t.Helper()
	cp, _ := svc.GetCipher("c-1")
	cp.ID, cp.Key, cp.Name = "", nil, "GitHub (Copy)"
	cp.Login.Fido2Credentials = nil
	_, err := svc.SaveCipher(context.Background(), cp)
	return err
}

func TestService_KeyChangeDropsOnlyProvenOldKeyCiphertext(t *testing.T) {
	env := newVaultTestEnv(t)
	sealed := mustEncString(t, "secret", env.cipherKey)
	seedLoginExtra(t, env, map[string]json.RawMessage{
		"year":         json.RawMessage(`"1.2024"`),
		"oldKey":       json.RawMessage(fmt.Sprintf("%q", sealed)),
		"mixed":        json.RawMessage(fmt.Sprintf(`{"secret":%q,"flag":true,"note":"1.0","deep":{"s":%q,"n":2}}`, sealed, sealed)),
		"plainVersion": json.RawMessage(`"1.0"`),
	})
	svc := loggedInTestService(t, env)
	if err := copyUnderNewKey(t, svc); err != nil {
		t.Fatal(err)
	}
	got := obj(t, env.body(t)["login"])
	if _, ok := got["oldKey"]; ok {
		t.Fatal("proven old-key ciphertext was sent under the new key")
	}
	sameJSON(t, "mixed", got["mixed"], `{"deep":{"n":2},"flag":true,"note":"1.0"}`)
	sameJSON(t, "plainVersion", got["plainVersion"], `"1.0"`)
	sameJSON(t, "year", got["year"], `"1.2024"`)
}

func TestService_KeyChangeRefusesUnprovenEncStrings(t *testing.T) {
	other, _ := crypto.GenerateSymmetricKey()
	foreign, _ := crypto.EncryptString("x", other)
	for name, value := range map[string]string{
		"RSA-shaped 3.2024":          "3.2024",
		"type 0":                     "0." + b64(16) + "|" + b64(32),
		"type 1":                     "1." + b64(16) + "|" + b64(32) + "|" + b64(32),
		"type 2 under another key":   foreign,
		"unknown type":               "7." + b64(48),
		"nested type 2, another key": "",
	} {
		t.Run(name, func(t *testing.T) {
			env := newVaultTestEnv(t)
			raw := json.RawMessage(fmt.Sprintf("%q", value))
			if value == "" {
				raw = json.RawMessage(fmt.Sprintf(`{"a":{"b":%q},"plain":true}`, foreign))
			}
			seedLoginExtra(t, env, map[string]json.RawMessage{"future": raw})
			svc := loggedInTestService(t, env)
			if err := copyUnderNewKey(t, svc); !errors.Is(err, ErrSealedField) {
				t.Fatalf("copy = %v, want ErrSealedField", err)
			}
			env.mu.Lock()
			sent := env.lastBody
			env.mu.Unlock()
			if sent != nil {
				t.Fatal("a refused save reached the server")
			}
			cur, _ := svc.GetCipher("c-1")
			if _, err := svc.SaveCipher(context.Background(), cur); err != nil {
				t.Fatalf("same-key save: %v", err)
			}
			sameJSON(t, "same-key save", obj(t, env.body(t)["login"])["future"], string(raw))
		})
	}
}

func TestService_KeyChangeRefusesUnknownEncStringTypes(t *testing.T) {
	env := newVaultTestEnv(t)
	seedSealedLogin(t, env)
	env.mu.Lock()
	c := env.ciphers["c-1"]
	login := *c.Login
	login.Extra = map[string]json.RawMessage{"future": json.RawMessage(fmt.Sprintf(`{"v":%q,"plain":true}`, "7."+b64(48)))}
	c.Login = &login
	env.ciphers["c-1"] = c
	env.mu.Unlock()
	svc := loggedInTestService(t, env)

	cp, _ := svc.GetCipher("c-1")
	cp.ID, cp.Key = "", nil
	if _, err := svc.SaveCipher(context.Background(), cp); !errors.Is(err, ErrSealedField) {
		t.Fatalf("SaveCipher = %v, want ErrSealedField", err)
	}
	env.mu.Lock()
	defer env.mu.Unlock()
	if env.lastBody != nil {
		t.Fatal("a refused save still reached the server")
	}
}

func TestService_KeyChangeRefusesEncStringsInArrays(t *testing.T) {
	env := newVaultTestEnv(t)
	seedSealedLogin(t, env)
	env.mu.Lock()
	c := env.ciphers["c-1"]
	login := *c.Login
	login.Extra = map[string]json.RawMessage{"list": json.RawMessage(fmt.Sprintf(`["plain",%q]`, mustEncString(t, "x", env.cipherKey)))}
	c.Login = &login
	env.ciphers["c-1"] = c
	env.mu.Unlock()
	svc := loggedInTestService(t, env)

	cp, _ := svc.GetCipher("c-1")
	cp.ID, cp.Key = "", nil
	if _, err := svc.SaveCipher(context.Background(), cp); !errors.Is(err, ErrSealedField) {
		t.Fatalf("SaveCipher = %v, want ErrSealedField", err)
	}
	env.mu.Lock()
	sent := env.lastBody
	env.mu.Unlock()
	if sent != nil {
		t.Fatalf("a refused save still reached the server: %s", sent)
	}

	// Under the same key the array is sent back unchanged.
	cur, _ := svc.GetCipher("c-1")
	if _, err := svc.SaveCipher(context.Background(), cur); err != nil {
		t.Fatal(err)
	}
}

func TestClassifyEncString(t *testing.T) {
	key, _ := crypto.GenerateSymmetricKey()
	real, _ := crypto.EncryptString("secret", key)
	env := func(typ crypto.EncType, iv, ct, mac []byte) string {
		return (&crypto.EncString{Type: typ, IV: iv, CT: ct, MAC: mac}).String()
	}
	iv, ct, mac, rsa := bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 256)
	for s, want := range map[string]crypto.EncStringKind{
		real:                                     crypto.IsEncString,
		env(crypto.EncAesCbc256B64, iv, ct, nil): crypto.IsEncString,
		env(crypto.EncAesCbc256HmacSha256B64, iv, ct, mac):           crypto.IsEncString,
		env(crypto.EncRsa2048OaepSha256B64, nil, rsa, nil):           crypto.IsEncString,
		env(crypto.EncRsa2048OaepSha1B64, nil, rsa, nil):             crypto.IsEncString,
		env(crypto.EncRsa2048OaepSha256HmacSha256B64, nil, rsa, mac): crypto.IsEncString,
		env(crypto.EncRsa2048OaepSha1HmacSha256B64, nil, rsa, nil):   crypto.IsEncString,
		"5." + b64(256) + "|":                          crypto.IsEncString,
		"1." + b64(16) + "|" + b64(32) + "|" + b64(32): crypto.IsEncString,
		"1.2024":                       crypto.NotEncString,
		"1.0":                          crypto.NotEncString,
		"2." + b64(16) + "|" + b64(32): crypto.NotEncString,
		"2.2024":                       crypto.NotEncString,
		"v2.abc":                       crypto.NotEncString,
		"2.":                           crypto.NotEncString,
		"https://example.com":          crypto.NotEncString,
		"7." + b64(48):                 crypto.MaybeEncString,
		"9.2024":                       crypto.MaybeEncString,
		"9.5":                          crypto.NotEncString,
	} {
		if got := crypto.ClassifyEncString(s); got != want {
			t.Errorf("ClassifyEncString(%q) = %v, want %v", s, got, want)
		}
		_, perr := crypto.ParseEncString(s)
		if typ := s[:2]; typ != "1." && typ != "7." && typ != "9." && (perr == nil) != (want == crypto.IsEncString) {
			t.Errorf("ClassifyEncString(%q) = %v disagrees with ParseEncString (%v)", s, want, perr)
		}
	}
}

func TestService_KeepsWirePresenceOfKnownFields(t *testing.T) {
	env := newVaultTestEnv(t)
	k := env.cipherKey
	env.mu.Lock()
	c := env.ciphers["c-1"]
	var login api.EncryptedLogin
	raw := fmt.Sprintf(`{"password":%q,"totp":null,"uris":[{"uri":%q}],"fido2Credentials":[]}`, mustEncString(t, "pw", k), mustEncString(t, "https://github.com", k))
	if err := json.Unmarshal([]byte(raw), &login); err != nil {
		t.Fatal(err)
	}
	c.Login = &login
	env.ciphers["c-1"] = c
	env.mu.Unlock()
	svc := loggedInTestService(t, env)

	check := func(step string, l jsonObj) {
		t.Helper()
		if _, ok := l["username"]; ok {
			t.Fatalf("%s: absent username was sent as %s", step, l["username"])
		}
		sameJSON(t, step+": totp", l["totp"], `null`)
		sameJSON(t, step+": fido2Credentials", l["fido2Credentials"], `[]`)
		if _, ok := obj(t, arr(t, l["uris"])[0])["match"]; ok {
			t.Fatalf("%s: absent uri match was sent", step)
		}
	}
	cur, _ := svc.GetCipher("c-1")
	cur.Name = "Renamed"
	if _, err := svc.SaveCipher(context.Background(), cur); err != nil {
		t.Fatal(err)
	}
	check("save", obj(t, env.body(t)["login"]))

	snap, err := svc.cfg.Store.LoadSnapshot(svc.accountID)
	if err != nil {
		t.Fatal(err)
	}
	var resp struct {
		Ciphers []jsonObj `json:"ciphers"`
	}
	if err := json.Unmarshal(snap.RawSyncJSON, &resp); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, sc := range resp.Ciphers {
		if string(sc["id"]) == `"c-1"` {
			check("snapshot", obj(t, sc["login"]))
			found = true
		}
	}
	if !found {
		t.Fatal("c-1 missing from snapshot")
	}

	cur, _ = svc.GetCipher("c-1")
	zero := 0
	cur.Login.URIs[0].Match = &zero
	if _, err := svc.SaveCipher(context.Background(), cur); err != nil {
		t.Fatal(err)
	}
	sameJSON(t, "explicit match 0", obj(t, arr(t, obj(t, env.body(t)["login"])["uris"])[0])["match"], `0`)
}

func TestService_UnreadablePasskeyFieldIsReported(t *testing.T) {
	env := newVaultTestEnv(t)
	seedSealedLogin(t, env)
	other, _ := crypto.GenerateSymmetricKey()
	env.mu.Lock()
	c := env.ciphers["c-1"]
	login := *c.Login
	login.Fido2Credentials = []api.EncryptedFido2Credential{{
		RpID: ptr(mustEncString(t, "github.com", env.cipherKey)), KeyValue: ptr(mustEncString(t, "k", other)), CreationDate: "2026-03-14T10:22:00Z",
	}}
	c.Login = &login
	env.ciphers["c-1"] = c
	env.mu.Unlock()
	svc := loggedInTestService(t, env)
	got, _ := svc.GetCipher("c-1")
	if f := got.Login.Fido2Credentials[0]; f.RpID != "github.com" || len(f.Unreadable) != 1 || f.Unreadable[0] != "keyValue" {
		t.Fatalf("passkey = %+v, want keyValue reported unreadable", f)
	}
}

func ptr(s string) *string { return &s }
