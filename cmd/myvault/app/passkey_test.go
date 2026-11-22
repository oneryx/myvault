package app

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/oneryx/myvault/cmd/myvault/core"
	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

const (
	sealedPasskeyA = `{"credentialId":"2.sealed-a","futurePasskeyField":1}`
	sealedPasskeyB = `{"credentialId":"2.sealed-b"}`
)

// passkeyLogin is c-github as a server stores it with two passkeys and the
// fields GoVault does not show.
func passkeyLogin(svc *mockVaultService) *state.Cipher {
	match := 3
	cs := "2.checksum|of|uri"
	c := svc.ciphers["c-github"]
	c.SealedKeyID = "key-1"
	c.Extra = map[string]json.RawMessage{"futureCipherField": json.RawMessage(`"plain"`)}
	c.Login.Extra = map[string]json.RawMessage{"autofillOnPageLoad": json.RawMessage(`true`)}
	c.Login.Shape = api.Shape{"totp": {Raw: json.RawMessage(`null`)}}
	c.Login.URIs[0].Match = &match
	c.Login.URIs[0].Checksum, c.Login.URIs[0].ChecksumOf = &cs, c.Login.URIs[0].URI
	c.Login.URIs[0].Extra = map[string]json.RawMessage{"futureUriField": json.RawMessage(`7`)}
	c.Login.Fido2Credentials = []state.Fido2Credential{
		{RpID: "github.com", CreationDate: "2026-03-14T10:22:00Z", Sealed: json.RawMessage(sealedPasskeyA)},
		{RpID: "gist.github.com", CreationDate: "2026-04-01T08:00:00Z", Sealed: json.RawMessage(sealedPasskeyB)},
	}
	linked := 2
	c.Fields = []state.CustomField{{Name: "PIN", Value: "1", Type: 1, LinkedID: &linked, Extra: map[string]json.RawMessage{"futureFieldField": json.RawMessage(`"keep"`)}}}
	return c
}

func TestEditorKeepsWhatItDoesNotShow(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	c := passkeyLogin(svc)
	d := draftFromCipher(c)
	d.Name, d.Password = "GitHub (work)", "changed"
	d.URIs = append(d.URIs, EditURIDraft{URI: "https://gist.github.com"})
	out := cipherFromDraft(d)

	if out.Name != "GitHub (work)" || out.Login.Password != "changed" || out.SealedKeyID != "key-1" {
		t.Fatalf("edit not applied: %+v", out)
	}
	if string(out.Extra["futureCipherField"]) != `"plain"` || string(out.Login.Extra["autofillOnPageLoad"]) != `true` || string(out.Login.Shape["totp"].Raw) != `null` {
		t.Fatal("unknown fields or wire shape lost")
	}
	if len(out.Login.Fido2Credentials) != 2 || string(out.Login.Fido2Credentials[0].Sealed) != sealedPasskeyA {
		t.Fatalf("passkeys lost: %+v", out.Login.Fido2Credentials)
	}
	u := out.Login.URIs[0]
	if u.Match == nil || *u.Match != 3 || u.Checksum == nil || u.ChecksumOf != u.URI || string(u.Extra["futureUriField"]) != `7` {
		t.Fatalf("URI lost its match, checksum or fields: %+v", u)
	}
	if added := out.Login.URIs[1]; added.URI != "https://gist.github.com" || added.Checksum != nil {
		t.Fatalf("added URI = %+v", added)
	}
	f := out.Fields[0]
	if f.LinkedID == nil || *f.LinkedID != 2 || string(f.Extra["futureFieldField"]) != `"keep"` {
		t.Fatalf("field lost its linked id or fields: %+v", f)
	}

	id := &state.Cipher{ID: "c-id", Type: api.CipherTypeIdentity, Name: "Me", Identity: &state.Identity{FirstName: "Alice", Address2: "Apt 4", Address3: "Floor 2", Extra: map[string]json.RawMessage{"x": json.RawMessage(`1`)}}}
	idd := draftFromCipher(id)
	idd.FirstName = "Alicia"
	if got := cipherFromDraft(idd).Identity; got.FirstName != "Alicia" || got.Address2 != "Apt 4" || got.Address3 != "Floor 2" || string(got.Extra["x"]) != `1` {
		t.Fatalf("identity edit lost hidden fields: %+v", got)
	}
}

func TestEditorKeepsExistingBlankRows(t *testing.T) {
	match := 5
	c := &state.Cipher{ID: "c-blank", Type: api.CipherTypeLogin, Name: "Blank rows", Login: &state.Login{
		Username: "alice",
		URIs:     []state.LoginURI{{URI: "", Match: &match, Extra: map[string]json.RawMessage{"futureUriField": json.RawMessage(`1`)}}, {URI: "https://a.example"}},
	}, Fields: []state.CustomField{{Name: "", Value: "", Type: 0, Extra: map[string]json.RawMessage{"futureFieldField": json.RawMessage(`2`)}}}}
	d := draftFromCipher(c)
	d.Name = "Renamed"
	d.URIs = append(d.URIs, EditURIDraft{URI: "  "})
	d.Fields = append(d.Fields, EditFieldDraft{})
	out := cipherFromDraft(d)
	if len(out.Login.URIs) != 2 || out.Login.URIs[0].Match == nil || *out.Login.URIs[0].Match != 5 || string(out.Login.URIs[0].Extra["futureUriField"]) != `1` {
		t.Fatalf("existing blank URI lost or new blank URI kept: %+v", out.Login.URIs)
	}
	if len(out.Fields) != 1 || string(out.Fields[0].Extra["futureFieldField"]) != `2` {
		t.Fatalf("existing blank field lost or new blank field kept: %+v", out.Fields)
	}

	d = draftFromCipher(c)
	d.URIs[1].URI = ""
	if out := cipherFromDraft(d); len(out.Login.URIs) != 1 {
		t.Fatalf("a URI the user cleared was kept: %+v", out.Login.URIs)
	}
}

func TestRemoveOnePasskeyKeepsTheOther(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	passkeyLogin(svc)
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})
	answers := []int{0, 1}
	app.OnAlert = func(core.AlertConfig) int { a := answers[0]; answers = answers[1:]; return a }

	app.Post(func() { m.SelectCipher(root, "c-github") })
	app.WaitFor("gist.github.com · Created Apr 1, 2026", 2*time.Second)
	if !app.Exists("github.com · Created Mar 14, 2026") || !app.Exists("gist.github.com · Created Apr 1, 2026") {
		t.Fatal("detail does not show both passkeys")
	}

	app.Press("Edit")
	app.WaitFor("Remove passkey", 2*time.Second)
	app.PressLast("Remove passkey")
	app.Settle()
	if len(m.EditDraft.Get().RemovedPasskeys) != 0 || !app.Exists("gist.github.com · Created Apr 1, 2026") {
		t.Fatal("cancelling the dialog removed the passkey")
	}
	app.PressLast("Remove passkey")
	app.WaitFor("Undo", 2*time.Second)
	if !app.Exists("github.com · Created Mar 14, 2026") || app.Exists("gist.github.com · Created Apr 1, 2026") {
		t.Fatal("removing the second passkey hid the first")
	}
	if c, _ := svc.GetCipher("c-github"); len(c.Login.Fido2Credentials) != 2 {
		t.Fatal("passkey removed before saving")
	}
	app.Press("Save")
	app.WaitUntil(2*time.Second, func() bool { return !m.EditMode.Get() })

	c, _ := svc.GetCipher("c-github")
	if len(c.Login.Fido2Credentials) != 1 || !bytes.Equal(c.Login.Fido2Credentials[0].Sealed, []byte(sealedPasskeyA)) {
		t.Fatalf("save kept %+v, want only the first passkey unchanged", c.Login.Fido2Credentials)
	}
	if string(c.Login.Extra["autofillOnPageLoad"]) != `true` || c.Login.URIs[0].Checksum == nil || string(c.Fields[0].Extra["futureFieldField"]) != `"keep"` || string(c.Extra["futureCipherField"]) != `"plain"` {
		t.Fatalf("removing a passkey changed other fields: %+v", c.Login)
	}
}

func TestLeavingEditorKeepsPasskey(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	passkeyLogin(svc)
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})
	app.OnAlert = func(cfg core.AlertConfig) int { return 1 }

	app.Post(func() { m.SelectCipher(root, "c-github") })
	app.WaitFor("Edit", 2*time.Second)
	app.Press("Edit")
	app.WaitFor("Remove passkey", 2*time.Second)
	app.Press("Remove passkey")
	app.WaitFor("Undo", 2*time.Second)
	app.Press("Cancel")
	app.WaitUntil(2*time.Second, func() bool { return !m.EditMode.Get() })
	if c, _ := svc.GetCipher("c-github"); len(c.Login.Fido2Credentials) != 2 {
		t.Fatal("leaving the editor without saving removed the passkey")
	}
}

func TestCloneDoesNotCopyPasskeyButKeepsExtras(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	passkeyLogin(svc)
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() { m.SelectCipher(root, "c-github") })
	app.WaitFor("Clone item", 2*time.Second)
	app.Press("Clone item")
	app.WaitUntil(2*time.Second, func() bool { return m.EditMode.Get() })
	if len(m.EditDraft.Get().DraftPasskeys()) != 0 || app.Exists("Remove passkey") {
		t.Fatal("clone editor offers the passkey")
	}
	app.Press("Save")
	app.WaitUntil(2*time.Second, func() bool { return !m.EditMode.Get() })
	cp, err := svc.GetCipher("c-new")
	if err != nil || len(cp.Login.Fido2Credentials) != 0 || !strings.HasSuffix(cp.Name, "(Copy)") {
		t.Fatalf("clone = %+v, %v", cp, err)
	}
	if string(cp.Extra["futureCipherField"]) != `"plain"` {
		t.Fatal("clone dropped top-level unknown fields; the key-change filter decides what goes")
	}
	if orig, _ := svc.GetCipher("c-github"); len(orig.Login.Fido2Credentials) != 2 {
		t.Fatal("clone changed the original passkeys")
	}
}

func TestEditorFieldTypeChangeClearsPresence(t *testing.T) {
	c := &state.Cipher{ID: "c-f", Type: api.CipherTypeSecureNote, Name: "N", SecureNote: &state.SecureNote{},
		Fields: []state.CustomField{{Name: "a", Value: "1", Type: 1, Shape: api.Shape{"type": {Raw: json.RawMessage(`null`), Zero: json.RawMessage(`0`)}, "linkedId": {Absent: true}}}}}
	d := draftFromCipher(c)
	d.Fields[0].Type = 0
	out := cipherFromDraft(d)
	if _, ok := out.Fields[0].Shape["type"]; ok {
		t.Fatal("an edited type kept its old presence, so a zero would be sent as null")
	}
	if _, ok := out.Fields[0].Shape["linkedId"]; !ok {
		t.Fatal("untouched presence was dropped")
	}
}
