package api

import (
	"encoding/json"
	"testing"
)

func roundTrip[T any](t *testing.T, in string, edit func(*T)) map[string]json.RawMessage {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(in), &v); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(&v)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestShapeKeepsUntouchedPresence(t *testing.T) {
	uri := roundTrip[EncryptedLoginURI](t, `{"uri":"2.x"}`, nil)
	if _, ok := uri["match"]; ok {
		t.Fatalf("absent match sent: %s", uri["match"])
	}
	note := roundTrip[EncryptedSecureNote](t, `{"type":null}`, nil)
	if string(note["type"]) != "null" {
		t.Fatalf("type null sent as %s", note["type"])
	}
	note = roundTrip[EncryptedSecureNote](t, `{}`, nil)
	if _, ok := note["type"]; ok {
		t.Fatal("absent type sent")
	}
	att := roundTrip[EncryptedAttachment](t, `{"id":"a","fileName":"2.x","key":null,"size":"3"}`, nil)
	if string(att["key"]) != "null" {
		t.Fatalf("attachment key null sent as %s", att["key"])
	}
	login := roundTrip[EncryptedLogin](t, `{"username":"","fido2Credentials":[]}`, nil)
	if string(login["username"]) != `""` || string(login["fido2Credentials"]) != "[]" {
		t.Fatalf("login = %s / %s", login["username"], login["fido2Credentials"])
	}
}

func TestShapeSendsExplicitEdits(t *testing.T) {
	zero, one := 0, 1
	uri := roundTrip(t, `{"uri":"2.x"}`, func(u *EncryptedLoginURI) { u.Match = &zero })
	if string(uri["match"]) != "0" {
		t.Fatalf("explicit match 0 sent as %q", uri["match"])
	}
	note := roundTrip(t, `{"type":null}`, func(n *EncryptedSecureNote) { n.Type = one })
	if string(note["type"]) != "1" {
		t.Fatalf("edited type sent as %s", note["type"])
	}
	s := "2.y"
	login := roundTrip(t, `{"totp":null}`, func(l *EncryptedLogin) { l.TOTP = &s })
	if string(login["totp"]) != `"2.y"` {
		t.Fatalf("edited totp sent as %s", login["totp"])
	}
}
