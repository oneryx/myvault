package api

import (
	"bytes"
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"
)

// The nested parts of a cipher keep every field the server sends, known or
// not, in Extra, and send it back unchanged on save. A field MyVault does
// not model, such as login.autofillOnPageLoad or a field a newer server
// adds, therefore survives edits. Shape keeps how known fields without a
// value were sent, so an untouched absent, null or empty field goes back
// the same way.

// Shape records how the known fields that carried no value were sent.
type Shape map[string]Presence

// Presence is how one known field without a value was sent: absent, or as
// Raw (null, "", [] or {}). Zero is the JSON of the Go zero value for a
// field that is not a pointer, slice or map: such a field cannot tell
// "unset" from zero, so its zero counts as unchanged. A pointer field set
// to an explicit zero, such as a URI match of 0, is a change and is sent.
type Presence struct {
	Absent bool
	Raw    json.RawMessage
	Zero   json.RawMessage
}

// Without returns a copy of s without the entries for names: fields that
// were set explicitly, whose value must be sent even when it is the zero
// that stood for "unset" before.
func (s Shape) Without(names ...string) Shape {
	if len(s) == 0 {
		return nil
	}
	out := make(Shape, len(s))
	for k, v := range s {
		if !slices.Contains(names, k) {
			out[k] = v.Clone()
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (p Presence) Clone() Presence {
	return Presence{Absent: p.Absent, Raw: bytes.Clone(p.Raw), Zero: bytes.Clone(p.Zero)}
}

func unmarshalNested(data []byte, dst any, extra *map[string]json.RawMessage, shape *Shape) error {
	if err := unmarshalWithExtra(data, dst, extra); err != nil {
		return err
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}
	out := Shape{}
	t := reflect.TypeOf(dst).Elem()
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		v, ok := all[name]
		if ok && !emptyJSON(v) {
			continue
		}
		p := Presence{Absent: !ok}
		if ok {
			p.Raw = bytes.Clone(v)
		}
		switch f.Type.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Map, reflect.Interface:
		default:
			if z, err := json.Marshal(reflect.Zero(f.Type).Interface()); err == nil {
				p.Zero = z
			}
		}
		out[name] = p
	}
	if len(out) > 0 {
		*shape = out
	}
	return nil
}

func marshalNested(src any, extra map[string]json.RawMessage, shape Shape) ([]byte, error) {
	if len(shape) == 0 {
		return marshalWithExtra(src, extra)
	}
	base, err := json.Marshal(src)
	if err != nil {
		return nil, err
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(base, &merged); err != nil {
		return nil, err
	}
	if merged == nil {
		merged = map[string]json.RawMessage{}
	}
	for name, p := range shape {
		cur, ok := merged[name]
		unchanged := !ok || emptyJSON(cur) || (len(p.Zero) > 0 && bytes.Equal(bytes.TrimSpace(cur), p.Zero))
		switch {
		case !unchanged:
		case p.Absent:
			delete(merged, name)
		default:
			merged[name] = bytes.Clone(p.Raw)
		}
	}
	out := make(map[string]json.RawMessage, len(extra)+len(merged))
	maps.Copy(out, extra)
	maps.Copy(out, merged)
	return json.Marshal(out)
}

func emptyJSON(v json.RawMessage) bool {
	switch string(bytes.TrimSpace(v)) {
	case "null", `""`, "[]", "{}":
		return true
	}
	return false
}

type EncryptedLogin struct {
	Username             *string                    `json:"username"`
	Password             *string                    `json:"password"`
	TOTP                 *string                    `json:"totp"`
	URIs                 []EncryptedLoginURI        `json:"uris,omitempty"`
	PasswordRevisionDate *time.Time                 `json:"passwordRevisionDate,omitempty"`
	Fido2Credentials     []EncryptedFido2Credential `json:"fido2Credentials,omitempty"`
	Extra                map[string]json.RawMessage `json:"-"`
	Shape                Shape                      `json:"-"`
}

func (l *EncryptedLogin) UnmarshalJSON(data []byte) error {
	type alias EncryptedLogin
	var v alias
	if err := unmarshalNested(data, &v, &v.Extra, &v.Shape); err != nil {
		return err
	}
	*l = EncryptedLogin(v)
	return nil
}

func (l EncryptedLogin) MarshalJSON() ([]byte, error) {
	type alias EncryptedLogin
	return marshalNested(alias(l), l.Extra, l.Shape)
}

type EncryptedLoginURI struct {
	URI         *string                    `json:"uri"`
	Match       *int                       `json:"match"`
	URIChecksum *string                    `json:"uriChecksum,omitempty"`
	Extra       map[string]json.RawMessage `json:"-"`
	Shape       Shape                      `json:"-"`
}

func (u *EncryptedLoginURI) UnmarshalJSON(data []byte) error {
	type alias EncryptedLoginURI
	var v alias
	if err := unmarshalNested(data, &v, &v.Extra, &v.Shape); err != nil {
		return err
	}
	*u = EncryptedLoginURI(v)
	return nil
}

func (u EncryptedLoginURI) MarshalJSON() ([]byte, error) {
	type alias EncryptedLoginURI
	return marshalNested(alias(u), u.Extra, u.Shape)
}

// EncryptedFido2Credential is a passkey as the server stores it. Every
// field but creationDate is an EncString under the cipher key. Raw is the
// entry exactly as received and is what MyVault sends back, so a passkey
// it cannot create or use is never altered; the parsed fields are only read.
type EncryptedFido2Credential struct {
	Raw json.RawMessage

	CredentialID    *string
	KeyType         *string
	KeyAlgorithm    *string
	KeyCurve        *string
	KeyValue        *string
	RpID            *string
	UserHandle      *string
	UserName        *string
	Counter         *string
	RpName          *string
	UserDisplayName *string
	Discoverable    *string
	CreationDate    string
}

type fido2Fields struct {
	CredentialID    *string `json:"credentialId"`
	KeyType         *string `json:"keyType"`
	KeyAlgorithm    *string `json:"keyAlgorithm"`
	KeyCurve        *string `json:"keyCurve"`
	KeyValue        *string `json:"keyValue"`
	RpID            *string `json:"rpId"`
	UserHandle      *string `json:"userHandle"`
	UserName        *string `json:"userName"`
	Counter         *string `json:"counter"`
	RpName          *string `json:"rpName"`
	UserDisplayName *string `json:"userDisplayName"`
	Discoverable    *string `json:"discoverable"`
	CreationDate    string  `json:"creationDate"`
}

func (f *EncryptedFido2Credential) UnmarshalJSON(data []byte) error {
	var v fido2Fields
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*f = EncryptedFido2Credential{
		Raw:          bytes.Clone(data),
		CredentialID: v.CredentialID, KeyType: v.KeyType, KeyAlgorithm: v.KeyAlgorithm,
		KeyCurve: v.KeyCurve, KeyValue: v.KeyValue, RpID: v.RpID, UserHandle: v.UserHandle,
		UserName: v.UserName, Counter: v.Counter, RpName: v.RpName,
		UserDisplayName: v.UserDisplayName, Discoverable: v.Discoverable, CreationDate: v.CreationDate,
	}
	return nil
}

// MarshalJSON sends Raw when the credential came from the server, and the
// fields otherwise (a passkey MyVault encrypted itself, such as one imported
// from a backup).
func (f EncryptedFido2Credential) MarshalJSON() ([]byte, error) {
	if len(f.Raw) > 0 {
		return f.Raw, nil
	}
	return json.Marshal(fido2Fields{
		CredentialID: f.CredentialID, KeyType: f.KeyType, KeyAlgorithm: f.KeyAlgorithm,
		KeyCurve: f.KeyCurve, KeyValue: f.KeyValue, RpID: f.RpID, UserHandle: f.UserHandle,
		UserName: f.UserName, Counter: f.Counter, RpName: f.RpName,
		UserDisplayName: f.UserDisplayName, Discoverable: f.Discoverable, CreationDate: f.CreationDate,
	})
}

type EncryptedSecureNote struct {
	Type  int                        `json:"type"`
	Extra map[string]json.RawMessage `json:"-"`
	Shape Shape                      `json:"-"`
}

func (n *EncryptedSecureNote) UnmarshalJSON(data []byte) error {
	type alias EncryptedSecureNote
	var v alias
	if err := unmarshalNested(data, &v, &v.Extra, &v.Shape); err != nil {
		return err
	}
	*n = EncryptedSecureNote(v)
	return nil
}

func (n EncryptedSecureNote) MarshalJSON() ([]byte, error) {
	type alias EncryptedSecureNote
	return marshalNested(alias(n), n.Extra, n.Shape)
}

type EncryptedCard struct {
	CardholderName *string                    `json:"cardholderName"`
	Brand          *string                    `json:"brand"`
	Number         *string                    `json:"number"`
	ExpMonth       *string                    `json:"expMonth"`
	ExpYear        *string                    `json:"expYear"`
	Code           *string                    `json:"code"`
	Extra          map[string]json.RawMessage `json:"-"`
	Shape          Shape                      `json:"-"`
}

func (c *EncryptedCard) UnmarshalJSON(data []byte) error {
	type alias EncryptedCard
	var v alias
	if err := unmarshalNested(data, &v, &v.Extra, &v.Shape); err != nil {
		return err
	}
	*c = EncryptedCard(v)
	return nil
}

func (c EncryptedCard) MarshalJSON() ([]byte, error) {
	type alias EncryptedCard
	return marshalNested(alias(c), c.Extra, c.Shape)
}

type EncryptedIdentity struct {
	Title          *string                    `json:"title"`
	FirstName      *string                    `json:"firstName"`
	MiddleName     *string                    `json:"middleName"`
	LastName       *string                    `json:"lastName"`
	Address1       *string                    `json:"address1"`
	Address2       *string                    `json:"address2"`
	Address3       *string                    `json:"address3"`
	City           *string                    `json:"city"`
	State          *string                    `json:"state"`
	PostalCode     *string                    `json:"postalCode"`
	Country        *string                    `json:"country"`
	Company        *string                    `json:"company"`
	Email          *string                    `json:"email"`
	Phone          *string                    `json:"phone"`
	SSN            *string                    `json:"ssn"`
	Username       *string                    `json:"username"`
	PassportNumber *string                    `json:"passportNumber"`
	LicenseNumber  *string                    `json:"licenseNumber"`
	Extra          map[string]json.RawMessage `json:"-"`
	Shape          Shape                      `json:"-"`
}

func (i *EncryptedIdentity) UnmarshalJSON(data []byte) error {
	type alias EncryptedIdentity
	var v alias
	if err := unmarshalNested(data, &v, &v.Extra, &v.Shape); err != nil {
		return err
	}
	*i = EncryptedIdentity(v)
	return nil
}

func (i EncryptedIdentity) MarshalJSON() ([]byte, error) {
	type alias EncryptedIdentity
	return marshalNested(alias(i), i.Extra, i.Shape)
}

type EncryptedSSHKey struct {
	PrivateKey     *string                    `json:"privateKey"`
	PublicKey      *string                    `json:"publicKey"`
	KeyFingerprint *string                    `json:"keyFingerprint"`
	Extra          map[string]json.RawMessage `json:"-"`
	Shape          Shape                      `json:"-"`
}

func (k *EncryptedSSHKey) UnmarshalJSON(data []byte) error {
	type alias EncryptedSSHKey
	var v alias
	if err := unmarshalNested(data, &v, &v.Extra, &v.Shape); err != nil {
		return err
	}
	*k = EncryptedSSHKey(v)
	return nil
}

func (k EncryptedSSHKey) MarshalJSON() ([]byte, error) {
	type alias EncryptedSSHKey
	return marshalNested(alias(k), k.Extra, k.Shape)
}

type EncryptedField struct {
	Name     *string                    `json:"name"`
	Value    *string                    `json:"value"`
	Type     int                        `json:"type"`
	LinkedID *int                       `json:"linkedId,omitempty"`
	Extra    map[string]json.RawMessage `json:"-"`
	Shape    Shape                      `json:"-"`
}

func (f *EncryptedField) UnmarshalJSON(data []byte) error {
	type alias EncryptedField
	var v alias
	if err := unmarshalNested(data, &v, &v.Extra, &v.Shape); err != nil {
		return err
	}
	*f = EncryptedField(v)
	return nil
}

func (f EncryptedField) MarshalJSON() ([]byte, error) {
	type alias EncryptedField
	return marshalNested(alias(f), f.Extra, f.Shape)
}

type EncryptedPasswordHistory struct {
	Password     string                     `json:"password"`
	LastUsedDate time.Time                  `json:"lastUsedDate"`
	Extra        map[string]json.RawMessage `json:"-"`
	Shape        Shape                      `json:"-"`
}

func (h *EncryptedPasswordHistory) UnmarshalJSON(data []byte) error {
	type alias EncryptedPasswordHistory
	var v alias
	if err := unmarshalNested(data, &v, &v.Extra, &v.Shape); err != nil {
		return err
	}
	*h = EncryptedPasswordHistory(v)
	return nil
}

func (h EncryptedPasswordHistory) MarshalJSON() ([]byte, error) {
	type alias EncryptedPasswordHistory
	return marshalNested(alias(h), h.Extra, h.Shape)
}
