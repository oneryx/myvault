package export

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/crypto"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

func login(id, name, user, pw string) *state.Cipher {
	return &state.Cipher{ID: id, Type: api.CipherTypeLogin, Name: name, Login: &state.Login{Username: user, Password: pw, URIs: []state.LoginURI{{URI: "https://" + strings.ToLower(name) + ".com"}}}}
}

func TestEncryptedExportRoundTrip(t *testing.T) {
	work := "f-work"
	org := "org-1"
	trashed := login("c-old", "Old", "o", "x")
	now := time.Now()
	trashed.DeletedDate = &now
	shared := login("c-org", "Shared", "s", "y")
	shared.OrganizationID = &org
	gh := login("c-gh", "GitHub", "alice", "gh-secret")
	gh.FolderID = &work
	gh.Fields = []state.CustomField{{Name: "PIN", Value: "1234", Type: 1}}
	note := &state.Cipher{ID: "c-note", Type: api.CipherTypeSecureNote, Name: "Note", Notes: "body", SecureNote: &state.SecureNote{}}
	v, _ := Build([]*state.Cipher{gh, note, shared, trashed}, []state.Folder{{ID: work, Name: "Work"}})
	if len(v.Items) != 2 {
		t.Fatalf("Build kept %d items, want personal active only", len(v.Items))
	}

	for _, cfg := range []crypto.KDFConfig{
		{Type: crypto.KDFPBKDF2, Iterations: 5000},
		{Type: crypto.KDFArgon2id, Iterations: 2, MemoryMB: 16, Parallelism: 1},
	} {
		data, err := EncryptWithPassword(v, []byte("backup pass"), cfg)
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]any
		_ = json.Unmarshal(data, &raw)
		for _, k := range []string{"encrypted", "passwordProtected", "salt", "kdfType", "kdfIterations", "kdfMemory", "kdfParallelism", "encKeyValidation_DO_NOT_EDIT", "data"} {
			if _, ok := raw[k]; !ok {
				t.Fatalf("export lacks %q", k)
			}
		}
		if strings.Contains(string(data), "gh-secret") {
			t.Fatal("export contains plaintext")
		}
		if need, err := NeedsPassword(data); !need || err != nil {
			t.Fatalf("NeedsPassword = (%v, %v)", need, err)
		}
		if _, err := Read(data, []byte("wrong")); !errors.Is(err, ErrWrongPassword) {
			t.Fatalf("wrong password = %v", err)
		}
		got, err := Read(data, []byte("backup pass"))
		if err != nil || len(got.Items) != 2 || got.Encrypted {
			t.Fatalf("Read = (%+v, %v)", got, err)
		}
		it := got.Items[0]
		if it.Name != "GitHub" || val(it.Login.Password) != "gh-secret" || val(it.FolderID) != work || val(it.Fields[0].Value) != "1234" {
			t.Fatalf("round-trip item = %+v", it)
		}
	}

	plain, _ := json.Marshal(v)
	if got, err := Read(plain, nil); err != nil || len(got.Items) != 2 {
		t.Fatalf("plain export = (%v, %v)", got, err)
	}
	if _, err := Read([]byte(`{"encrypted":true,"encKeyValidation_DO_NOT_EDIT":"x","data":"y"}`), nil); !errors.Is(err, ErrAccountRestricted) {
		t.Fatalf("account-restricted export = %v", err)
	}
}

type fakeWriter struct {
	ciphers map[string]*state.Cipher
	folders []state.Folder
	saves   []string
	next    int
}

func (f *fakeWriter) GetCipher(id string) (*state.Cipher, error) {
	c, ok := f.ciphers[id]
	if !ok {
		return nil, state.ErrCipherNotFound
	}
	cp := *c
	return &cp, nil
}

func (f *fakeWriter) SaveCipher(_ context.Context, c *state.Cipher) (*state.Cipher, error) {
	if c.ID == "" {
		f.next++
		c.ID = fmt.Sprintf("new-%d", f.next)
	}
	f.saves = append(f.saves, c.ID)
	f.ciphers[c.ID] = c
	return c, nil
}

func (f *fakeWriter) Folders() []state.Folder { return f.folders }

func (f *fakeWriter) SaveFolder(_ context.Context, fo *state.Folder) (*state.Folder, error) {
	fo.ID = "f-" + strings.ToLower(fo.Name)
	f.folders = append(f.folders, *fo)
	return fo, nil
}

func TestPlanClassifiesAndAppliesOnlyApproved(t *testing.T) {
	same := login("c-same", "Same", "u", "pw")
	changed := login("c-changed", "Changed", "u", "old")
	readOnly := login("c-ro", "Locked", "u", "old")
	readOnly.ReadOnly = true
	current := []*state.Cipher{same, changed, readOnly}

	backupChanged := FromCipher(login("other-id", "Changed", "u", "new"))
	backupChanged.Notes = opt("added")
	backupRO := FromCipher(login("c-ro", "Locked", "u", "new"))
	backup := &Vault{
		Folders: []Folder{{ID: "bf-1", Name: "Imported"}},
		Items: []Item{
			FromCipher(same),
			backupChanged,
			backupRO,
			FromCipher(login("c-brand-new", "Brand New", "n", "pw")),
		},
	}
	backup.Items[3].FolderID = opt("bf-1")

	p := BuildPlan(backup, current, nil)
	classes := []Class{ClassIdentical, ClassConflict, ClassConflict, ClassNew}
	for i, e := range p.Entries {
		if e.Class != classes[i] {
			t.Fatalf("entry %d (%s) class = %v, want %v", i, e.Item.Name, e.Class, classes[i])
		}
	}
	if d := strings.Join(p.Entries[1].Diff, ","); d != "Notes,Password" {
		t.Fatalf("conflict diff = %q", d)
	}
	if c := p.Counts(); c.Create != 1 || c.Update != 0 || c.Skip != 3 {
		t.Fatalf("default counts = %+v; conflicts must default to skip", c)
	}
	if p.Entries[2].CanUpdate || p.Entries[2].SetAction(ActionUpdate) {
		t.Fatal("read-only conflict accepted Update")
	}

	w := &fakeWriter{ciphers: map[string]*state.Cipher{}}
	for _, c := range current {
		cp := *c
		w.ciphers[c.ID] = &cp
	}
	res := Apply(context.Background(), w, p)
	if res.Created != 1 || res.Updated != 0 || res.Skipped != 3 || res.Err != nil {
		t.Fatalf("default apply = %+v", res)
	}
	if w.ciphers["c-changed"].Login.Password != "old" || w.ciphers["c-ro"].Login.Password != "old" {
		t.Fatal("a conflict was overwritten without approval")
	}
	created := w.ciphers["new-1"]
	if created == nil || created.Name != "Brand New" || created.FolderID == nil || *created.FolderID != "f-imported" {
		t.Fatalf("created = %+v", created)
	}

	p = BuildPlan(backup, current, nil)
	p.Entries[3].SetAction(ActionSkip)
	if !p.Entries[1].SetAction(ActionUpdate) {
		t.Fatal("editable conflict rejected Update")
	}
	p.Entries[2].SetAction(ActionCreate)
	res = Apply(context.Background(), w, p)
	if res.Created != 1 || res.Updated != 1 || res.Err != nil {
		t.Fatalf("approved apply = %+v", res)
	}
	if got := w.ciphers["c-changed"]; got.Login.Password != "new" || got.Notes != "added" || got.ID != "c-changed" {
		t.Fatalf("updated = %+v", got)
	}
	if w.ciphers["c-ro"].Login.Password != "old" || w.ciphers["new-2"].Login.Password != "new" {
		t.Fatal("read-only conflict was changed instead of copied")
	}
}

func sealedLogin(id string) *state.Cipher {
	c := login(id, "GitHub", "alice", "old")
	cs := "2.checksum|of|uri"
	c.SealedKeyID = "key-1"
	c.Extra = map[string]json.RawMessage{"futureCipherField": json.RawMessage(`"plain"`)}
	c.Login.Extra = map[string]json.RawMessage{"autofillOnPageLoad": json.RawMessage(`true`)}
	c.Login.URIs[0].Checksum, c.Login.URIs[0].ChecksumOf = &cs, c.Login.URIs[0].URI
	c.Login.URIs[0].Extra = map[string]json.RawMessage{"futureUriField": json.RawMessage(`7`)}
	c.Login.Fido2Credentials = []state.Fido2Credential{{CredentialID: "cred-1", RpID: "github.com", CreationDate: "2026-03-14T10:22:00Z", Sealed: json.RawMessage(`{"credentialId":"2.sealed"}`)}}
	c.Fields = []state.CustomField{{Name: "PIN", Value: "1", Type: 1, Extra: map[string]json.RawMessage{"futureFieldField": json.RawMessage(`"keep"`)}}}
	return c
}

func TestImportUpdateKeepsPasskeyAndUnknownFields(t *testing.T) {
	cur := sealedLogin("c-gh")
	w := &fakeWriter{ciphers: map[string]*state.Cipher{"c-gh": cur}}

	backup := FromCipher(login("c-gh", "GitHub", "alice", "new"))
	backup.Fields = []Field{{Name: opt("PIN"), Value: opt("2"), Type: 1}}
	p := BuildPlan(&Vault{Items: []Item{backup}}, []*state.Cipher{cur}, nil)
	if !p.Entries[0].SetAction(ActionUpdate) {
		t.Fatal("update not allowed")
	}
	if res := Apply(context.Background(), w, p); res.Updated != 1 || res.Err != nil {
		t.Fatalf("apply = %+v", res)
	}
	got := w.ciphers["c-gh"]
	if got.Login.Password != "new" || got.Fields[0].Value != "2" {
		t.Fatalf("update not applied: %+v", got.Login)
	}
	if got.SealedKeyID != "key-1" || string(got.Extra["futureCipherField"]) != `"plain"` ||
		string(got.Login.Extra["autofillOnPageLoad"]) != `true` ||
		got.Login.URIs[0].Checksum == nil || *got.Login.URIs[0].Checksum != "2.checksum|of|uri" || got.Login.URIs[0].ChecksumOf != got.Login.URIs[0].URI ||
		string(got.Login.URIs[0].Extra["futureUriField"]) != `7` ||
		string(got.Fields[0].Extra["futureFieldField"]) != `"keep"` {
		t.Fatalf("update lost unknown fields or checksums: %+v", got)
	}
	if len(got.Login.Fido2Credentials) != 1 || string(got.Login.Fido2Credentials[0].Sealed) != `{"credentialId":"2.sealed"}` {
		t.Fatalf("update removed the passkey: %+v", got.Login.Fido2Credentials)
	}

	other := FromCipher(login("c-gh", "GitHub", "alice", "new"))
	other.Login.Fido2Credentials = []Fido2{{CredentialID: "cred-other", RpID: "github.com", KeyValue: "k"}}
	e := BuildPlan(&Vault{Items: []Item{other}}, []*state.Cipher{sealedLogin("c-gh")}, nil).Entries[0]
	if !strings.Contains(strings.Join(e.Diff, ","), "Passkey") {
		t.Fatalf("diff = %v, want Passkey", e.Diff)
	}
	w = &fakeWriter{ciphers: map[string]*state.Cipher{"c-gh": sealedLogin("c-gh")}}
	e.SetAction(ActionUpdate)
	Apply(context.Background(), w, &Plan{Entries: []Entry{e}})
	if f := w.ciphers["c-gh"].Login.Fido2Credentials; len(f) != 1 || f[0].CredentialID != "cred-1" {
		t.Fatalf("an existing passkey was replaced: %+v", f)
	}
}

func TestImportCopyNeverCopiesPasskeyAndExportIncludesIt(t *testing.T) {
	src := sealedLogin("c-gh")
	src.Login.Fido2Credentials[0].KeyValue = "private-key"
	v, _ := Build([]*state.Cipher{src}, nil)
	f := v.Items[0].Login.Fido2Credentials
	if len(f) != 1 || f[0].RpID != "github.com" || f[0].KeyValue != "private-key" || f[0].CreationDate != "2026-03-14T10:22:00Z" {
		t.Fatalf("export passkey = %+v", f)
	}
	data, _ := json.Marshal(v)
	if !strings.Contains(string(data), `"fido2Credentials":[{"credentialId":"cred-1"`) {
		t.Fatalf("export JSON lacks fido2Credentials: %s", data)
	}

	cur := login("c-gh", "GitHub", "alice", "different")
	p := BuildPlan(v, []*state.Cipher{cur}, nil)
	p.Entries[0].SetAction(ActionCreate)
	w := &fakeWriter{ciphers: map[string]*state.Cipher{"c-gh": cur}}
	Apply(context.Background(), w, p)
	if c := w.ciphers["new-1"]; c == nil || len(c.Login.Fido2Credentials) != 0 {
		t.Fatalf("Create Copy copied the passkey: %+v", c)
	}

	p = BuildPlan(v, nil, nil)
	w = &fakeWriter{ciphers: map[string]*state.Cipher{}}
	Apply(context.Background(), w, p)
	c := w.ciphers["new-1"]
	if c == nil || len(c.Login.Fido2Credentials) != 1 || c.Login.Fido2Credentials[0].Sealed != nil || c.SealedKeyID != "" {
		t.Fatalf("a new item from a backup should import its passkey in plaintext to be sealed on save: %+v", c)
	}
}

func TestImportUpdateNeverErasesANestedObject(t *testing.T) {
	cur := sealedLogin("c-gh")
	for _, raw := range []string{
		`{"id":"c-gh","type":1,"name":"GitHub"}`,
		`{"id":"c-gh","type":1,"name":"GitHub","login":null}`,
	} {
		var it Item
		if err := json.Unmarshal([]byte(raw), &it); err != nil {
			t.Fatal(err)
		}
		p := BuildPlan(&Vault{Items: []Item{it}}, []*state.Cipher{cur}, nil)
		e := &p.Entries[0]
		if e.CanUpdate || e.SetAction(ActionUpdate) || slices.Contains(e.Allowed(), ActionUpdate) {
			t.Fatalf("%s: a login item without a login may update the vault item", raw)
		}
		e.CanUpdate, e.Action = true, ActionUpdate
		w := &fakeWriter{ciphers: map[string]*state.Cipher{"c-gh": sealedLogin("c-gh")}}
		res := Apply(context.Background(), w, p)
		if len(w.saves) != 0 || res.Failed != 1 {
			t.Fatalf("%s: forced update saved %v (result %+v)", raw, w.saves, res)
		}
	}

	c := sealedLogin("c-gh")
	mergeContent(c, Item{Type: api.CipherTypeLogin, Name: "GitHub"})
	if c.Login == nil || c.Login.Password != "old" || len(c.Login.Fido2Credentials) != 1 {
		t.Fatalf("mergeContent cleared the login: %+v", c.Login)
	}
}

func TestImportUpdateMatchesDuplicatesExactly(t *testing.T) {
	extra := func(v string) map[string]json.RawMessage { return map[string]json.RawMessage{"x": json.RawMessage(v)} }
	xs := func(fields []state.CustomField) (out []string) {
		for _, f := range fields {
			out = append(out, string(f.Extra["x"]))
		}
		return out
	}
	one, two, three := 1, 2, 3

	c := login("c-gh", "GitHub", "alice", "pw")
	u := c.Login.URIs[0].URI
	c.Login.URIs = []state.LoginURI{{URI: u, Extra: extra(`"nil-match"`)}, {URI: u, Match: &three, Extra: extra(`"match-3"`)}}
	it := FromCipher(login("c-gh", "GitHub", "alice", "pw"))
	it.Login.URIs = []URI{{URI: opt(u), Match: &three}, {URI: opt(u)}}
	if err := mergeContent(c, it); err != nil {
		t.Fatal(err)
	}
	if got := c.Login.URIs; string(got[0].Extra["x"]) != `"match-3"` || string(got[1].Extra["x"]) != `"nil-match"` {
		t.Fatalf("URI extras followed position, not match setting: %s, %s", got[0].Extra["x"], got[1].Extra["x"])
	}

	for _, tc := range []struct {
		name   string
		old    []state.CustomField
		backup []Field
		want   []string
	}{
		{"reordered by value",
			[]state.CustomField{{Name: "PIN", Value: "1", Type: 1, Extra: extra(`"a"`)}, {Name: "PIN", Value: "2", Type: 1, Extra: extra(`"b"`)}},
			[]Field{{Name: opt("PIN"), Value: opt("2"), Type: 1}, {Name: opt("PIN"), Value: opt("1"), Type: 1}},
			[]string{`"b"`, `"a"`}},
		{"reordered by linked id",
			[]state.CustomField{{Name: "L", Type: 3, LinkedID: &one, Extra: extra(`"a"`)}, {Name: "L", Type: 3, LinkedID: &two, Extra: extra(`"b"`)}},
			[]Field{{Name: opt("L"), Type: 3, LinkedID: &two}, {Name: opt("L"), Type: 3, LinkedID: &one}},
			[]string{`"b"`, `"a"`}},
		{"one value changed, the other reordered",
			[]state.CustomField{{Name: "PIN", Value: "1", Type: 1, Extra: extra(`"a"`)}, {Name: "PIN", Value: "2", Type: 1, Extra: extra(`"b"`)}},
			[]Field{{Name: opt("PIN"), Value: opt("3"), Type: 1}, {Name: opt("PIN"), Value: opt("1"), Type: 1}},
			[]string{`"b"`, `"a"`}},
		{"identical duplicates by position",
			[]state.CustomField{{Name: "PIN", Type: 1, Extra: extra(`"same"`)}, {Name: "PIN", Type: 1, Extra: extra(`"same"`)}},
			[]Field{{Name: opt("PIN"), Type: 1}, {Name: opt("PIN"), Type: 1}, {Name: opt("PIN"), Type: 1}},
			[]string{`"same"`, `"same"`, ``}},
	} {
		c := login("c-gh", "GitHub", "alice", "pw")
		c.Fields = tc.old
		if err := mergeContent(c, Item{Type: api.CipherTypeLogin, Login: &Login{}, Fields: tc.backup}); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := xs(c.Fields); !slices.Equal(got, tc.want) {
			t.Fatalf("%s: extras = %v, want %v", tc.name, got, tc.want)
		}
	}

	for name, backup := range map[string][]Field{
		"same content, different hidden data": {{Name: opt("PIN"), Type: 1}, {Name: opt("PIN"), Type: 1}},
		"both values changed":                 {{Name: opt("PIN"), Value: opt("8"), Type: 1}, {Name: opt("PIN"), Value: opt("9"), Type: 1}},
	} {
		cur := login("c-gh", "GitHub", "alice", "pw")
		vals := []string{"", ""}
		if name == "both values changed" {
			vals = []string{"1", "2"}
		}
		cur.Fields = []state.CustomField{{Name: "PIN", Value: vals[0], Type: 1, Extra: extra(`"a"`)}, {Name: "PIN", Value: vals[1], Type: 1, Extra: extra(`"b"`)}}
		if err := mergeContent(cloneLogin(cur), Item{Type: api.CipherTypeLogin, Login: &Login{}, Fields: backup}); !errors.Is(err, ErrAmbiguousUpdate) {
			t.Fatalf("%s: mergeContent = %v, want ErrAmbiguousUpdate", name, err)
		}
		it := FromCipher(cur)
		it.Fields = backup
		e := BuildPlan(&Vault{Items: []Item{it}}, []*state.Cipher{cur}, nil).Entries[0]
		if e.CanUpdate || e.UpdateBlocked == "" || !slices.Equal(e.Allowed(), []Action{ActionSkip, ActionCreate}) {
			t.Fatalf("%s: entry = %+v, want Update refused with a reason", name, e)
		}
		w := &fakeWriter{ciphers: map[string]*state.Cipher{"c-gh": cur}}
		e.CanUpdate, e.Action = true, ActionUpdate
		if res := Apply(context.Background(), w, &Plan{Entries: []Entry{e}}); res.Failed != 1 || len(w.saves) != 0 {
			t.Fatalf("%s: forced update saved %v", name, w.saves)
		}
	}
}

func cloneLogin(c *state.Cipher) *state.Cipher {
	cp := *c
	return &cp
}

func TestExportRefusesUnreadablePasskey(t *testing.T) {
	c := sealedLogin("c-gh")
	c.Login.Fido2Credentials[0].Unreadable = []string{"keyValue"}
	v, err := Build([]*state.Cipher{c}, nil)
	if !errors.Is(err, ErrUnreadablePasskey) || v != nil || !strings.Contains(err.Error(), `"GitHub"`) || !strings.Contains(err.Error(), "keyValue") {
		t.Fatalf("Build = %v, %v; want ErrUnreadablePasskey naming GitHub and keyValue", v, err)
	}
}

type localCopyWriter struct{ *fakeWriter }

func (w localCopyWriter) SaveCipher(ctx context.Context, c *state.Cipher) (*state.Cipher, error) {
	saved, _ := w.fakeWriter.SaveCipher(ctx, c)
	return saved, &state.LocalCopyError{Cipher: saved, Err: errors.New("disk full")}
}

func TestApplyCountsServerAcceptedChangesAsDone(t *testing.T) {
	cur := login("c-gh", "GitHub", "alice", "old")
	backup := FromCipher(login("c-gh", "GitHub", "alice", "new"))
	fresh := FromCipher(login("", "Fresh", "bob", "pw"))
	p := BuildPlan(&Vault{Items: []Item{backup, fresh}}, []*state.Cipher{cur}, nil)
	p.Entries[0].SetAction(ActionUpdate)
	w := localCopyWriter{&fakeWriter{ciphers: map[string]*state.Cipher{"c-gh": cur}}}
	res := Apply(context.Background(), w, p)
	if res.Created != 1 || res.Updated != 1 || res.Failed != 0 || res.Err != nil {
		t.Fatalf("result = %+v, want the accepted changes counted as done", res)
	}
	if !errors.Is(res.LocalCopyErr, state.ErrSnapshotNotUpdated) || len(w.saves) != 2 {
		t.Fatalf("LocalCopyErr = %v, saves = %v", res.LocalCopyErr, w.saves)
	}
}

func TestImportExplicitZeroIsSent(t *testing.T) {
	var wire api.EncryptedSecureNote
	if err := json.Unmarshal([]byte(`{"type":null}`), &wire); err != nil {
		t.Fatal(err)
	}
	cur := &state.Cipher{ID: "c-note", Type: api.CipherTypeSecureNote, Name: "Note", SecureNote: &state.SecureNote{Shape: wire.Shape}}
	if err := mergeContent(cur, Item{Type: api.CipherTypeSecureNote, Name: "Note", SecureNote: &SecureNote{Type: 0}}); err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(api.EncryptedSecureNote{Type: cur.SecureNote.Type, Shape: cur.SecureNote.Shape})
	if string(out) != `{"type":0}` {
		t.Fatalf("imported type 0 over null sent as %s", out)
	}

	untouched, _ := json.Marshal(api.EncryptedSecureNote{Shape: wire.Shape})
	if string(untouched) != `{"type":null}` {
		t.Fatalf("untouched type sent as %s", untouched)
	}
}

func TestImportFieldMetadataNeedsAOneToOneMatch(t *testing.T) {
	extra := map[string]json.RawMessage{"x": json.RawMessage(`"meta"`)}
	for _, order := range [][]string{{"1", "2"}, {"2", "1"}} {
		c := login("c-gh", "GitHub", "alice", "pw")
		c.Fields = []state.CustomField{{Name: "PIN", Value: "0", Type: 1, Extra: extra}}
		backup := []Field{{Name: opt("PIN"), Value: opt(order[0]), Type: 1}, {Name: opt("PIN"), Value: opt(order[1]), Type: 1}}
		if err := mergeContent(c, Item{Type: api.CipherTypeLogin, Login: &Login{}, Fields: backup}); !errors.Is(err, ErrAmbiguousUpdate) {
			t.Fatalf("order %v: mergeContent = %v, want ErrAmbiguousUpdate", order, err)
		}
	}

	u := "https://github.com"
	for _, first := range []bool{true, false} {
		c := login("c-gh", "GitHub", "alice", "pw")
		c.Login.URIs = []state.LoginURI{{URI: u, Extra: extra}}
		three := 3
		uris := []URI{{URI: opt(u)}, {URI: opt(u), Match: &three}}
		if !first {
			uris[0], uris[1] = uris[1], uris[0]
		}
		// Only the URI without a match setting matches; the result is
		// the same for both orders.
		if err := mergeContent(c, Item{Type: api.CipherTypeLogin, Login: &Login{URIs: uris}}); err != nil {
			t.Fatal(err)
		}
		for _, got := range c.Login.URIs {
			if (got.Match == nil) != (len(got.Extra) > 0) {
				t.Fatalf("first=%v: extras went to %+v", first, got)
			}
		}
		c.Login.URIs = []state.LoginURI{{URI: u, Extra: extra}}
		if err := mergeContent(c, Item{Type: api.CipherTypeLogin, Login: &Login{URIs: []URI{{URI: opt(u)}, {URI: opt(u)}}}}); err != nil {
			t.Fatalf("identical backup URIs: %v", err)
		}
	}
}

func TestPlanReservesExactIDsAndRefusesAmbiguousNames(t *testing.T) {
	personal := login("c-personal", "Mail", "alice", "pw")
	org := login("c-org", "Mail", "alice", "pw")
	orgID := "org-1"
	org.OrganizationID = &orgID
	for _, current := range [][]*state.Cipher{{personal, org}, {org, personal}} {
		it := FromCipher(login("other-id", "Mail", "alice", "new"))
		e := BuildPlan(&Vault{Items: []Item{it}}, current, nil).Entries[0]
		if e.Match != nil || !e.Ambiguous || e.Action != ActionSkip || e.Class != ClassNew {
			t.Fatalf("two vault items match by name; entry = %+v", e)
		}
	}

	// The vault item one backup item names by ID is not also offered to
	// another backup item by name.
	byName := FromCipher(login("unknown", "Mail", "alice", "x"))
	byID := FromCipher(login("c-personal", "Mail", "alice", "y"))
	for _, items := range [][]Item{{byName, byID}, {byID, byName}} {
		p := BuildPlan(&Vault{Items: items}, []*state.Cipher{personal}, nil)
		for _, e := range p.Entries {
			switch e.Item.ID {
			case "c-personal":
				if e.Match == nil || e.Match.ID != "c-personal" {
					t.Fatalf("exact ID not matched: %+v", e)
				}
			default:
				if e.Match != nil {
					t.Fatalf("name match took an item reserved by ID: %+v", e.Match.ID)
				}
			}
		}
	}

	// Two backup items wanting the one vault item by name match neither.
	a, b := FromCipher(login("x1", "Mail", "alice", "1")), FromCipher(login("x2", "Mail", "alice", "2"))
	for _, e := range BuildPlan(&Vault{Items: []Item{a, b}}, []*state.Cipher{personal}, nil).Entries {
		if e.Match != nil || !e.Ambiguous {
			t.Fatalf("contested name match: %+v", e)
		}
	}
}

func TestApplyRefusesAnItemChangedAfterReview(t *testing.T) {
	rev := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	cur := login("c-gh", "GitHub", "alice", "old")
	cur.RevisionDate = &rev
	backup := FromCipher(login("c-gh", "GitHub", "alice", "new"))
	backup.FolderID = opt("f-b")
	p := BuildPlan(&Vault{Items: []Item{backup}, Folders: []Folder{{ID: "f-b", Name: "Imported"}}}, []*state.Cipher{cur}, nil)
	if !p.Entries[0].SetAction(ActionUpdate) {
		t.Fatal("update not allowed")
	}

	changed := *cur
	later := rev.Add(time.Minute)
	changed.RevisionDate = &later
	changed.Login = &state.Login{Username: "alice", Password: "changed elsewhere"}
	w := &fakeWriter{ciphers: map[string]*state.Cipher{"c-gh": &changed}}
	res := Apply(context.Background(), w, p)
	if res.Updated != 0 || res.Failed != 1 || !errors.Is(res.Err, ErrChangedSinceReview) {
		t.Fatalf("result = %+v, want ErrChangedSinceReview", res)
	}
	if len(w.saves) != 0 || len(w.folders) != 0 {
		t.Fatalf("wrote after the item changed: saves %v, folders %v", w.saves, w.folders)
	}
}

func TestUpdatingAProtectedItemNeedsApproval(t *testing.T) {
	rev := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	cur := login("c-gh", "GitHub", "alice", "old")
	cur.Reprompt, cur.RevisionDate = 1, &rev
	backup := FromCipher(login("c-gh", "GitHub", "alice", "new"))
	p := BuildPlan(&Vault{Items: []Item{backup}}, []*state.Cipher{cur}, nil)
	e := &p.Entries[0]
	if !e.NeedsReprompt() || e.SetAction(ActionUpdate) {
		t.Fatal("Update of a protected item was allowed without verification")
	}

	e.Action = ActionUpdate
	w := &fakeWriter{ciphers: map[string]*state.Cipher{"c-gh": cur}}
	if res := Apply(context.Background(), w, p); !errors.Is(res.Err, ErrRepromptRequired) || len(w.saves) != 0 {
		t.Fatalf("forced unverified update = %+v", res)
	}

	e.ApproveReprompt()
	if !e.SetAction(ActionUpdate) {
		t.Fatal("Update refused after verification")
	}
	if res := Apply(context.Background(), w, p); res.Updated != 1 || res.Err != nil {
		t.Fatalf("verified update = %+v", res)
	}
}

func TestDiffSeesMatchModeAndLinkedField(t *testing.T) {
	three, one, two := 3, 1, 2
	cur := login("c-gh", "GitHub", "alice", "pw")
	it := FromCipher(cur)
	it.Login.URIs[0].Match = &three
	if e := BuildPlan(&Vault{Items: []Item{it}}, []*state.Cipher{cur}, nil).Entries[0]; e.Class != ClassConflict || !slices.Contains(e.Diff, "Websites") {
		t.Fatalf("a changed match mode = %v %v", e.Class, e.Diff)
	}
	cur.Fields = []state.CustomField{{Name: "L", Type: 3, LinkedID: &one}}
	it = FromCipher(cur)
	it.Fields[0].LinkedID = &two
	if e := BuildPlan(&Vault{Items: []Item{it}}, []*state.Cipher{cur}, nil).Entries[0]; !slices.Contains(e.Diff, "Custom Fields") {
		t.Fatalf("a changed linked field = %v", e.Diff)
	}
}

func TestApplyStopsWhenTheSessionEnds(t *testing.T) {
	items := []Item{FromCipher(login("", "A", "a", "1")), FromCipher(login("", "B", "b", "2")), FromCipher(login("", "C", "c", "3"))}
	p := BuildPlan(&Vault{Items: items}, nil, nil)
	w := &lockingWriter{fakeWriter: &fakeWriter{ciphers: map[string]*state.Cipher{}}}
	res := Apply(context.Background(), w, p)
	if w.calls != 1 || res.Created != 0 || res.Failed != 3 {
		t.Fatalf("after the session ended: calls %d, result %+v", w.calls, res)
	}
}

type lockingWriter struct {
	*fakeWriter
	calls int
}

func (w *lockingWriter) SaveCipher(context.Context, *state.Cipher) (*state.Cipher, error) {
	w.calls++
	return nil, state.ErrLocked
}

func TestExportRefusesABackupTooLargeToImport(t *testing.T) {
	big := &state.Cipher{ID: "n", Type: api.CipherTypeSecureNote, Name: "Big", Notes: strings.Repeat("x", MaxFileSize*3/4), SecureNote: &state.SecureNote{}}
	v, err := Build([]*state.Cipher{big}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EncryptWithPassword(v, []byte("backup pass"), crypto.KDFConfig{Type: crypto.KDFPBKDF2, Iterations: 5000}); !errors.Is(err, ErrBackupTooLarge) {
		t.Fatalf("EncryptWithPassword = %v, want ErrBackupTooLarge", err)
	}
}

func TestExportKeepsArchivedDate(t *testing.T) {
	when := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	c := login("c-old", "Myspace", "alex", "pw")
	c.ArchivedDate = &when
	v, err := Build([]*state.Cipher{c}, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(v)
	if !strings.Contains(string(data), `"archivedDate":"2026-11-01T09:00:00Z"`) {
		t.Fatalf("export lacks archivedDate: %s", data)
	}
	var back Vault
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if got := back.Items[0].content().ArchivedDate; got == nil || !got.Equal(when) {
		t.Fatalf("a new item from the backup is archived at %v", got)
	}
}

func TestImportSkipsTypesMyVaultCannotSave(t *testing.T) {
	for _, typ := range []api.CipherType{api.CipherTypeBankAccount, api.CipherTypeDriversLicense, api.CipherTypePassport, 42} {
		var it Item
		raw := fmt.Sprintf(`{"id":"x-%d","type":%d,"name":"Unsupported","bankAccount":{"accountNumber":"1"}}`, typ, typ)
		if err := json.Unmarshal([]byte(raw), &it); err != nil {
			t.Fatal(err)
		}
		cur := &state.Cipher{ID: it.ID, Type: typ, Name: "Unsupported"}
		p := BuildPlan(&Vault{Items: []Item{it}}, []*state.Cipher{cur}, nil)
		e := &p.Entries[0]
		if !e.Unsupported || e.Action != ActionSkip || !slices.Equal(e.Allowed(), []Action{ActionSkip}) || e.Match != nil {
			t.Fatalf("type %d: entry %+v, allowed %v", typ, e, e.Allowed())
		}
		for _, a := range []Action{ActionCreate, ActionUpdate} {
			if e.SetAction(a) {
				t.Fatalf("type %d: %v allowed", typ, a)
			}
		}
		// Even forced, nothing is written.
		w := &fakeWriter{ciphers: map[string]*state.Cipher{}}
		e.Action = ActionCreate
		if res := Apply(context.Background(), w, p); len(w.saves) != 0 || !errors.Is(res.Err, ErrUnsupportedType) {
			t.Fatalf("type %d: forced create = %+v, saves %v", typ, res, w.saves)
		}
	}
}
