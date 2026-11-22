package state

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/crypto"
)

func decryptCipher(enc *api.EncryptedCipher, userKey *crypto.SymmetricKey) (*Cipher, error) {
	if len(enc.Data) > 0 && enc.Name == "" {
		return nil, ErrUnsupportedCipherFormat
	}

	activeKey := userKey
	if enc.Key != nil && *enc.Key != "" {
		rawKey, err := decryptBytesFromString(*enc.Key, userKey)
		if err != nil {
			return nil, err
		}
		cipherKey, err := crypto.SymmetricKeyFromBytes(rawKey)
		crypto.ZeroBytes(rawKey)
		if err != nil {
			return nil, err
		}
		defer cipherKey.Zero()
		activeKey = cipherKey
	}

	name, err := decryptRequired(enc.Name, activeKey)
	if err != nil {
		return nil, err
	}
	notes, err := decryptOptional(enc.Notes, activeKey)
	if err != nil {
		return nil, err
	}

	c := &Cipher{
		ID:               enc.ID,
		Type:             enc.Type,
		FolderID:         cloneStringPtr(enc.FolderID),
		OrganizationID:   cloneStringPtr(enc.OrganizationID),
		Favorite:         enc.Favorite,
		Reprompt:         enc.Reprompt,
		Key:              cloneStringPtr(enc.Key),
		Name:             name,
		Notes:            notes,
		RevisionDate:     cloneTimePtr(enc.RevisionDate),
		CreationDate:     cloneTimePtr(enc.CreationDate),
		DeletedDate:      cloneTimePtr(enc.DeletedDate),
		ArchivedDate:     cloneTimePtr(enc.ArchivedDate),
		Data:             append(json.RawMessage(nil), enc.Data...),
		EncryptedFor:     cloneStringPtr(enc.EncryptedFor),
		EncryptedByKeyID: cloneStringPtr(enc.EncryptedByKeyID),
		CollectionIDs:    append([]string(nil), enc.CollectionIDs...),
		ReadOnly:         enc.Edit != nil && !*enc.Edit,
		HidePassword:     enc.ViewPassword != nil && !*enc.ViewPassword,
		Extra:            cloneExtra(enc.Extra),
		SealedKeyID:      sealedKeyID(activeKey),
	}

	if enc.Login != nil {
		login, err := decryptLogin(enc.Login, activeKey)
		if err != nil {
			return nil, err
		}
		c.Login = login
	}
	if enc.SecureNote != nil {
		c.SecureNote = &SecureNote{Type: enc.SecureNote.Type, Extra: cloneExtra(enc.SecureNote.Extra), Shape: cloneShape(enc.SecureNote.Shape)}
	}
	if enc.Card != nil {
		card, err := decryptCard(enc.Card, activeKey)
		if err != nil {
			return nil, err
		}
		c.Card = card
	}
	if enc.Identity != nil {
		ident, err := decryptIdentity(enc.Identity, activeKey)
		if err != nil {
			return nil, err
		}
		c.Identity = ident
	}
	if enc.SSHKey != nil {
		key, err := decryptSSHKey(enc.SSHKey, activeKey)
		if err != nil {
			return nil, err
		}
		c.SSHKey = key
	}
	if len(enc.Fields) > 0 {
		c.Fields = make([]CustomField, len(enc.Fields))
		for i, f := range enc.Fields {
			fn, err := decryptOptional(f.Name, activeKey)
			if err != nil {
				return nil, err
			}
			fv, err := decryptOptional(f.Value, activeKey)
			if err != nil {
				return nil, err
			}
			c.Fields[i] = CustomField{
				Name:     fn,
				Value:    fv,
				Type:     f.Type,
				LinkedID: cloneIntPtr(f.LinkedID),
				Extra:    cloneExtra(f.Extra),
				Shape:    cloneShape(f.Shape),
			}
		}
	}
	if len(enc.Attachments) > 0 {
		c.Attachments = make([]Attachment, len(enc.Attachments))
		for i, a := range enc.Attachments {
			name, err := decryptRequired(a.FileName, activeKey)
			if err != nil {
				return nil, err
			}
			c.Attachments[i] = Attachment{
				ID:       a.ID,
				URL:      a.URL,
				FileName: name,
				Key:      cloneStringPtr(a.Key),
				Size:     int64(a.Size),
				SizeName: a.SizeName,
				Extra:    cloneExtra(a.Extra),
			}
		}
	}
	if len(enc.PasswordHistory) > 0 {
		c.PasswordHistory = make([]PasswordHistoryEntry, len(enc.PasswordHistory))
		for i, h := range enc.PasswordHistory {
			pw, err := decryptRequired(h.Password, activeKey)
			if err != nil {
				return nil, err
			}
			c.PasswordHistory[i] = PasswordHistoryEntry{
				Password:     pw,
				LastUsedDate: h.LastUsedDate,
				Extra:        cloneExtra(h.Extra),
				Shape:        cloneShape(h.Shape),
			}
		}
	}

	c.ProvenSealed = collectProven(c, activeKey)
	return c, nil
}

// collectProven proves the unknown fields of c that are ciphertext under key
// (see proveSealed).
func collectProven(c *Cipher, key *crypto.SymmetricKey) map[string]bool {
	extras := []map[string]json.RawMessage{c.Extra}
	if l := c.Login; l != nil {
		extras = append(extras, l.Extra)
		for _, u := range l.URIs {
			extras = append(extras, u.Extra)
		}
	}
	if c.SecureNote != nil {
		extras = append(extras, c.SecureNote.Extra)
	}
	if c.Card != nil {
		extras = append(extras, c.Card.Extra)
	}
	if c.Identity != nil {
		extras = append(extras, c.Identity.Extra)
	}
	if c.SSHKey != nil {
		extras = append(extras, c.SSHKey.Extra)
	}
	for _, f := range c.Fields {
		extras = append(extras, f.Extra)
	}
	for _, h := range c.PasswordHistory {
		extras = append(extras, h.Extra)
	}
	proven := map[string]bool{}
	proveSealed(proven, key, extras...)
	if len(proven) == 0 {
		return nil
	}
	return proven
}

func encryptCipherPayload(c *Cipher, userKey *crypto.SymmetricKey) (*api.CipherPayload, error) {
	activeKey := userKey
	if c.Key != nil && *c.Key != "" {
		rawKey, err := decryptBytesFromString(*c.Key, userKey)
		if err != nil {
			return nil, err
		}
		cipherKey, err := crypto.SymmetricKeyFromBytes(rawKey)
		crypto.ZeroBytes(rawKey)
		if err != nil {
			return nil, err
		}
		defer cipherKey.Zero()
		activeKey = cipherKey
	}

	// Blobs the server sealed (passkeys, URI checksums, encrypted unknown
	// fields) are only sent back under the key they were sealed with.
	sl := &sealer{same: c.SealedKeyID != "" && c.SealedKeyID == sealedKeyID(activeKey), proven: c.ProvenSealed}

	encName, err := crypto.EncryptString(c.Name, activeKey)
	if err != nil {
		return nil, err
	}
	encNotes, err := encryptOptional(c.Notes, activeKey)
	if err != nil {
		return nil, err
	}

	p := &api.CipherPayload{
		Type:                  c.Type,
		FolderID:              cloneStringPtr(c.FolderID),
		OrganizationID:        cloneStringPtr(c.OrganizationID),
		Favorite:              c.Favorite,
		Reprompt:              c.Reprompt,
		Key:                   cloneStringPtr(c.Key),
		Name:                  encName,
		Notes:                 encNotes,
		LastKnownRevisionDate: cloneTimePtr(c.RevisionDate),
		ArchivedDate:          cloneTimePtr(c.ArchivedDate),
		CollectionIDs:         append([]string(nil), c.CollectionIDs...),
		Extra:                 sl.keep(c.Extra),
	}

	if c.Login != nil {
		login, err := encryptLogin(c.Login, activeKey, sl)
		if err != nil {
			return nil, err
		}
		p.Login = login
	}
	if c.SecureNote != nil {
		p.SecureNote = &api.EncryptedSecureNote{Type: c.SecureNote.Type, Extra: sl.keep(c.SecureNote.Extra), Shape: cloneShape(c.SecureNote.Shape)}
	}
	if c.Card != nil {
		card, err := encryptCard(c.Card, activeKey, sl)
		if err != nil {
			return nil, err
		}
		p.Card = card
	}
	if c.Identity != nil {
		ident, err := encryptIdentity(c.Identity, activeKey, sl)
		if err != nil {
			return nil, err
		}
		p.Identity = ident
	}
	if c.SSHKey != nil {
		key, err := encryptSSHKey(c.SSHKey, activeKey, sl)
		if err != nil {
			return nil, err
		}
		p.SSHKey = key
	}
	if len(c.Fields) > 0 {
		p.Fields = make([]api.EncryptedField, len(c.Fields))
		for i, f := range c.Fields {
			fn, err := encryptOptional(f.Name, activeKey)
			if err != nil {
				return nil, err
			}
			fv, err := encryptOptional(f.Value, activeKey)
			if err != nil {
				return nil, err
			}
			p.Fields[i] = api.EncryptedField{
				Name:     fn,
				Value:    fv,
				Type:     f.Type,
				LinkedID: cloneIntPtr(f.LinkedID),
				Extra:    sl.keep(f.Extra),
				Shape:    cloneShape(f.Shape),
			}
		}
	}
	if len(c.PasswordHistory) > 0 {
		p.PasswordHistory = make([]api.EncryptedPasswordHistory, len(c.PasswordHistory))
		for i, h := range c.PasswordHistory {
			pw, err := crypto.EncryptString(h.Password, activeKey)
			if err != nil {
				return nil, err
			}
			p.PasswordHistory[i] = api.EncryptedPasswordHistory{
				Password:     pw,
				LastUsedDate: h.LastUsedDate,
				Extra:        sl.keep(h.Extra),
				Shape:        cloneShape(h.Shape),
			}
		}
	}
	if sl.err != nil {
		return nil, sl.err
	}

	return p, nil
}

// sealer applies keepSealed to every unknown field of one save and keeps
// the first error.
type sealer struct {
	same   bool
	proven map[string]bool
	err    error
}

func (s *sealer) keep(m map[string]json.RawMessage) map[string]json.RawMessage {
	out, err := keepSealed(m, s.same, s.proven)
	if err != nil && s.err == nil {
		s.err = err
	}
	return out
}

func decryptFolder(enc *api.EncryptedFolder, userKey *crypto.SymmetricKey) (Folder, error) {
	name, err := decryptRequired(enc.Name, userKey)
	if err != nil {
		return Folder{}, err
	}
	return Folder{
		ID:           enc.ID,
		Name:         name,
		RevisionDate: cloneTimePtr(enc.RevisionDate),
		Extra:        cloneExtra(enc.Extra),
	}, nil
}

func decryptLogin(enc *api.EncryptedLogin, key *crypto.SymmetricKey) (*Login, error) {
	username, err := decryptOptional(enc.Username, key)
	if err != nil {
		return nil, err
	}
	password, err := decryptOptional(enc.Password, key)
	if err != nil {
		return nil, err
	}
	totp, err := decryptOptional(enc.TOTP, key)
	if err != nil {
		return nil, err
	}
	uris := make([]LoginURI, len(enc.URIs))
	for i, u := range enc.URIs {
		uriStr, err := decryptOptional(u.URI, key)
		if err != nil {
			return nil, err
		}
		uris[i] = LoginURI{
			URI: uriStr, Match: cloneIntPtr(u.Match),
			Checksum: cloneStringPtr(u.URIChecksum), ChecksumOf: uriStr,
			Extra: cloneExtra(u.Extra), Shape: cloneShape(u.Shape),
		}
	}
	l := &Login{
		Username:             username,
		Password:             password,
		TOTP:                 totp,
		URIs:                 uris,
		PasswordRevisionDate: cloneTimePtr(enc.PasswordRevisionDate),
		Extra:                cloneExtra(enc.Extra),
		Shape:                cloneShape(enc.Shape),
	}
	for _, f := range enc.Fido2Credentials {
		l.Fido2Credentials = append(l.Fido2Credentials, decryptFido2(f, key))
	}
	return l, nil
}

// decryptFido2 decrypts a passkey for display and export. A field that does
// not decrypt is left empty and named in Unreadable: the passkey itself is
// still kept and sent back as the server stored it.
func decryptFido2(f api.EncryptedFido2Credential, key *crypto.SymmetricKey) Fido2Credential {
	out := Fido2Credential{CreationDate: f.CreationDate, Sealed: append(json.RawMessage(nil), f.Raw...)}
	for _, fl := range []struct {
		name string
		enc  *string
		dst  *string
	}{
		{"credentialId", f.CredentialID, &out.CredentialID}, {"keyType", f.KeyType, &out.KeyType},
		{"keyAlgorithm", f.KeyAlgorithm, &out.KeyAlgorithm}, {"keyCurve", f.KeyCurve, &out.KeyCurve},
		{"keyValue", f.KeyValue, &out.KeyValue}, {"rpId", f.RpID, &out.RpID},
		{"userHandle", f.UserHandle, &out.UserHandle}, {"userName", f.UserName, &out.UserName},
		{"counter", f.Counter, &out.Counter}, {"rpName", f.RpName, &out.RpName},
		{"userDisplayName", f.UserDisplayName, &out.UserDisplayName}, {"discoverable", f.Discoverable, &out.Discoverable},
	} {
		v, err := decryptOptional(fl.enc, key)
		if err != nil {
			out.Unreadable = append(out.Unreadable, fl.name)
			continue
		}
		*fl.dst = v
	}
	return out
}

// encryptFido2 seals a passkey that came from plaintext, such as one in an
// imported backup. Passkeys from the server are never re-encrypted.
func encryptFido2(f Fido2Credential, key *crypto.SymmetricKey) (api.EncryptedFido2Credential, error) {
	var out api.EncryptedFido2Credential
	fields := []struct {
		plain string
		dst   **string
	}{
		{f.CredentialID, &out.CredentialID}, {f.KeyType, &out.KeyType}, {f.KeyAlgorithm, &out.KeyAlgorithm},
		{f.KeyCurve, &out.KeyCurve}, {f.KeyValue, &out.KeyValue}, {f.RpID, &out.RpID},
		{f.UserHandle, &out.UserHandle}, {f.UserName, &out.UserName}, {f.Counter, &out.Counter},
		{f.RpName, &out.RpName}, {f.UserDisplayName, &out.UserDisplayName}, {f.Discoverable, &out.Discoverable},
	}
	for _, fl := range fields {
		v, err := encryptOptional(fl.plain, key)
		if err != nil {
			return out, err
		}
		*fl.dst = v
	}
	out.CreationDate = f.CreationDate
	return out, nil
}

func encryptLogin(l *Login, key *crypto.SymmetricKey, sl *sealer) (*api.EncryptedLogin, error) {
	username, err := encryptOptional(l.Username, key)
	if err != nil {
		return nil, err
	}
	password, err := encryptOptional(l.Password, key)
	if err != nil {
		return nil, err
	}
	totp, err := encryptOptional(l.TOTP, key)
	if err != nil {
		return nil, err
	}
	var uris []api.EncryptedLoginURI
	if len(l.URIs) > 0 {
		uris = make([]api.EncryptedLoginURI, len(l.URIs))
		for i, u := range l.URIs {
			eu, err := encryptOptional(u.URI, key)
			if err != nil {
				return nil, err
			}
			out := api.EncryptedLoginURI{URI: eu, Match: cloneIntPtr(u.Match), Extra: sl.keep(u.Extra), Shape: cloneShape(u.Shape)}
			switch {
			case sl.same && u.Checksum != nil && u.URI == u.ChecksumOf:
				out.URIChecksum = cloneStringPtr(u.Checksum)
			case u.URI != "":
				if out.URIChecksum, err = uriChecksum(u.URI, key); err != nil {
					return nil, err
				}
			}
			uris[i] = out
		}
	}
	out := &api.EncryptedLogin{
		Username:             username,
		Password:             password,
		TOTP:                 totp,
		URIs:                 uris,
		PasswordRevisionDate: cloneTimePtr(l.PasswordRevisionDate),
		Extra:                sl.keep(l.Extra),
		Shape:                cloneShape(l.Shape),
	}
	for _, f := range l.Fido2Credentials {
		switch {
		case len(f.Sealed) > 0 && sl.same:
			out.Fido2Credentials = append(out.Fido2Credentials, api.EncryptedFido2Credential{Raw: append(json.RawMessage(nil), f.Sealed...)})
		case len(f.Sealed) > 0:
			// Sealed under another key: nobody could use it here, and a
			// passkey is never copied to another item.
		default:
			ef, err := encryptFido2(f, key)
			if err != nil {
				return nil, err
			}
			out.Fido2Credentials = append(out.Fido2Credentials, ef)
		}
	}
	return out, nil
}

func decryptCard(enc *api.EncryptedCard, key *crypto.SymmetricKey) (*Card, error) {
	fields := []*string{enc.CardholderName, enc.Brand, enc.Number, enc.ExpMonth, enc.ExpYear, enc.Code}
	out := make([]string, len(fields))
	for i, f := range fields {
		v, err := decryptOptional(f, key)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return &Card{
		CardholderName: out[0],
		Brand:          out[1],
		Number:         out[2],
		ExpMonth:       out[3],
		ExpYear:        out[4],
		Code:           out[5],
		Extra:          cloneExtra(enc.Extra),
		Shape:          cloneShape(enc.Shape),
	}, nil
}

func encryptCard(c *Card, key *crypto.SymmetricKey, sl *sealer) (*api.EncryptedCard, error) {
	vals := []string{c.CardholderName, c.Brand, c.Number, c.ExpMonth, c.ExpYear, c.Code}
	out := make([]*string, len(vals))
	for i, v := range vals {
		ev, err := encryptOptional(v, key)
		if err != nil {
			return nil, err
		}
		out[i] = ev
	}
	return &api.EncryptedCard{
		CardholderName: out[0],
		Brand:          out[1],
		Number:         out[2],
		ExpMonth:       out[3],
		ExpYear:        out[4],
		Code:           out[5],
		Extra:          sl.keep(c.Extra),
		Shape:          cloneShape(c.Shape),
	}, nil
}

func decryptIdentity(enc *api.EncryptedIdentity, key *crypto.SymmetricKey) (*Identity, error) {
	fields := []*string{
		enc.Title, enc.FirstName, enc.MiddleName, enc.LastName,
		enc.Address1, enc.Address2, enc.Address3, enc.City,
		enc.State, enc.PostalCode, enc.Country, enc.Company,
		enc.Email, enc.Phone, enc.SSN, enc.Username,
		enc.PassportNumber, enc.LicenseNumber,
	}
	out := make([]string, len(fields))
	for i, f := range fields {
		v, err := decryptOptional(f, key)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return &Identity{
		Title: out[0], FirstName: out[1], MiddleName: out[2], LastName: out[3],
		Address1: out[4], Address2: out[5], Address3: out[6], City: out[7],
		State: out[8], PostalCode: out[9], Country: out[10], Company: out[11],
		Email: out[12], Phone: out[13], SSN: out[14], Username: out[15],
		PassportNumber: out[16], LicenseNumber: out[17],
		Extra: cloneExtra(enc.Extra), Shape: cloneShape(enc.Shape),
	}, nil
}

func encryptIdentity(id *Identity, key *crypto.SymmetricKey, sl *sealer) (*api.EncryptedIdentity, error) {
	vals := []string{
		id.Title, id.FirstName, id.MiddleName, id.LastName,
		id.Address1, id.Address2, id.Address3, id.City,
		id.State, id.PostalCode, id.Country, id.Company,
		id.Email, id.Phone, id.SSN, id.Username,
		id.PassportNumber, id.LicenseNumber,
	}
	out := make([]*string, len(vals))
	for i, v := range vals {
		ev, err := encryptOptional(v, key)
		if err != nil {
			return nil, err
		}
		out[i] = ev
	}
	return &api.EncryptedIdentity{
		Title: out[0], FirstName: out[1], MiddleName: out[2], LastName: out[3],
		Address1: out[4], Address2: out[5], Address3: out[6], City: out[7],
		State: out[8], PostalCode: out[9], Country: out[10], Company: out[11],
		Email: out[12], Phone: out[13], SSN: out[14], Username: out[15],
		PassportNumber: out[16], LicenseNumber: out[17],
		Extra: sl.keep(id.Extra), Shape: cloneShape(id.Shape),
	}, nil
}

func decryptSSHKey(enc *api.EncryptedSSHKey, key *crypto.SymmetricKey) (*SSHKey, error) {
	fields := []*string{enc.PrivateKey, enc.PublicKey, enc.KeyFingerprint}
	out := make([]string, len(fields))
	for i, f := range fields {
		v, err := decryptOptional(f, key)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return &SSHKey{PrivateKey: out[0], PublicKey: out[1], KeyFingerprint: out[2], Extra: cloneExtra(enc.Extra), Shape: cloneShape(enc.Shape)}, nil
}

func encryptSSHKey(k *SSHKey, key *crypto.SymmetricKey, sl *sealer) (*api.EncryptedSSHKey, error) {
	vals := []string{k.PrivateKey, k.PublicKey, k.KeyFingerprint}
	out := make([]*string, len(vals))
	for i, v := range vals {
		ev, err := encryptOptional(v, key)
		if err != nil {
			return nil, err
		}
		out[i] = ev
	}
	return &api.EncryptedSSHKey{PrivateKey: out[0], PublicKey: out[1], KeyFingerprint: out[2], Extra: sl.keep(k.Extra), Shape: cloneShape(k.Shape)}, nil
}

func decryptBytesFromString(encStr string, key *crypto.SymmetricKey) ([]byte, error) {
	parsed, err := crypto.ParseEncString(encStr)
	if err != nil {
		return nil, err
	}
	return crypto.DecryptBytes(parsed, key)
}

func decryptRequired(encStr string, key *crypto.SymmetricKey) (string, error) {
	if encStr == "" {
		return "", nil
	}
	return crypto.DecryptString(encStr, key)
}

func decryptOptional(encStr *string, key *crypto.SymmetricKey) (string, error) {
	if encStr == nil || *encStr == "" {
		return "", nil
	}
	return crypto.DecryptString(*encStr, key)
}

func encryptOptional(plain string, key *crypto.SymmetricKey) (*string, error) {
	if plain == "" {
		return nil, nil
	}
	enc, err := crypto.EncryptString(plain, key)
	if err != nil {
		return nil, err
	}
	return &enc, nil
}

func cloneCipher(c *Cipher) *Cipher {
	if c == nil {
		return nil
	}
	cp := *c
	cp.FolderID = cloneStringPtr(c.FolderID)
	cp.OrganizationID = cloneStringPtr(c.OrganizationID)
	cp.Key = cloneStringPtr(c.Key)
	cp.RevisionDate = cloneTimePtr(c.RevisionDate)
	cp.CreationDate = cloneTimePtr(c.CreationDate)
	cp.DeletedDate = cloneTimePtr(c.DeletedDate)
	cp.ArchivedDate = cloneTimePtr(c.ArchivedDate)
	cp.EncryptedFor = cloneStringPtr(c.EncryptedFor)
	cp.EncryptedByKeyID = cloneStringPtr(c.EncryptedByKeyID)
	cp.Data = append(json.RawMessage(nil), c.Data...)
	cp.Extra = cloneExtra(c.Extra)
	cp.ProvenSealed = maps.Clone(c.ProvenSealed)
	cp.CollectionIDs = append([]string(nil), c.CollectionIDs...)
	if c.Login != nil {
		l := *c.Login
		l.PasswordRevisionDate = cloneTimePtr(c.Login.PasswordRevisionDate)
		l.Extra = cloneExtra(c.Login.Extra)
		l.Shape = cloneShape(c.Login.Shape)
		l.URIs = nil
		for _, u := range c.Login.URIs {
			u.Match = cloneIntPtr(u.Match)
			u.Checksum = cloneStringPtr(u.Checksum)
			u.Extra = cloneExtra(u.Extra)
			u.Shape = cloneShape(u.Shape)
			l.URIs = append(l.URIs, u)
		}
		l.Fido2Credentials = nil
		for _, f := range c.Login.Fido2Credentials {
			f.Sealed = append(json.RawMessage(nil), f.Sealed...)
			f.Unreadable = slices.Clone(f.Unreadable)
			l.Fido2Credentials = append(l.Fido2Credentials, f)
		}
		cp.Login = &l
	}
	if c.SecureNote != nil {
		sn := *c.SecureNote
		sn.Extra = cloneExtra(c.SecureNote.Extra)
		sn.Shape = cloneShape(c.SecureNote.Shape)
		cp.SecureNote = &sn
	}
	if c.Card != nil {
		card := *c.Card
		card.Extra = cloneExtra(c.Card.Extra)
		card.Shape = cloneShape(c.Card.Shape)
		cp.Card = &card
	}
	if c.Identity != nil {
		id := *c.Identity
		id.Extra = cloneExtra(c.Identity.Extra)
		id.Shape = cloneShape(c.Identity.Shape)
		cp.Identity = &id
	}
	if c.SSHKey != nil {
		k := *c.SSHKey
		k.Extra = cloneExtra(c.SSHKey.Extra)
		k.Shape = cloneShape(c.SSHKey.Shape)
		cp.SSHKey = &k
	}
	cp.Fields = nil
	for _, f := range c.Fields {
		f.LinkedID = cloneIntPtr(f.LinkedID)
		f.Extra = cloneExtra(f.Extra)
		f.Shape = cloneShape(f.Shape)
		cp.Fields = append(cp.Fields, f)
	}
	cp.PasswordHistory = nil
	for _, h := range c.PasswordHistory {
		h.Extra = cloneExtra(h.Extra)
		h.Shape = cloneShape(h.Shape)
		cp.PasswordHistory = append(cp.PasswordHistory, h)
	}
	if len(c.Attachments) > 0 {
		cp.Attachments = make([]Attachment, len(c.Attachments))
		for i, a := range c.Attachments {
			a.Key = cloneStringPtr(a.Key)
			a.Extra = cloneExtra(a.Extra)
			cp.Attachments[i] = a
		}
	}
	return &cp
}

func summarizeCipher(c *Cipher) CipherSummary {
	subtitle := ""
	hasTOTP, hasPasskey := false, false
	var uris []string
	switch c.Type {
	case api.CipherTypeLogin:
		if c.Login != nil {
			subtitle = c.Login.Username
			hasTOTP = strings.TrimSpace(c.Login.TOTP) != ""
			hasPasskey = len(c.Login.Fido2Credentials) > 0
			for _, u := range c.Login.URIs {
				uris = append(uris, u.URI)
			}
		}
	case api.CipherTypeCard:
		if c.Card != nil {
			subtitle = c.Card.Brand
			if subtitle == "" {
				subtitle = c.Card.CardholderName
			}
		}
	case api.CipherTypeIdentity:
		if c.Identity != nil {
			subtitle = strings.TrimSpace(c.Identity.FirstName + " " + c.Identity.LastName)
			if subtitle == "" {
				subtitle = c.Identity.Email
			}
		}
	case api.CipherTypeSSHKey:
		if c.SSHKey != nil {
			subtitle = c.SSHKey.KeyFingerprint
		}
	}
	return CipherSummary{
		ID:       c.ID,
		Type:     c.Type,
		FolderID: cloneStringPtr(c.FolderID),
		Favorite: c.Favorite,
		Deleted:  c.DeletedDate != nil,
		Archived: c.ArchivedDate != nil,
		Name:     c.Name,
		Subtitle: subtitle,
		HasTOTP:  hasTOTP,

		HasPasskey:   hasPasskey,
		RevisionDate: cloneTimePtr(c.RevisionDate),
		Reprompt:     c.Reprompt,
		URIs:         uris,

		OrganizationID: cloneStringPtr(c.OrganizationID),
		CollectionIDs:  append([]string(nil), c.CollectionIDs...),
	}
}

func cloneStringPtr(p *string) *string {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneIntPtr(p *int) *int {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneTimePtr(p *time.Time) *time.Time {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneExtra(m map[string]json.RawMessage) map[string]json.RawMessage {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]json.RawMessage, len(m))
	maps.Copy(out, m)
	return out
}

func cloneShape(m api.Shape) api.Shape {
	if len(m) == 0 {
		return nil
	}
	out := make(api.Shape, len(m))
	for k, v := range m {
		out[k] = v.Clone()
	}
	return out
}
