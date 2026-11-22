package export

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/state"
)

type Class int

const (
	ClassNew Class = iota
	ClassConflict
	ClassIdentical
)

type Action int

const (
	ActionSkip Action = iota
	ActionCreate
	ActionUpdate
)

// Entry is one backup item compared with the vault. Nothing is written until
// Apply runs, and only as Action says.
type Entry struct {
	Item       Item
	FolderName string
	Class      Class
	// Match is the vault item the backup item corresponds to, for conflicts
	// and identical items.
	Match *state.Cipher
	// Diff names the fields that differ, never their values.
	Diff []string
	// MatchRevision is the revision of Match the user reviewed. Update
	// refuses to write over an item that changed since.
	MatchRevision *time.Time
	// Ambiguous means several vault items have this item's type, name and
	// username, so it is matched to none of them.
	Ambiguous bool
	// Unsupported means MyVault cannot save items of this type (such as a
	// bank account, driver's license or passport), so it is only skipped.
	Unsupported bool
	CanUpdate   bool
	// UpdateBlocked says why Update is not offered for a backup item that
	// cannot safely update its match, if that is the reason.
	UpdateBlocked string
	Action        Action

	repromptOK *approval
}

// approval is a master-password verification for updating one protected
// item at one revision.
type approval struct {
	id  string
	rev *time.Time
}

// NeedsReprompt reports that Update changes a vault item protected by
// master-password reprompt, which the user must verify first.
func (e *Entry) NeedsReprompt() bool {
	return e.Match != nil && e.Match.Reprompt != 0 && e.repromptOK == nil
}

// ApproveReprompt records that the user verified the master password to
// update Match at the reviewed revision.
func (e *Entry) ApproveReprompt() {
	if e.Match != nil {
		e.repromptOK = &approval{id: e.Match.ID, rev: e.MatchRevision}
	}
}

func (e *Entry) approvedFor(c *state.Cipher) bool {
	return c.Reprompt == 0 || (e.repromptOK != nil && e.repromptOK.id == c.ID && sameTime(e.repromptOK.rev, c.RevisionDate))
}

var (
	// ErrChangedSinceReview means the vault item changed after the user
	// reviewed the import; it is not overwritten.
	ErrChangedSinceReview = errors.New("export: the item changed after you reviewed the import; review it again")
	// ErrRepromptRequired means the vault item is protected by
	// master-password reprompt and the update was not verified.
	ErrRepromptRequired = errors.New("export: updating this protected item needs your master password")
	// ErrUnsupportedType means MyVault cannot save items of this type.
	ErrUnsupportedType = errors.New("export: MyVault cannot save this type of item yet")
)

func sameTime(a, b *time.Time) bool {
	return (a == nil) == (b == nil) && (a == nil || a.Equal(*b))
}

// Allowed lists the actions the entry may take.
func (e *Entry) Allowed() []Action {
	switch {
	case e.Unsupported:
		return []Action{ActionSkip}
	case e.Class == ClassNew:
		return []Action{ActionCreate, ActionSkip}
	case e.CanUpdate:
		return []Action{ActionSkip, ActionCreate, ActionUpdate}
	default:
		return []Action{ActionSkip, ActionCreate}
	}
}

// SetAction applies a if the entry allows it.
func (e *Entry) SetAction(a Action) bool {
	if !slices.Contains(e.Allowed(), a) || (a == ActionUpdate && e.NeedsReprompt()) {
		return false
	}
	e.Action = a
	return true
}

type Plan struct {
	Entries []Entry
}

type Counts struct {
	New, Conflicts, Identical int
	Create, Update, Skip      int
}

func (p *Plan) Counts() Counts {
	var c Counts
	for _, e := range p.Entries {
		switch e.Class {
		case ClassNew:
			c.New++
		case ClassConflict:
			c.Conflicts++
		case ClassIdentical:
			c.Identical++
		}
		switch e.Action {
		case ActionCreate:
			c.Create++
		case ActionUpdate:
			c.Update++
		default:
			c.Skip++
		}
	}
	return c
}

func itemKey(t int, name, username string) string {
	return fmt.Sprintf("%d\x00%s\x00%s", t, strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(username))
}

func cipherUsername(c *state.Cipher) string {
	if c.Login != nil {
		return c.Login.Username
	}
	return ""
}

// BuildPlan compares the backup with the active vault items. A backup item
// matches a vault item with the same ID, or else the same type, name and
// username. New items default to Create; conflicts and identical items
// default to Skip, so nothing in the vault changes unless the user asks.
func BuildPlan(backup *Vault, current []*state.Cipher, folders []state.Folder) *Plan {
	backupFolders := map[string]string{}
	for _, f := range backup.Folders {
		backupFolders[f.ID] = f.Name
	}
	currentFolders := map[string]string{}
	for _, f := range folders {
		currentFolders[f.ID] = f.Name
	}
	byID := map[string]*state.Cipher{}
	byKey := map[string][]*state.Cipher{}
	for _, c := range current {
		if c == nil || c.DeletedDate != nil {
			continue
		}
		byID[c.ID] = c
		k := itemKey(int(c.Type), c.Name, cipherUsername(c))
		byKey[k] = append(byKey[k], c)
	}
	// Exact IDs are matched first, so a name match never takes an item
	// another backup item names by ID.
	items := slices.DeleteFunc(slices.Clone(backup.Items), func(it Item) bool { return it.DeletedDate != nil })
	matches := make([]*state.Cipher, len(items))
	used := map[string]bool{}
	for i, it := range items {
		if c := byID[it.ID]; c != nil && !used[c.ID] && c.Type == it.Type {
			matches[i], used[c.ID] = c, true
		}
	}
	// A name match counts only when it is one to one: one vault item with
	// that type, name and username left, wanted by one backup item.
	keyOf := func(it Item) string {
		username := ""
		if it.Login != nil {
			username = val(it.Login.Username)
		}
		return itemKey(int(it.Type), it.Name, username)
	}
	wanted := map[string]int{}
	for i, it := range items {
		if matches[i] == nil {
			wanted[keyOf(it)]++
		}
	}
	ambiguous := make([]bool, len(items))
	for i, it := range items {
		if matches[i] != nil {
			continue
		}
		var free []*state.Cipher
		for _, c := range byKey[keyOf(it)] {
			if !used[c.ID] {
				free = append(free, c)
			}
		}
		switch {
		case len(free) == 1 && wanted[keyOf(it)] == 1:
			matches[i] = free[0]
		case len(free) > 0:
			ambiguous[i] = true
		}
	}
	for i := range matches {
		if matches[i] != nil {
			used[matches[i].ID] = true
		}
	}

	p := &Plan{}
	for i, it := range items {
		e := Entry{Item: it, FolderName: backupFolders[val(it.FolderID)]}
		match := matches[i]
		if !it.savable() {
			e.Class, e.Action, e.Unsupported = ClassNew, ActionSkip, true
			p.Entries = append(p.Entries, e)
			continue
		}
		switch {
		case match == nil && ambiguous[i]:
			e.Class, e.Action, e.Ambiguous = ClassNew, ActionSkip, true
		case match == nil:
			e.Class, e.Action = ClassNew, ActionCreate
		default:
			e.Match = match
			e.MatchRevision = match.RevisionDate
			e.Diff = diff(it, e.FolderName, match, currentFolders[val(match.FolderID)])
			e.CanUpdate = !match.ReadOnly && !match.HidePassword
			switch probe := *match; {
			case !e.CanUpdate:
			case !it.complete():
				e.CanUpdate, e.UpdateBlocked = false, "the backup item is incomplete"
			case mergeContent(&probe, it) != nil:
				e.CanUpdate, e.UpdateBlocked = false, "its fields or websites cannot be matched safely"
			}
			e.Class, e.Action = ClassIdentical, ActionSkip
			if len(e.Diff) > 0 {
				e.Class = ClassConflict
			}
		}
		p.Entries = append(p.Entries, e)
	}
	return p
}

func diff(it Item, folderName string, c *state.Cipher, currentFolder string) []string {
	want := it.content()
	var out []string
	add := func(label string, differ bool) {
		if differ {
			out = append(out, label)
		}
	}
	add("Name", want.Name != c.Name)
	add("Notes", want.Notes != c.Notes)
	add("Folder", !strings.EqualFold(folderName, currentFolder))
	add("Favorite", want.Favorite != c.Favorite)
	add("Reprompt", want.Reprompt != c.Reprompt)
	if want.Login != nil || c.Login != nil {
		a, b := want.Login, c.Login
		if a == nil {
			a = &state.Login{}
		}
		if b == nil {
			b = &state.Login{}
		}
		add("Username", a.Username != b.Username)
		add("Password", a.Password != b.Password)
		add("Verification Code", a.TOTP != b.TOTP)
		add("Websites", !slices.EqualFunc(a.URIs, b.URIs, func(x, y state.LoginURI) bool {
			return x.URI == y.URI && sameMatch(x.Match, y.Match)
		}))
	}
	if want.Login != nil && c.Login != nil && len(want.Login.Fido2Credentials) > 0 {
		add("Passkey", !samePasskeys(want.Login.Fido2Credentials, c.Login.Fido2Credentials))
	}
	add("Card", ptrDiff(cardContentOf(want.Card), cardContentOf(c.Card)))
	add("Identity", ptrDiff(identityContentOf(want.Identity), identityContentOf(c.Identity)))
	add("SSH Key", ptrDiff(sshKeyContentOf(want.SSHKey), sshKeyContentOf(c.SSHKey)))
	add("Custom Fields", !slices.EqualFunc(want.Fields, c.Fields, func(x, y state.CustomField) bool {
		return x.Name == y.Name && x.Value == y.Value && x.Type == y.Type && sameMatch(x.LinkedID, y.LinkedID)
	}))
	return out
}

// samePasskeys compares passkeys by credential and relying party, never by
// their secret material.
func samePasskeys(a, b []state.Fido2Credential) bool {
	return slices.EqualFunc(a, b, func(x, y state.Fido2Credential) bool {
		return x.CredentialID == y.CredentialID && x.RpID == y.RpID
	})
}

// The content types reduce nested items to what the user sees, so the diff
// ignores the unknown fields the server stores with them.
type cardContent struct {
	CardholderName, Brand, Number, ExpMonth, ExpYear, Code string
}

type identityContent struct {
	Title, FirstName, MiddleName, LastName, Address1, Address2, Address3, City, State,
	PostalCode, Country, Company, Email, Phone, SSN, Username, PassportNumber, LicenseNumber string
}

type sshKeyContent struct {
	PrivateKey, PublicKey, KeyFingerprint string
}

func cardContentOf(t *state.Card) *cardContent {
	if t == nil {
		return nil
	}
	return &cardContent{t.CardholderName, t.Brand, t.Number, t.ExpMonth, t.ExpYear, t.Code}
}

func identityContentOf(t *state.Identity) *identityContent {
	if t == nil {
		return nil
	}
	return &identityContent{t.Title, t.FirstName, t.MiddleName, t.LastName, t.Address1, t.Address2, t.Address3,
		t.City, t.State, t.PostalCode, t.Country, t.Company, t.Email, t.Phone, t.SSN, t.Username, t.PassportNumber, t.LicenseNumber}
}

func sshKeyContentOf(t *state.SSHKey) *sshKeyContent {
	if t == nil {
		return nil
	}
	return &sshKeyContent{t.PrivateKey, t.PublicKey, t.KeyFingerprint}
}

func ptrDiff[T comparable](a, b *T) bool {
	switch {
	case a == nil && b == nil:
		return false
	case a == nil || b == nil:
		var zero T
		if a == nil {
			return *b != zero
		}
		return *a != zero
	}
	return *a != *b
}

// Writer is what Apply needs from the vault.
type Writer interface {
	GetCipher(id string) (*state.Cipher, error)
	SaveCipher(ctx context.Context, c *state.Cipher) (*state.Cipher, error)
	Folders() []state.Folder
	SaveFolder(ctx context.Context, f *state.Folder) (*state.Folder, error)
}

type Result struct {
	Created, Updated, Skipped, Failed int
	Err                               error
	// LocalCopyErr reports changes the server accepted (and that are
	// counted as created or updated) but MyVault could not write to its
	// encrypted local copy. They must not be retried; a sync refreshes
	// the local copy.
	LocalCopyErr error
}

// Apply carries out exactly the actions chosen in p. Folders the approved
// items need are reused by name or created. Updates keep the vault item's
// identity, organization and attachments and replace its content.
func Apply(ctx context.Context, w Writer, p *Plan) Result {
	var res Result
	var errs, local []error
	// done splits err into a committed change, whose local copy may have
	// failed, and a real failure.
	done := func(name string, err error) bool {
		var lc *state.LocalCopyError
		if errors.As(err, &lc) {
			local = append(local, fmt.Errorf("%s: %w", name, err))
			return true
		}
		return err == nil
	}
	folderIDs := map[string]string{}
	for _, f := range w.Folders() {
		key := strings.ToLower(f.Name)
		if _, ok := folderIDs[key]; !ok {
			folderIDs[key] = f.ID
		}
	}
	folderFor := func(name string) (*string, error) {
		if strings.TrimSpace(name) == "" {
			return nil, nil
		}
		key := strings.ToLower(name)
		if id, ok := folderIDs[key]; ok {
			return &id, nil
		}
		f, err := w.SaveFolder(ctx, &state.Folder{Name: name})
		if !done("folder "+name, err) {
			return nil, err
		}
		folderIDs[key] = f.ID
		return &f.ID, nil
	}

	for i := range p.Entries {
		e := &p.Entries[i]
		if ctx.Err() != nil || errors.Is(errors.Join(errs...), state.ErrLocked) {
			if e.Action != ActionSkip {
				res.Failed++
			} else {
				res.Skipped++
			}
			continue
		}
		var err error
		switch e.Action {
		case ActionCreate:
			if err = createItem(ctx, w, e, folderFor); done(e.Item.Name, err) {
				res.Created++
				continue
			}
		case ActionUpdate:
			if err = updateItem(ctx, w, e, folderFor); done(e.Item.Name, err) {
				res.Updated++
				continue
			}
		default:
			res.Skipped++
			continue
		}
		res.Failed++
		errs = append(errs, fmt.Errorf("%s: %w", e.Item.Name, err))
	}
	res.Err = errors.Join(errs...)
	res.LocalCopyErr = errors.Join(local...)
	return res
}

func createItem(ctx context.Context, w Writer, e *Entry, folderFor func(string) (*string, error)) error {
	if !e.Item.savable() {
		return ErrUnsupportedType
	}
	c := e.Item.content()
	if e.Class != ClassNew && c.Login != nil {
		// Create Copy: a passkey belongs to one item and is never copied.
		c.Login.Fido2Credentials = nil
	}
	folder, err := folderFor(e.FolderName)
	if err != nil {
		return err
	}
	c.FolderID = folder
	_, err = w.SaveCipher(ctx, c)
	return err
}

func updateItem(ctx context.Context, w Writer, e *Entry, folderFor func(string) (*string, error)) error {
	if !e.Item.savable() {
		return ErrUnsupportedType
	}
	if e.Match == nil || !e.CanUpdate {
		return state.ErrReadOnlyCipher
	}
	cur, err := w.GetCipher(e.Match.ID)
	if err != nil {
		return err
	}
	if cur.ReadOnly || cur.HidePassword || cur.DeletedDate != nil || cur.Type != e.Item.Type || !e.Item.complete() {
		return state.ErrReadOnlyCipher
	}
	if cur.ID != e.Match.ID || !sameTime(cur.RevisionDate, e.MatchRevision) {
		return ErrChangedSinceReview
	}
	if !e.approvedFor(cur) {
		return ErrRepromptRequired
	}
	folder, err := folderFor(e.FolderName)
	if err != nil {
		return err
	}
	cur.Name = e.Item.Name
	cur.Notes = val(e.Item.Notes)
	cur.Favorite = e.Item.Favorite
	cur.Reprompt = e.Item.Reprompt
	cur.FolderID = folder
	if err := mergeContent(cur, e.Item); err != nil {
		return err
	}
	_, err = w.SaveCipher(ctx, cur)
	return err
}
