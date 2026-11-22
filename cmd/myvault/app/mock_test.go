package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/crypto"
	"github.com/oneryx/myvault/internal/vaultcore/state"
	"github.com/oneryx/myvault/internal/vaultcore/store"
)

type mockVaultService struct {
	mu       sync.RWMutex
	status   state.LockStatus
	password string
	ciphers  map[string]*state.Cipher
	order    []string
	folders  []state.Folder

	twoFactorCode string
	emailSends    int

	organizations []state.Organization
	collections   []state.Collection

	downloadGate chan struct{}

	// localCopyFails makes saves succeed on the "server" but report a
	// failed local copy, as state.Service does when the snapshot write fails.
	localCopyFails bool
	creates        int

	syncErrs  []error
	syncCalls int

	unreadable []string
	noPremium  bool
	// session names the mock's current session; archiveSessions records
	// the session each archive request was bound to.
	session         int
	archiveSessions []any
	uploads         int
	attempt         uint64
	revokes         int
	localOnly       bool
	credsUnsaved    bool
	lastLogin       state.LoginRequest
	// trustedServer is the server the trusted sign-in record names.
	trustedServer string
	// emailGate, when set, holds SendEmailTwoFactorCode until closed.
	emailGate chan struct{}
	// unlockCommitted, when set, holds UnlockWithPassword after it commits
	// until the test answers.
	unlockCommitted chan struct{}
	// saveGate, when set, holds SaveCipher until it is closed.
	saveGate chan struct{}
	// accounts are the vaults on the "device"; current is the one open or
	// locked, "" for the default account acct-1 when accounts is empty.
	accounts []state.Account
	current  string
	switches []string
}

func newMockVaultService(initial state.LockStatus) *mockVaultService {
	c1 := &state.Cipher{
		ID:       "c-github",
		Type:     api.CipherTypeLogin,
		Name:     "GitHub",
		Favorite: true,
		Login: &state.Login{
			Username: "alice@example.com",
			Password: "gh-secret-password",
			TOTP:     "JBSWY3DPEHPK3PXP",
			URIs:     []state.LoginURI{{URI: "https://github.com"}},
		},
	}
	c2 := &state.Cipher{
		ID:         "c-note",
		Type:       api.CipherTypeSecureNote,
		Name:       "SSH Recovery Note",
		Notes:      "Keep safe",
		SecureNote: &state.SecureNote{Type: 0},
	}
	return &mockVaultService{
		status:   initial,
		password: "master-password",
		ciphers: map[string]*state.Cipher{
			c1.ID: c1,
			c2.ID: c2,
		},
		order: []string{c1.ID, c2.ID},
		folders: []state.Folder{
			{ID: "f-work", Name: "Work"},
		},
	}
}

func (m *mockVaultService) Status() state.LockStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

func (m *mockVaultService) Login(_ context.Context, req state.LoginRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastLogin = req
	if string(req.MasterPassword) != m.password {
		return api.ErrUnauthorized
	}
	if m.twoFactorCode != "" && (req.TwoFactorProvider != api.TwoFactorEmail || req.TwoFactorCode != m.twoFactorCode) {
		if req.TwoFactorCode != "" {
			return &api.APIError{StatusCode: 400, Message: "Invalid TOTP code"}
		}
		return &api.TwoFactorRequiredError{Challenge: api.TwoFactorChallenge{
			Providers:    []api.TwoFactorProvider{api.TwoFactorAuthenticator, api.TwoFactorEmail},
			ProviderData: map[api.TwoFactorProvider]json.RawMessage{api.TwoFactorEmail: json.RawMessage(`{"Email":"a***@example.com"}`)},
		}}
	}
	m.status = state.StatusUnlocked
	if m.accounts != nil {
		id := "acct-" + req.Email
		if !slices.ContainsFunc(m.accounts, func(a state.Account) bool { return a.ID == id }) {
			m.accounts = append(m.accounts, state.Account{ID: id, Email: req.Email, ServerURL: req.ServerURL})
		}
		m.current = id
	}
	return nil
}

func (m *mockVaultService) SendEmailTwoFactorCode(_ context.Context, req state.LoginRequest) error {
	m.mu.RLock()
	gate := m.emailGate
	m.mu.RUnlock()
	if gate != nil {
		<-gate
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if string(req.MasterPassword) != m.password {
		return api.ErrUnauthorized
	}
	m.emailSends++
	return nil
}

func (m *mockVaultService) UnlockWithPassword(_ context.Context, pw []byte) error {
	m.mu.Lock()
	if string(pw) != m.password {
		m.mu.Unlock()
		return crypto.ErrInvalidMAC
	}
	m.status = state.StatusUnlocked
	committed := m.unlockCommitted
	m.mu.Unlock()
	if committed != nil {
		// The service has committed the session; the UI has not heard yet.
		committed <- struct{}{}
		<-committed
	}
	return nil
}

func (m *mockVaultService) UnlockWithUserKey(_ context.Context, _ *crypto.SymmetricKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status = state.StatusUnlocked
	return nil
}

func (m *mockVaultService) EnableBiometricUnlock(_ store.SecretStore) error  { return nil }
func (m *mockVaultService) DisableBiometricUnlock(_ store.SecretStore) error { return nil }

func (m *mockVaultService) Lock() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status == state.StatusUnlocked {
		m.status = state.StatusLocked
	}
}

func (m *mockVaultService) Logout(_ context.Context, _ store.SecretStore) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status = state.StatusLoggedOut
	m.accounts = slices.DeleteFunc(m.accounts, func(a state.Account) bool { return a.ID == m.current })
	m.current = ""
	return nil
}

func (m *mockVaultService) Accounts() []state.Account {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return slices.Clone(m.accounts)
}

func (m *mockVaultService) SwitchAccount(accountID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if accountID != "" && !slices.ContainsFunc(m.accounts, func(a state.Account) bool { return a.ID == accountID }) {
		return store.ErrSnapshotNotFound
	}
	m.switches = append(m.switches, accountID)
	m.attempt++
	m.current = accountID
	m.status = state.StatusLoggedOut
	if accountID != "" {
		m.status = state.StatusLocked
	}
	return nil
}

func (m *mockVaultService) SyncNow(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncCalls++
	if len(m.syncErrs) == 0 {
		return nil
	}
	err := m.syncErrs[0]
	m.syncErrs = m.syncErrs[1:]
	return err
}

func (m *mockVaultService) Search(query string, filter state.SearchFilter) []state.CipherSummary {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.status != state.StatusUnlocked {
		return nil
	}
	q := strings.ToLower(strings.TrimSpace(query))
	var out []state.CipherSummary
	for _, id := range m.order {
		c := m.ciphers[id]
		if c == nil {
			continue
		}
		deleted := c.DeletedDate != nil
		if filter.Category == state.FilterTrash {
			if !deleted {
				continue
			}
		} else if deleted {
			continue
		} else if (filter.Category == state.FilterArchive) != (c.ArchivedDate != nil) {
			continue
		}
		if filter.Category == state.FilterFavorites && !c.Favorite {
			continue
		}
		if filter.Type != nil && c.Type != *filter.Type {
			continue
		}
		if filter.CollectionID != "" && !slices.Contains(c.CollectionIDs, filter.CollectionID) {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(c.Name), q) {
			continue
		}
		sub := ""
		hasTOTP := false
		if c.Login != nil {
			sub = c.Login.Username
			hasTOTP = strings.TrimSpace(c.Login.TOTP) != ""
		}
		out = append(out, state.CipherSummary{
			ID:       c.ID,
			Type:     c.Type,
			FolderID: c.FolderID,
			Favorite: c.Favorite,
			Deleted:  deleted,
			Archived: c.ArchivedDate != nil,
			Name:     c.Name,
			Subtitle: sub,
			HasTOTP:  hasTOTP,

			HasPasskey:   c.Login != nil && len(c.Login.Fido2Credentials) > 0,
			RevisionDate: c.RevisionDate,
			Reprompt:     c.Reprompt,
			URIs:         loginURIs(c),

			OrganizationID: c.OrganizationID,
			CollectionIDs:  c.CollectionIDs,
		})
	}
	return out
}

func (m *mockVaultService) GetCipher(id string) (*state.Cipher, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.status != state.StatusUnlocked {
		return nil, state.ErrLocked
	}
	c, ok := m.ciphers[id]
	if !ok {
		return nil, state.ErrCipherNotFound
	}
	cp := *c
	return &cp, nil
}

func (m *mockVaultService) SaveCipher(_ context.Context, c *state.Cipher) (*state.Cipher, error) {
	m.mu.RLock()
	gate := m.saveGate
	m.mu.RUnlock()
	if gate != nil {
		<-gate
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status != state.StatusUnlocked {
		return nil, state.ErrLocked
	}
	cp := *c
	if cp.ID == "" {
		cp.ID = "c-new"
		for i := 2; m.ciphers[cp.ID] != nil; i++ {
			cp.ID = fmt.Sprintf("c-new-%d", i)
		}
		m.order = append(m.order, cp.ID)
		m.creates++
	}
	m.ciphers[cp.ID] = &cp
	if m.localCopyFails {
		out := cp
		return &out, &state.LocalCopyError{Cipher: &out, Err: errors.New("disk full")}
	}
	return &cp, nil
}

func (m *mockVaultService) MoveCiphers(_ context.Context, ids []string, folderID *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range ids {
		if c, ok := m.ciphers[id]; ok {
			c.FolderID = nil
			if folderID != nil {
				f := *folderID
				c.FolderID = &f
			}
		}
	}
	return nil
}

func (m *mockVaultService) SoftDeleteCipher(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.ciphers[id]
	if !ok {
		return state.ErrCipherNotFound
	}
	now := time.Now()
	c.DeletedDate = &now
	return nil
}

func (m *mockVaultService) RestoreCipher(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.ciphers[id]
	if !ok {
		return state.ErrCipherNotFound
	}
	c.DeletedDate = nil
	return nil
}

func (m *mockVaultService) HardDeleteCipher(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.ciphers, id)
	return nil
}

func (m *mockVaultService) Account() state.Account {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, a := range m.accounts {
		if a.ID == m.current {
			return state.Account{ID: a.ID, Email: a.Email}
		}
	}
	return state.Account{ID: "acct-1", Email: "alice@example.com"}
}

func (m *mockVaultService) TrustedServerURL(string) string { return m.trustedServer }

func (m *mockVaultService) AuthAttempt() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.attempt
}

func (m *mockVaultService) RevokeAuthAttempts() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attempt++
	m.revokes++
	if m.status == state.StatusUnlocked {
		m.status = state.StatusLocked
	}
}

func (m *mockVaultService) LocalOnly() bool { return m.localOnly }

func (m *mockVaultService) CredentialsNotSaved() bool { return m.credsUnsaved }

func (m *mockVaultService) BackupData() state.BackupData {
	return state.BackupData{Ciphers: m.AllCiphers(), Folders: m.Folders(), Unreadable: m.unreadable}
}

func (m *mockVaultService) UnreadableItems() []string { return m.unreadable }

type mockSessionKey struct{}

func (m *mockVaultService) SessionContext(parent context.Context) (context.Context, context.CancelFunc, error) {
	m.mu.RLock()
	session := m.session
	m.mu.RUnlock()
	ctx, cancel := context.WithCancel(context.WithValue(parent, mockSessionKey{}, session))
	return ctx, cancel, nil
}

func (m *mockVaultService) CanArchive() bool { return !m.noPremium }

func (m *mockVaultService) ArchiveCipher(ctx context.Context, id string) error {
	m.mu.Lock()
	m.archiveSessions = append(m.archiveSessions, ctx.Value(mockSessionKey{}))
	m.mu.Unlock()
	return m.setArchived(id, true)
}

func (m *mockVaultService) UnarchiveCipher(_ context.Context, id string) error {
	return m.setArchived(id, false)
}

func (m *mockVaultService) setArchived(id string, archive bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.ciphers[id]
	if !ok {
		return state.ErrCipherNotFound
	}
	if archive && m.noPremium {
		return state.ErrPremiumRequired
	}
	if archive {
		now := time.Now()
		c.ArchivedDate = &now
	} else {
		c.ArchivedDate = nil
	}
	return nil
}

func (m *mockVaultService) TrashSelection() state.TrashSelection {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var sel state.TrashSelection
	for id, c := range m.ciphers {
		switch {
		case c.DeletedDate == nil:
		case c.ReadOnly:
			sel.ReadOnly++
		default:
			sel.Items = append(sel.Items, state.TrashItem{ID: id, RevisionDate: c.RevisionDate})
		}
	}
	return sel
}

func (m *mockVaultService) EmptyTrash(_ context.Context, sel state.TrashSelection) (state.TrashResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := state.TrashResult{ReadOnly: sel.ReadOnly}
	for _, it := range sel.Items {
		if c, ok := m.ciphers[it.ID]; !ok || c.DeletedDate == nil {
			res.Skipped++
			continue
		}
		delete(m.ciphers, it.ID)
		res.Deleted++
	}
	return res, nil
}

func (m *mockVaultService) Folders() []state.Folder {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]state.Folder(nil), m.folders...)
}

func (m *mockVaultService) SaveFolder(_ context.Context, f *state.Folder) (*state.Folder, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f.ID == "" {
		f.ID = "f-new"
		m.folders = append(m.folders, *f)
	}
	return f, nil
}

func (m *mockVaultService) Organizations() []state.Organization {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]state.Organization(nil), m.organizations...)
}

func (m *mockVaultService) Collections() []state.Collection {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]state.Collection(nil), m.collections...)
}

func (m *mockVaultService) DeleteFolder(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, f := range m.folders {
		if f.ID == id {
			m.folders = append(m.folders[:i], m.folders[i+1:]...)
			return nil
		}
	}
	return errors.New("not found")
}

func ptr[T any](v T) *T { return &v }

func loginURIs(c *state.Cipher) []string {
	if c.Login == nil {
		return nil
	}
	out := make([]string, 0, len(c.Login.URIs))
	for _, u := range c.Login.URIs {
		out = append(out, u.URI)
	}
	return out
}

func (m *mockVaultService) DownloadAttachment(_ context.Context, cipherID, attachmentID string) ([]byte, string, error) {
	if m.downloadGate != nil {
		<-m.downloadGate
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.ciphers[cipherID]
	if !ok {
		return nil, "", state.ErrCipherNotFound
	}
	for _, a := range c.Attachments {
		if a.ID == attachmentID {
			return []byte("contents of " + a.FileName), a.FileName, nil
		}
	}
	return nil, "", state.ErrAttachmentNotFound
}

func (m *mockVaultService) UploadAttachment(_ context.Context, cipherID, fileName string, plain []byte) (*state.Cipher, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.ciphers[cipherID]
	if !ok {
		return nil, state.ErrCipherNotFound
	}
	c.Attachments = append(slices.Clone(c.Attachments), state.Attachment{ID: "att-" + fileName, FileName: fileName, Size: int64(len(plain))})
	m.uploads++
	cp := *c
	if m.localCopyFails {
		return &cp, &state.LocalCopyError{Cipher: &cp, Err: errors.New("disk full")}
	}
	return &cp, nil
}

func (m *mockVaultService) DeleteAttachment(_ context.Context, cipherID, attachmentID string) (*state.Cipher, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.ciphers[cipherID]
	if !ok {
		return nil, state.ErrCipherNotFound
	}
	c.Attachments = slices.DeleteFunc(slices.Clone(c.Attachments), func(a state.Attachment) bool { return a.ID == attachmentID })
	cp := *c
	return &cp, nil
}

func (m *mockVaultService) AllCiphers() []*state.Cipher {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.status != state.StatusUnlocked {
		return nil
	}
	out := make([]*state.Cipher, 0, len(m.order))
	for _, id := range m.order {
		if c := m.ciphers[id]; c != nil {
			cp := *c
			out = append(out, &cp)
		}
	}
	return out
}
