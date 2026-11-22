package state

import (
	"context"
	"errors"

	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/crypto"
	"github.com/oneryx/myvault/internal/vaultcore/store"
)

// op is one network operation bound to the session that started it. It keeps
// that session's client, account and keys, so a lock, logout or account
// switch in the meantime can never mix credentials or state across sessions.
type op struct {
	s         *Service
	gen       uint64
	ctx       context.Context
	release   context.CancelFunc
	client    *api.Client
	accountID string
	snap      *store.Snapshot
	seq       uint64
	userKey   *crypto.SymmetricKey
}

// startSessionLocked invalidates the previous session and begins a new one.
// The caller holds s.mu.
func (s *Service) startSessionLocked() {
	s.endSessionLocked()
	s.sessionCtx, s.sessionCancel = context.WithCancel(context.Background())
}

// endSessionLocked invalidates the current session: in-flight operations are
// cancelled and can no longer commit. The caller holds s.mu.
func (s *Service) endSessionLocked() {
	s.sessionGen++
	if s.sessionCancel != nil {
		s.sessionCancel()
	}
	s.sessionCtx, s.sessionCancel = nil, nil
	s.accessToken = ""
	s.unsavedRefresh = ""
	s.credsUnsaved = false
}

type sessionGenKey struct{}

// SessionContext returns a context bound to the current session: it ends
// with the session, and an operation started with it under a later
// session fails with ErrLocked. A batch of changes uses it so that a lock,
// logout or account switch stops the batch instead of continuing in the
// next session.
func (s *Service) SessionContext(parent context.Context) (context.Context, context.CancelFunc, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.status != StatusUnlocked || s.sessionCtx == nil {
		return nil, nil, ErrLocked
	}
	ctx, cancel := context.WithCancel(context.WithValue(s.sessionCtx, sessionGenKey{}, s.sessionGen))
	stop := context.AfterFunc(parent, cancel)
	return ctx, func() { stop(); cancel() }, nil
}

func (s *Service) beginOp(ctx context.Context) (*op, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.status != StatusUnlocked || s.userKey == nil || s.sessionCtx == nil {
		return nil, ErrLocked
	}
	if s.localOnly {
		return nil, ErrSignInRequired
	}
	if gen, ok := ctx.Value(sessionGenKey{}).(uint64); ok && (gen != s.sessionGen || ctx.Err() != nil) {
		return nil, ErrLocked
	}
	if s.apiClient == nil || s.snapshot == nil {
		return nil, ErrLoggedOut
	}
	raw := s.userKey.Bytes()
	keyCopy, err := crypto.SymmetricKeyFromBytes(raw[:])
	crypto.ZeroBytes(raw[:])
	if err != nil {
		return nil, err
	}
	opCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.sessionCtx, cancel)
	snapCopy := *s.snapshot
	return &op{
		s:         s,
		gen:       s.sessionGen,
		ctx:       opCtx,
		release:   func() { stop(); cancel() },
		client:    s.apiClient,
		accountID: s.accountID,
		snap:      &snapCopy,
		seq:       s.snapSeq,
		userKey:   keyCopy,
	}, nil
}

func (o *op) end() {
	o.userKey.Zero()
	o.release()
}

// currentLocked reports whether o's session is still the active, unlocked
// one. The caller holds s.mu.
func (o *op) currentLocked() bool {
	return o.s.sessionGen == o.gen && o.s.status == StatusUnlocked
}

func (o *op) current() bool {
	o.s.mu.RLock()
	defer o.s.mu.RUnlock()
	return o.currentLocked()
}

func (o *op) accessToken() (string, error) {
	o.s.mu.RLock()
	tok, ok := o.s.accessToken, o.currentLocked()
	o.s.mu.RUnlock()
	if !ok {
		return "", ErrLocked
	}
	if tok != "" {
		return tok, nil
	}
	return o.refreshAfter(o.ctx, "")
}

// refreshAfter gets a new access token after stale was rejected (or none
// was held). Refreshes run one at a time; one that finds a newer token
// than stale, from a refresh that finished meanwhile, uses it.
func (o *op) refreshAfter(ctx context.Context, stale string) (string, error) {
	o.s.refreshMu.Lock()
	defer o.s.refreshMu.Unlock()
	o.s.mu.RLock()
	cur, ok := o.s.accessToken, o.currentLocked()
	o.s.mu.RUnlock()
	if !ok {
		return "", ErrLocked
	}
	if cur != "" && cur != stale {
		return cur, nil
	}
	refreshTok, err := o.s.loadRefreshToken(o.accountID, o.snap.ServerURL)
	if err != nil {
		return "", err
	}
	resp, err := o.client.RefreshToken(ctx, refreshTok)
	if err != nil {
		return "", err
	}

	// Keychain writes can be slow or interactive, so they run outside s.mu.
	// secretMu orders them with logout, which advances the session first.
	var saveErr error
	if resp.RefreshToken != "" {
		o.s.secretMu.Lock()
		if !o.current() {
			o.s.secretMu.Unlock()
			return "", ErrLocked
		}
		saveErr = o.s.saveRefreshToken(o.accountID, o.snap.ServerURL, resp.RefreshToken)
		o.s.secretMu.Unlock()
	}

	o.s.mu.Lock()
	defer o.s.mu.Unlock()
	if !o.currentLocked() {
		return "", ErrLocked
	}
	o.s.accessToken = resp.AccessToken
	// Only a new refresh token changes what is saved. A refresh that
	// issued none leaves an unsaved token, and its warning, as they were.
	if resp.RefreshToken != "" {
		o.s.unsavedRefresh = ""
		o.s.credsUnsaved = saveErr != nil
		if saveErr != nil {
			// The request goes on with the new token; the session remembers
			// that the next unlock needs a fresh sign-in, for the UI to show.
			o.s.unsavedRefresh = resp.RefreshToken
			go o.s.notifyUpdated()
		}
	}
	return resp.AccessToken, nil
}

func withAuth[T any](o *op, fn func(ctx context.Context, token string) (T, error)) (T, error) {
	tok, err := o.accessToken()
	if err != nil {
		var zero T
		return zero, err
	}
	refresh := func(ctx context.Context) (string, error) { return o.refreshAfter(ctx, tok) }
	return api.DoWithRefresh(o.ctx, tok, refresh, func(t string) (T, error) { return fn(o.ctx, t) })
}

// itemKey returns a copy of the key that encrypts items owned by orgID, or
// of the user key for personal items.
func (o *op) itemKey(orgID *string) (*crypto.SymmetricKey, error) {
	var raw [64]byte
	defer crypto.ZeroBytes(raw[:])
	if orgID == nil || *orgID == "" {
		raw = o.userKey.Bytes()
		return crypto.SymmetricKeyFromBytes(raw[:])
	}
	o.s.mu.RLock()
	k := o.s.orgKeys[*orgID]
	ok := o.currentLocked()
	if k != nil && ok {
		raw = k.Bytes()
	}
	o.s.mu.RUnlock()
	if !ok {
		return nil, ErrLocked
	}
	if k == nil {
		return nil, ErrOrganizationKeyMissing
	}
	return crypto.SymmetricKeyFromBytes(raw[:])
}

// editableCipher returns a copy of the cipher with id after checking that the
// organization lets the user change it.
func (o *op) editableCipher(id string) (*Cipher, error) {
	o.s.mu.RLock()
	defer o.s.mu.RUnlock()
	if !o.currentLocked() {
		return nil, ErrLocked
	}
	c, ok := o.s.ciphers[id]
	if !ok {
		return nil, ErrCipherNotFound
	}
	if o.s.effectiveReadOnlyLocked(c) {
		return nil, ErrReadOnlyCipher
	}
	return cloneCipher(c), nil
}

// effectiveReadOnlyLocked reports whether c is read-only for the item itself
// or through every known collection it belongs to. The caller holds s.mu.
func (s *Service) effectiveReadOnlyLocked(c *Cipher) bool {
	return c.ReadOnly || s.allCollectionsLocked(c, func(col Collection) bool { return col.ReadOnly })
}

// effectiveHidePasswordLocked is effectiveReadOnlyLocked for hidePasswords.
func (s *Service) effectiveHidePasswordLocked(c *Cipher) bool {
	return c.HidePassword || s.allCollectionsLocked(c, func(col Collection) bool { return col.HidePasswords })
}

func (s *Service) allCollectionsLocked(c *Cipher, pred func(Collection) bool) bool {
	known := 0
	for _, id := range c.CollectionIDs {
		col, ok := s.collections[id]
		if !ok {
			continue
		}
		if !pred(col) {
			return false
		}
		known++
	}
	return known > 0
}

// serverUserID is the user ID a cipher write names as its owner
// (encryptedFor), which the server refuses unless it is the signed-in
// user's. It comes from the last sync's profile; without one a sync is
// tried, and if the server still sends none, nothing is written.
func (o *op) serverUserID() (string, error) {
	o.s.mu.RLock()
	id := o.s.userID
	o.s.mu.RUnlock()
	if id != "" {
		return id, nil
	}
	if err := o.s.sync(o.ctx, true); err != nil && !errors.Is(err, ErrSyncDeferred) {
		return "", err
	}
	o.s.mu.RLock()
	id = o.s.userID
	o.s.mu.RUnlock()
	if id == "" {
		return "", ErrAccountIDUnknown
	}
	return id, nil
}
