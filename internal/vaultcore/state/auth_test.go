package state

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/realtime"
	"github.com/oneryx/myvault/internal/vaultcore/store"
)

func newServiceWith(t *testing.T, env *vaultTestEnv, st store.Store, secrets store.SecretStore) *Service {
	t.Helper()
	svc, err := NewService(ServiceConfig{Store: st, Secrets: secrets, AccountID: env.profileID, HTTPClient: env.server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestService_ConcurrentRefreshesUseTheRotatingTokenOnce(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	env.mu.Lock()
	env.rotateRefresh, env.refreshes = true, 0
	env.mu.Unlock()
	svc.mu.Lock()
	svc.accessToken = ""
	svc.mu.Unlock()

	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- svc.forceSync(context.Background())
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil && !errors.Is(err, ErrSyncDeferred) {
			t.Fatalf("sync = %v", err)
		}
	}
	env.mu.Lock()
	defer env.mu.Unlock()
	if env.refreshes != 1 {
		t.Fatalf("refreshes = %d, want one shared refresh", env.refreshes)
	}
}

type failingSecrets struct {
	*memSecretStore
	fail bool
}

func (f *failingSecrets) Set(account, value string) error {
	if f.fail {
		return errors.New("keychain locked")
	}
	return f.memSecretStore.Set(account, value)
}

func TestService_LoginSnapshotIsNeverNewerThanItsData(t *testing.T) {
	env := newVaultTestEnv(t)
	env.mu.Lock()
	env.onSync = func() {
		env.mu.Lock()
		env.revDate = env.revDate.Add(time.Minute)
		c := env.ciphers["c-1"]
		c.Name = mustEncString(t, "Edited elsewhere", env.cipherKey)
		env.ciphers["c-1"] = c
		env.onSync = nil
		env.mu.Unlock()
	}
	env.mu.Unlock()
	svc := loggedInTestService(t, env)
	if err := svc.SyncNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c, _ := svc.GetCipher("c-1"); c.Name != "Edited elsewhere" {
		t.Fatalf("a change made during login was never fetched: %q", c.Name)
	}
}

func TestService_UnlockStartedBeforeALockNeverPublishes(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	svc.Lock()

	gen := svc.attemptGen()
	svc.Lock() // the system sleeps while the unlock is still deriving keys
	if err := svc.unlock(context.Background(), env.userKey, gen); !errors.Is(err, ErrLocked) {
		t.Fatalf("unlock after a lock = %v, want ErrLocked", err)
	}
	if st := svc.Status(); st != StatusLocked {
		t.Fatalf("status = %v, want locked", st)
	}

	gen = svc.attemptGen()
	if err := svc.Logout(context.Background(), newMemSecretStore()); err != nil {
		t.Fatal(err)
	}
	if err := svc.unlock(context.Background(), env.userKey, gen); !errors.Is(err, ErrLocked) && !errors.Is(err, ErrLoggedOut) {
		t.Fatalf("unlock after logout = %v, want it refused", err)
	}
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	if svc.status == StatusUnlocked || svc.snapshot != nil {
		t.Fatal("an unlock finished after logout")
	}
}

func TestService_RealtimeConnectCatchesUpOnMissedChanges(t *testing.T) {
	env := newVaultTestEnv(t)
	rt := &fakeRealtimeClient{events: make(chan realtime.Event), connect: true}
	svc, err := NewService(ServiceConfig{
		Store: store.NewFileStore(t.TempDir()), Secrets: newMemSecretStore(), HTTPClient: env.server.Client(),
		NewRealtimeClient: func(string) (realtime.Client, error) { return rt, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Login(context.Background(), LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password}); err != nil {
		t.Fatal(err)
	}
	// A change lands while the notification connection is down.
	env.mu.Lock()
	env.revDate = env.revDate.Add(time.Minute)
	c := env.ciphers["c-1"]
	c.Name = mustEncString(t, "Changed while offline", env.cipherKey)
	env.ciphers["c-1"] = c
	env.mu.Unlock()

	if err := svc.StartRealtime(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got, _ := svc.GetCipher("c-1"); got != nil && got.Name == "Changed while offline" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("reconnecting did not fetch the change made while disconnected")
		}
		runtime.Gosched()
	}
}

// loginThenReopen signs in with a fresh service, locks, lets edit change
// the stored state, and opens a new service on the same stores.
func loginThenReopen(t *testing.T, env *vaultTestEnv, secrets store.SecretStore, edit func(st store.Store)) *Service {
	t.Helper()
	st := store.NewFileStore(t.TempDir())
	first := newServiceWith(t, env, st, secrets)
	if err := first.Login(context.Background(), LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password}); err != nil {
		t.Fatal(err)
	}
	first.Lock()
	if edit != nil {
		edit(st)
	}
	return newServiceWith(t, env, st, secrets)
}

// assertLocalOnly checks an unlocked vault that is readable but sends
// nothing to the server.
func assertLocalOnly(t *testing.T, env *vaultTestEnv, svc *Service) {
	t.Helper()
	if !svc.LocalOnly() || svc.Status() != StatusUnlocked {
		t.Fatalf("status %v, local only %v; want an unlocked local-only vault", svc.Status(), svc.LocalOnly())
	}
	if c, err := svc.GetCipher("c-1"); err != nil || c.Name != "GitHub" {
		t.Fatalf("vault not readable offline: %+v, %v", c, err)
	}
	env.mu.Lock()
	seen := len(env.authSeen)
	env.mu.Unlock()
	if err := svc.SyncNow(context.Background()); !errors.Is(err, ErrSignInRequired) {
		t.Fatalf("sync = %v, want ErrSignInRequired", err)
	}
	if _, err := svc.SaveCipher(context.Background(), &Cipher{Type: 2, Name: "x", SecureNote: &SecureNote{}}); !errors.Is(err, ErrSignInRequired) {
		t.Fatalf("save = %v, want ErrSignInRequired", err)
	}
	env.mu.Lock()
	defer env.mu.Unlock()
	if len(env.authSeen) != seen {
		t.Fatal("a local-only session sent an authenticated request")
	}
}

func TestService_BoundTokenIsStoredWithItsServer(t *testing.T) {
	env := newVaultTestEnv(t)
	secrets := newMemSecretStore()
	loginThenReopen(t, env, secrets, nil)
	raw, _, _ := secrets.Get(refreshTokenKeyPrefix + env.profileID)
	var bound boundRefreshToken
	if json.Unmarshal([]byte(raw), &bound) != nil || bound.Origin != serverOrigin(env.server.URL) || bound.Token != "ref-1" {
		t.Fatalf("stored refresh token = %q, want it bound to the server", raw)
	}
}

func TestService_UnvalidatedCredentialsUnlockLocalOnly(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, env *vaultTestEnv, secrets *flakySecrets, st store.Store)
	}{
		{"snapshot points at another server", func(t *testing.T, env *vaultTestEnv, _ *flakySecrets, st store.Store) {
			snap, _ := st.LoadSnapshot(env.profileID)
			snap.ServerURL = "https://attacker.example"
			if err := st.SaveSnapshot(snap); err != nil {
				t.Fatal(err)
			}
		}},
		{"token from an older version", func(t *testing.T, env *vaultTestEnv, secrets *flakySecrets, _ store.Store) {
			_ = secrets.memSecretStore.Set(refreshTokenKeyPrefix+env.profileID, "legacy-token")
		}},
		{"key store unavailable", func(_ *testing.T, _ *vaultTestEnv, secrets *flakySecrets, _ store.Store) {
			secrets.getFails = true
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newVaultTestEnv(t)
			secrets := &flakySecrets{memSecretStore: newMemSecretStore()}
			svc := loginThenReopen(t, env, secrets, func(st store.Store) { tc.setup(t, env, secrets, st) })
			if err := svc.UnlockWithPassword(context.Background(), env.password); err != nil {
				t.Fatalf("unlock with the right master password = %v", err)
			}
			assertLocalOnly(t, env, svc)
			if raw, _, _ := secrets.memSecretStore.Get(refreshTokenKeyPrefix + env.profileID); tc.name == "token from an older version" && raw != "legacy-token" {
				t.Fatalf("a legacy token was rewritten from snapshot data: %q", raw)
			}

			// One fresh sign-in replaces it with a token bound to the
			// server the user typed.
			if err := svc.Login(context.Background(), LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password}); err != nil {
				t.Fatal(err)
			}
			if svc.LocalOnly() {
				t.Fatal("still local only after signing in")
			}
		})
	}
}

type flakySecrets struct {
	*memSecretStore
	getFails, setFails bool
	setStarted         chan struct{}
	setGate            chan struct{}
}

func (f *flakySecrets) Get(account string) (string, bool, error) {
	if f.getFails {
		return "", false, errors.New("keychain unavailable")
	}
	return f.memSecretStore.Get(account)
}

func (f *flakySecrets) Set(account, value string) error {
	if f.setStarted != nil {
		close(f.setStarted)
		f.setStarted = nil
		<-f.setGate
	}
	if f.setFails {
		return errors.New("keychain locked")
	}
	return f.memSecretStore.Set(account, value)
}

func TestService_LogoutDuringLoginLeavesNoToken(t *testing.T) {
	env := newVaultTestEnv(t)
	secrets := &flakySecrets{memSecretStore: newMemSecretStore(), setStarted: make(chan struct{}), setGate: make(chan struct{})}
	started := secrets.setStarted
	svc := newServiceWith(t, env, store.NewFileStore(t.TempDir()), secrets)
	loginDone := make(chan error, 1)
	go func() {
		loginDone <- svc.Login(context.Background(), LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password})
	}()
	<-started
	logoutDone := make(chan error, 1)
	go func() { logoutDone <- svc.Logout(context.Background(), newMemSecretStore()) }()
	close(secrets.setGate)
	<-loginDone
	if err := <-logoutDone; err != nil {
		t.Fatal(err)
	}
	if raw, ok, _ := secrets.memSecretStore.Get(refreshTokenKeyPrefix + env.profileID); ok {
		t.Fatalf("a refresh token is on disk after logout: %q", raw)
	}
}

func TestService_RevokedAttemptsNeverPublish(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := newServiceWith(t, env, store.NewFileStore(t.TempDir()), newMemSecretStore())
	attempt := svc.AuthAttempt()
	svc.RevokeAuthAttempts() // the system sleeps while signing in
	err := svc.Login(WithAuthAttempt(context.Background(), attempt), LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password})
	if !errors.Is(err, ErrLocked) || svc.Status() == StatusUnlocked {
		t.Fatalf("login after sleep = %v, status %v", err, svc.Status())
	}

	if err := svc.Login(context.Background(), LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password}); err != nil {
		t.Fatal(err)
	}
	svc.Lock()
	attempt = svc.AuthAttempt() // a biometric prompt opens
	svc.RevokeAuthAttempts()
	if err := svc.UnlockWithUserKey(WithAuthAttempt(context.Background(), attempt), env.userKey); !errors.Is(err, ErrLocked) {
		t.Fatalf("biometric unlock after sleep = %v, want ErrLocked", err)
	}
	if svc.Status() != StatusLocked {
		t.Fatalf("status = %v", svc.Status())
	}

	// An unlock that committed before the UI heard of it is locked again
	// by the revoke the sleep sends.
	if err := svc.UnlockWithPassword(context.Background(), env.password); err != nil {
		t.Fatal(err)
	}
	svc.RevokeAuthAttempts()
	if svc.Status() != StatusLocked {
		t.Fatalf("status after a revoke over a committed unlock = %v, want locked", svc.Status())
	}
}

func TestService_SignInAgainRefusesAnotherAccountBeforeSavingAnything(t *testing.T) {
	env := newVaultTestEnv(t)
	st := store.NewFileStore(t.TempDir())
	secrets := newMemSecretStore()
	svc := newServiceWith(t, env, st, secrets)
	for _, want := range []Account{
		{ID: "someone-else", ServerURL: env.server.URL},
		{ID: env.profileID, ServerURL: "https://other.example"},
	} {
		err := svc.Login(context.Background(), LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password, SameAccount: &want})
		if !errors.Is(err, ErrDifferentAccount) {
			t.Fatalf("login with %+v = %v, want ErrDifferentAccount", want, err)
		}
	}
	if _, err := st.LoadSnapshot(env.profileID); err == nil {
		t.Fatal("a refused sign-in saved a snapshot")
	}
	if _, ok, _ := secrets.Get(refreshTokenKeyPrefix + env.profileID); ok {
		t.Fatal("a refused sign-in saved a refresh token")
	}
	same := Account{ID: env.profileID, ServerURL: env.server.URL + "/"}
	if err := svc.Login(context.Background(), LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password, SameAccount: &same}); err != nil {
		t.Fatalf("the same account = %v", err)
	}
	if a := svc.Account(); a.ID != env.profileID || serverOrigin(svc.TrustedServerURL(a.ID)) != serverOrigin(env.server.URL) {
		t.Fatalf("Account() = %+v, trusted server %q", a, svc.TrustedServerURL(a.ID))
	}
}

func TestService_MalformedServerURLStillOpensLocalOnly(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loginThenReopen(t, env, newMemSecretStore(), func(st store.Store) {
		snap, _ := st.LoadSnapshot(env.profileID)
		snap.ServerURL = "http://[::1"
		_ = st.SaveSnapshot(snap)
	})
	if err := svc.UnlockWithPassword(context.Background(), env.password); err != nil {
		t.Fatalf("unlock with a malformed server address = %v", err)
	}
	if !svc.LocalOnly() {
		t.Fatal("expected a local-only vault")
	}
}

func TestService_RefreshWithoutANewTokenKeepsTheUnsavedOne(t *testing.T) {
	env := newVaultTestEnv(t)
	secrets := &flakySecrets{memSecretStore: newMemSecretStore()}
	svc := newServiceWith(t, env, store.NewFileStore(t.TempDir()), secrets)
	if err := svc.Login(context.Background(), LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password}); err != nil {
		t.Fatal(err)
	}
	env.mu.Lock()
	env.rotateRefresh = true
	env.mu.Unlock()
	secrets.setFails = true
	svc.mu.Lock()
	svc.accessToken = ""
	svc.mu.Unlock()
	if err := svc.forceSync(context.Background()); err != nil {
		t.Fatal(err)
	}
	svc.mu.RLock()
	unsaved := svc.unsavedRefresh
	svc.mu.RUnlock()

	// The server answers the next refresh with an access token only.
	env.mu.Lock()
	env.rotateRefresh, env.noNewRefresh = false, true
	env.mu.Unlock()
	secrets.setFails = false
	svc.mu.Lock()
	svc.accessToken = ""
	svc.mu.Unlock()
	if err := svc.forceSync(context.Background()); err != nil {
		t.Fatal(err)
	}
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	if !svc.credsUnsaved || svc.unsavedRefresh != unsaved || unsaved == "" {
		t.Fatalf("after an access-token-only refresh: warning %v, token kept %v", svc.credsUnsaved, svc.unsavedRefresh == unsaved)
	}
}

func TestService_UnsavedRotatedTokenIsKeptAndFlagged(t *testing.T) {
	env := newVaultTestEnv(t)
	secrets := &flakySecrets{memSecretStore: newMemSecretStore()}
	svc := newServiceWith(t, env, store.NewFileStore(t.TempDir()), secrets)
	if err := svc.Login(context.Background(), LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password}); err != nil {
		t.Fatal(err)
	}
	env.mu.Lock()
	env.rotateRefresh = true
	env.mu.Unlock()
	secrets.setFails = true
	svc.mu.Lock()
	svc.accessToken = ""
	svc.mu.Unlock()

	if err := svc.forceSync(context.Background()); err != nil {
		t.Fatalf("sync after an unsaved refresh = %v", err)
	}
	if !svc.CredentialsNotSaved() {
		t.Fatal("an unsaved sign-in was not reported")
	}
	// It stays reported across later successful requests, and the next
	// refresh uses the token the server issued, not the spent one.
	svc.mu.Lock()
	svc.accessToken = ""
	svc.mu.Unlock()
	if err := svc.forceSync(context.Background()); err != nil || !svc.CredentialsNotSaved() {
		t.Fatalf("second refresh = %v, still reported %v", err, svc.CredentialsNotSaved())
	}
	// Once a save works, the warning goes.
	secrets.setFails = false
	svc.mu.Lock()
	svc.accessToken = ""
	svc.mu.Unlock()
	if err := svc.forceSync(context.Background()); err != nil || svc.CredentialsNotSaved() {
		t.Fatalf("after a saved refresh: %v, still reported %v", err, svc.CredentialsNotSaved())
	}
}

func TestService_SignInAgainNeverSendsToTheSnapshotServer(t *testing.T) {
	env := newVaultTestEnv(t)
	var attackerHits int
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerHits++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer attacker.Close()
	secrets := newMemSecretStore()
	svc := loginThenReopen(t, env, secrets, func(st store.Store) {
		snap, _ := st.LoadSnapshot(env.profileID)
		snap.ServerURL = attacker.URL
		_ = st.SaveSnapshot(snap)
	})
	if err := svc.UnlockWithPassword(context.Background(), env.password); err != nil || !svc.LocalOnly() {
		t.Fatalf("unlock = %v, local only %v", err, svc.LocalOnly())
	}
	acct := svc.Account()
	trusted := svc.TrustedServerURL(acct.ID)
	if serverOrigin(trusted) != serverOrigin(env.server.URL) {
		t.Fatalf("trusted server = %q, want the one signed in to, not the snapshot's", trusted)
	}

	// Sign In Again aimed at the snapshot's server is refused before
	// prelogin; aimed at the trusted one it works.
	bad := Account{ID: acct.ID, ServerURL: attacker.URL}
	if err := svc.Login(context.Background(), LoginRequest{ServerURL: attacker.URL, Email: env.email, MasterPassword: env.password, SameAccount: &bad}); !errors.Is(err, ErrDifferentAccount) {
		t.Fatalf("sign-in at the snapshot server = %v, want ErrDifferentAccount", err)
	}
	good := Account{ID: acct.ID, ServerURL: trusted}
	if err := svc.Login(context.Background(), LoginRequest{ServerURL: trusted, Email: env.email, MasterPassword: env.password, SameAccount: &good}); err != nil {
		t.Fatal(err)
	}
	if attackerHits != 0 {
		t.Fatalf("the snapshot server received %d requests", attackerHits)
	}
}

func TestService_SignInRecordIsKeptApartAndRemovedOnLogout(t *testing.T) {
	env := newVaultTestEnv(t)
	secrets := newMemSecretStore()
	svc := newServiceWith(t, env, store.NewFileStore(t.TempDir()), secrets)
	if err := svc.Login(context.Background(), LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password}); err != nil {
		t.Fatal(err)
	}
	// A token problem does not lose where the account signs in.
	_ = secrets.Delete(refreshTokenKeyPrefix + env.profileID)
	if svc.TrustedServerURL(env.profileID) != env.server.URL {
		t.Fatalf("trusted server = %q", svc.TrustedServerURL(env.profileID))
	}
	if err := svc.Logout(context.Background(), secrets); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := secrets.Get(signInRecordPrefix + env.profileID); ok || svc.TrustedServerURL(env.profileID) != "" {
		t.Fatal("the sign-in record survived logout")
	}
}
