package app

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/state"
)

var testPNG = []byte("\x89PNG\r\n\x1a\nfake-icon")

func TestIconDomain(t *testing.T) {
	cases := map[string]string{
		"https://GitHub.com/login":                "github.com",
		"http://user:pw@Vault.Example.com:8443/x": "vault.example.com",
		"accounts.google.com/signin":              "accounts.google.com",
		"androidapp://com.example.app":            "",
		"ftp://files.example.com":                 "",
		"https://localhost":                       "",
		"https://192.168.1.10/admin":              "",
		"https://../etc/passwd":                   "",
		"https://exa_mple.com":                    "",
		"https://-bad.example.com":                "",
		"":                                        "",
	}
	for in, want := range cases {
		if got := iconDomain(in); got != want {
			t.Errorf("iconDomain(%q) = %q, want %q", in, got, want)
		}
	}
	if got := IconDomain([]string{"androidapp://x", "", "https://linear.app/team"}); got != "linear.app" {
		t.Errorf("IconDomain picked %q, want linear.app", got)
	}
}

type iconServer struct {
	*httptest.Server
	hits atomic.Int32
}

func newIconServer(t *testing.T) *iconServer {
	s := &iconServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		switch r.URL.Path {
		case "/icons/github.com/icon.png":
			_, _ = w.Write(testPNG)
		case "/icons/html.example.com/icon.png":
			_, _ = w.Write([]byte("<html>nope</html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func waitLoaded(t *testing.T, ch <-chan string, want string) {
	t.Helper()
	select {
	case got := <-ch:
		if got != want {
			t.Fatalf("loaded %q, want %q", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %q", want)
	}
}

func waitHits(t *testing.T, srv *iconServer, want int32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for srv.hits.Load() < want && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	if got := srv.hits.Load(); got != want {
		t.Fatalf("server hits = %d, want %d", got, want)
	}
}

func TestFaviconStoreCachesDedupsAndClears(t *testing.T) {
	srv := newIconServer(t)
	dir := filepath.Join(t.TempDir(), "icons")
	loaded := make(chan string, 8)
	store := NewFaviconStore(FaviconStoreConfig{CacheDir: dir, HTTPClient: srv.Client()})
	store.SetOnLoaded(func(d string) { loaded <- d })
	store.SetAccount("acct-1")

	if store.Lookup(srv.URL, "github.com") != nil || store.Lookup(srv.URL, "github.com") != nil {
		t.Fatal("first lookups should miss")
	}
	waitLoaded(t, loaded, "github.com")
	if got := store.Lookup(srv.URL, "github.com"); !bytes.Equal(got, testPNG) {
		t.Fatalf("memory hit = %q", got)
	}
	if disk, err := os.ReadFile(store.diskPath("github.com")); err != nil || !bytes.Equal(disk, testPNG) {
		t.Fatalf("disk cache = %q, %v", disk, err)
	}
	_ = filepath.WalkDir(dir, func(p string, _ os.DirEntry, _ error) error {
		if strings.Contains(p, "github") {
			t.Fatalf("the cache names a vault domain: %s", p)
		}
		return nil
	})

	for range 3 {
		store.Lookup(srv.URL, "missing.example.com")
		store.Lookup(srv.URL, "html.example.com")
	}
	waitHits(t, srv, 3)
	store.Lookup(srv.URL, "missing.example.com")
	store.Lookup(srv.URL, "html.example.com")
	waitHits(t, srv, 3)

	fresh := NewFaviconStore(FaviconStoreConfig{CacheDir: dir, HTTPClient: srv.Client()})
	fresh.SetAccount("acct-1")
	freshLoaded := make(chan string, 1)
	fresh.SetOnLoaded(func(d string) { freshLoaded <- d })
	fresh.Lookup(srv.URL, "github.com")
	waitLoaded(t, freshLoaded, "github.com")
	if srv.hits.Load() != 3 {
		t.Fatal("disk hit still fetched from the server")
	}

	if err := store.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("cache dir after Clear: %v", err)
	}
	if store.Lookup(srv.URL, "github.com") != nil {
		t.Fatal("Clear kept the memory entry")
	}
	waitLoaded(t, loaded, "github.com")
	waitHits(t, srv, 4)

	store.SetEnabled(false)
	store.ResetMemory()
	if store.Lookup(srv.URL, "github.com") != nil {
		t.Fatal("disabled store returned an icon")
	}
	waitHits(t, srv, 4)
}

func TestShowFaviconsToggleGatesFetches(t *testing.T) {
	srv := newIconServer(t)
	svc := newMockVaultService(state.StatusUnlocked)
	favicons := NewFaviconStore(FaviconStoreConfig{HTTPClient: srv.Client()})
	app := newTestApp(t, svc, PlatformHooks{Favicons: favicons}, 980, 640, func(m *AppModel) {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs {
			p.ServerURL = srv.URL
			return p
		})
		m.SetShowFavicons(false)
		m.MainWinVisible.Set(true)
		m.RefreshVaultData()
	})
	model := app.m

	app.WaitFor("GitHub", 2*time.Second)
	app.Settle()
	if got := srv.hits.Load(); got != 0 {
		t.Fatalf("hits with icons off = %d, want 0", got)
	}

	app.Post(func() { model.SetShowFavicons(true) })
	app.WaitUntil(2*time.Second, func() bool { return srv.hits.Load() == 1 })
	app.WaitUntil(2*time.Second, func() bool { return favicons.Lookup(srv.URL, "github.com") != nil })
}

func TestFaviconFetchedBeforeClearIsNeverWritten(t *testing.T) {
	dir := t.TempDir()
	s := NewFaviconStore(FaviconStoreConfig{CacheDir: dir})
	s.SetAccount("acct-1")
	path := s.diskPath("github.com")
	job := faviconJob{domain: "github.com", generation: 0}
	s.mu.Lock()
	job.generation = s.generation
	s.mu.Unlock()
	if err := s.ClearAccount("acct-1"); err != nil {
		t.Fatal(err)
	}
	s.writeIfCurrent(job, path, testPNG)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("an icon fetched before Clear was written after it: %v", err)
	}
}

func TestLogoutRemovesTheAccountIconCache(t *testing.T) {
	srv := newIconServer(t)
	dir := t.TempDir()
	store := NewFaviconStore(FaviconStoreConfig{CacheDir: dir, HTTPClient: srv.Client()})
	loaded := make(chan string, 1)
	store.SetOnLoaded(func(d string) { loaded <- d })
	store.SetAccount("acct-1")
	store.Lookup(srv.URL, "github.com")
	waitLoaded(t, loaded, "github.com")
	acct := store.accountDir("acct-1")
	if _, err := os.Stat(acct); err != nil {
		t.Fatal(err)
	}
	if err := store.ClearAccount("acct-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(acct); !os.IsNotExist(err) {
		t.Fatalf("account icon cache after logout: %v", err)
	}
}

func TestLegacyIconFilesGoWhenTheCacheOpensAndOnLogout(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "bank.example.com.png")
	if err := os.WriteFile(legacy, testPNG, 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewFaviconStore(FaviconStoreConfig{CacheDir: dir})
	s.SetEnabled(false)
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("a legacy icon named after a vault domain survived opening the cache: %v", err)
	}
	if err := os.WriteFile(legacy, testPNG, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearAccount(""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("a legacy icon survived logout: %v", err)
	}
}

func TestOfflineIconsNeverFetch(t *testing.T) {
	srv := newIconServer(t)
	store := NewFaviconStore(FaviconStoreConfig{CacheDir: t.TempDir(), HTTPClient: srv.Client()})
	store.SetAccount("acct-1")
	store.SetOffline(true)
	store.Lookup(srv.URL, "github.com")
	deadline := time.Now().Add(2 * time.Second)
	for {
		store.mu.Lock()
		_, miss := store.failed["github.com"]
		store.mu.Unlock()
		if miss {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the offline lookup never finished")
		}
		runtime.Gosched()
	}
	if srv.hits.Load() != 0 {
		t.Fatalf("a local-only vault fetched %d icons", srv.hits.Load())
	}
}
