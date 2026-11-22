package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// Every API request names the client, its device type and the Bitwarden
// release it follows: Vaultwarden sends SSH keys only to clients that state
// 2024.12.0 or later, and newer servers refuse logins without it.
func TestEveryAPIRequestCarriesClientHeaders(t *testing.T) {
	var mu sync.Mutex
	type request struct {
		name   string
		header http.Header
	}
	var seen []request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, request{r.Method + " " + r.URL.Path, r.Header.Clone()})
		mu.Unlock()
		switch r.URL.Path {
		case "/identity/accounts/prelogin":
			_, _ = w.Write([]byte(`{"kdf":0,"kdfIterations":600000}`))
		case "/api/accounts/revision-date":
			_, _ = w.Write([]byte(`1700000000000`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	client, err := NewClient(ClientConfig{ServerURL: srv.URL, DeviceType: 7})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, _ = client.Prelogin(ctx, "a@example.com")
	_, _ = client.LoginPassword(ctx, "a@example.com", "hash", nil)
	_, _ = client.RefreshToken(ctx, "refresh")
	_ = client.SendEmailTwoFactorLogin(ctx, "a@example.com", "hash")
	_, _ = client.RevisionDate(ctx, "tok")
	_, _, _ = client.Sync(ctx, "tok")
	_, _ = client.GetCipher(ctx, "tok", "c")
	_, _ = client.UpdateCipher(ctx, "tok", "c", &CipherPayload{})
	if len(seen) != 8 {
		t.Fatalf("%d requests reached the server, want 8", len(seen))
	}
	for _, r := range seen {
		h := r.header
		if h.Get("Bitwarden-Client-Version") != ClientVersion || h.Get("Bitwarden-Client-Name") != "desktop" || h.Get("Device-Type") != "7" {
			t.Errorf("%s: client headers = %q %q %q", r.name, h.Get("Bitwarden-Client-Name"), h.Get("Bitwarden-Client-Version"), h.Get("Device-Type"))
		}
	}
}
