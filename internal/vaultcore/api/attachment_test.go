package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestDownloadAttachmentBytes_AuthOnlySameOrigin(t *testing.T) {
	var mu sync.Mutex
	gotAuth := map[string]string{}
	var cdnURL string
	handler := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			gotAuth[name+r.URL.Path] = r.Header.Get("Authorization")
			mu.Unlock()
			switch r.URL.Path {
			case "/to-cdn":
				http.Redirect(w, r, cdnURL+"/blob", http.StatusFound)
			case "/to-self":
				http.Redirect(w, r, "/blob", http.StatusFound)
			case "/max":
				_, _ = w.Write(make([]byte, MaxAttachmentWireSize))
			case "/big":
				_, _ = w.Write(make([]byte, MaxAttachmentWireSize+1))
			default:
				_, _ = w.Write([]byte("blob"))
			}
		}
	}
	server := httptest.NewServer(handler("server"))
	defer server.Close()
	cdn := httptest.NewServer(handler("cdn"))
	defer cdn.Close()
	cdnURL = cdn.URL

	c, err := NewClient(ClientConfig{ServerURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, u := range []string{"/attachments/a", server.URL + "/to-self", cdn.URL + "/direct", server.URL + "/to-cdn"} {
		if data, err := c.DownloadAttachmentBytes(ctx, "tok", u); err != nil || string(data) != "blob" {
			t.Fatalf("download %s = (%q, %v)", u, data, err)
		}
	}
	want := map[string]string{
		"server/attachments/a": "Bearer tok",
		"server/to-self":       "Bearer tok",
		"server/blob":          "Bearer tok",
		"cdn/direct":           "",
		"server/to-cdn":        "Bearer tok",
		"cdn/blob":             "",
	}
	mu.Lock()
	for k, v := range want {
		if gotAuth[k] != v {
			t.Errorf("Authorization at %s = %q, want %q", k, gotAuth[k], v)
		}
	}
	mu.Unlock()

	if data, err := c.DownloadAttachmentBytes(ctx, "tok", "/max"); err != nil || len(data) != MaxAttachmentWireSize {
		t.Fatalf("max-size encrypted attachment = (%d, %v)", len(data), err)
	}
	if _, err := c.DownloadAttachmentBytes(ctx, "tok", "/big"); !errors.Is(err, ErrAttachmentTooLarge) {
		t.Fatalf("oversized download = %v", err)
	}
	if _, err := c.DownloadAttachmentBytes(ctx, "tok", "file:///etc/passwd"); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("file URL = %v", err)
	}
}
