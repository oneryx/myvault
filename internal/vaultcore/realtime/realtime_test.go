package realtime

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/vmihailenco/msgpack/v5"
)

func TestVector10_SignalRMessagePackFraming(t *testing.T) {
	if HandshakeRequest != "{\"protocol\":\"messagepack\",\"version\":1}\x1e" {
		t.Fatalf("unexpected HandshakeRequest: %q", HandshakeRequest)
	}
	if err := ParseHandshakeResponse([]byte("{}\x1e")); err != nil {
		t.Fatalf("ParseHandshakeResponse valid failed: %v", err)
	}
	if err := ParseHandshakeResponse([]byte("{\"error\":\"bad protocol\"}\x1e")); !errors.Is(err, ErrHandshakeFailed) {
		t.Fatalf("ParseHandshakeResponse error = %v, want ErrHandshakeFailed", err)
	}

	pingFrame := EncodePing()
	if !bytes.Equal(pingFrame, []byte{0x02, 0x91, 0x06}) {
		t.Fatalf("EncodePing = %x, want 029106", pingFrame)
	}

	invPayload, err := msgpack.Marshal([]any{
		1,
		map[string]any{},
		nil,
		"ReceiveMessage",
		[]any{
			map[string]any{
				"ContextId": "dev-1",
				"Type":      0,
				"Payload":   map[string]any{"Id": "cipher-1"},
			},
		},
	})
	if err != nil {
		t.Fatalf("msgpack.Marshal: %v", err)
	}
	invFrame := EncodeFrame(invPayload)

	combined := append(append([]byte{}, pingFrame...), invFrame...)
	frames, err := DecodeFrames(combined)
	if err != nil {
		t.Fatalf("DecodeFrames: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("decoded %d frames, want 2", len(frames))
	}

	msgType, ev, err := DecodeMessage(frames[0])
	if err != nil || msgType != MsgPing || ev != nil {
		t.Fatalf("frame[0] = (%d, %+v, %v), want Ping", msgType, ev, err)
	}

	msgType, ev, err = DecodeMessage(frames[1])
	if err != nil || msgType != MsgInvocation || ev == nil {
		t.Fatalf("frame[1] = (%d, %+v, %v), want Invocation event", msgType, ev, err)
	}
	if ev.Type != SyncCipherUpdate || ev.ContextID != "dev-1" || ev.ItemID != "cipher-1" {
		t.Fatalf("event = %+v, want SyncCipherUpdate dev-1 cipher-1", ev)
	}
}

func TestWSClient_HandshakePingNotificationAndShutdown(t *testing.T) {
	pingAcked := make(chan struct{}, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/notifications/hub" || r.URL.Query().Get("access_token") != "jwt-123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")

		ctx := r.Context()
		mt, hs, err := conn.Read(ctx)
		if err != nil || mt != websocket.MessageText || string(hs) != HandshakeRequest {
			return
		}
		if err := conn.Write(ctx, websocket.MessageText, []byte("{}\x1e")); err != nil {
			return
		}

		// Send Ping followed by ReceiveMessage(SyncCipherUpdate) + ReceiveMessage(LogOut) in one binary frame.
		inv1, _ := msgpack.Marshal([]any{1, map[string]any{}, nil, "ReceiveMessage", []any{
			map[string]any{"ContextId": "other-dev", "Type": int(SyncCipherUpdate), "Payload": map[string]any{"Id": "c-42"}},
		}})
		inv2, _ := msgpack.Marshal([]any{1, map[string]any{}, nil, "ReceiveMessage", []any{
			map[string]any{"ContextId": nil, "Type": int(LogOut), "Payload": map[string]any{}},
		}})
		batch := append(EncodePing(), EncodeFrame(inv1)...)
		batch = append(batch, EncodeFrame(inv2)...)
		if err := conn.Write(ctx, websocket.MessageBinary, batch); err != nil {
			return
		}

		// Expect Ping reply from client.
		mt, reply, err := conn.Read(ctx)
		if err == nil && mt == websocket.MessageBinary && bytes.Equal(reply, EncodePing()) {
			pingAcked <- struct{}{}
		}
		<-ctx.Done()
	}))
	defer srv.Close()

	client, err := NewClient(Config{
		ServerURL:      srv.URL,
		HTTPClient:     srv.Client(),
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := make(chan Event, 4)
	done := make(chan error, 1)
	go func() {
		done <- client.Run(ctx, &testTokens{tokens: []string{"jwt-123"}}, nil, func(ev Event) {
			events <- ev
		})
	}()

	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()

	var got []Event
	for len(got) < 2 {
		select {
		case ev := <-events:
			got = append(got, ev)
		case <-timeout.C:
			t.Fatalf("timed out waiting for events, got %d", len(got))
		}
	}
	if got[0] != (Event{Type: SyncCipherUpdate, ContextID: "other-dev", ItemID: "c-42"}) {
		t.Errorf("event[0] = %+v", got[0])
	}
	if got[1] != (Event{Type: LogOut}) {
		t.Errorf("event[1] = %+v", got[1])
	}

	select {
	case <-pingAcked:
	case <-timeout.C:
		t.Fatalf("timed out waiting for client Ping reply")
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
	case <-timeout.C:
		t.Fatalf("timed out waiting for clean shutdown")
	}
}

type testTokens struct {
	mu       sync.Mutex
	tokens   []string
	rejected []string
}

func (t *testTokens) Token() (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.tokens[0], nil
}

func (t *testTokens) Rejected(token string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rejected = append(t.rejected, token)
	if len(t.tokens) > 1 && t.tokens[0] == token {
		t.tokens = t.tokens[1:]
	}
}

func TestWSClient_RefreshesARejectedTokenAndReportsEachConnect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("access_token") != "fresh" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")
		if _, _, err := conn.Read(r.Context()); err != nil {
			return
		}
		_ = conn.Write(r.Context(), websocket.MessageText, []byte("{}\x1e"))
		<-r.Context().Done()
	}))
	defer srv.Close()
	client, err := NewClient(Config{ServerURL: srv.URL, HTTPClient: srv.Client(), InitialBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tokens := &testTokens{tokens: []string{"expired", "fresh"}}
	connected := make(chan struct{}, 1)
	go func() { _ = client.Run(ctx, tokens, func() { connected <- struct{}{} }, nil) }()
	select {
	case <-connected:
	case <-time.After(5 * time.Second):
		t.Fatal("never connected with the refreshed token")
	}
	tokens.mu.Lock()
	defer tokens.mu.Unlock()
	if len(tokens.rejected) == 0 || tokens.rejected[0] != "expired" {
		t.Fatalf("rejected = %v, want the expired token reported", tokens.rejected)
	}
}
