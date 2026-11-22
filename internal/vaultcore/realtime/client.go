package realtime

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
)

const (
	defaultInitialBackoff = time.Second
	defaultMaxBackoff     = 60 * time.Second
)

// Tokens supplies access tokens. Rejected reports one the server refused,
// so the next Token call gets a fresh one instead of retrying it.
type Tokens interface {
	Token() (string, error)
	Rejected(token string)
}

// Client keeps a notification connection open. onConnect runs after each
// handshake, the first and every reconnect, so the caller can catch up on
// changes it missed while disconnected.
type Client interface {
	Run(ctx context.Context, tokens Tokens, onConnect func(), onEvent func(Event)) error
}

type Config struct {
	ServerURL      string
	HTTPClient     *http.Client
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
}

type WSClient struct {
	hubBaseURL     string
	httpClient     *http.Client
	initialBackoff time.Duration
	maxBackoff     time.Duration
}

func NewClient(cfg Config) (*WSClient, error) {
	raw := strings.TrimRight(strings.TrimSpace(cfg.ServerURL), "/")
	if raw == "" {
		return nil, errors.New("realtime: ServerURL is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("realtime: invalid ServerURL %q", cfg.ServerURL)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	case "wss", "ws":
	default:
		return nil, fmt.Errorf("realtime: unsupported URL scheme %q", u.Scheme)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/notifications/hub"

	initial := cfg.InitialBackoff
	if initial <= 0 {
		initial = defaultInitialBackoff
	}
	maxBackoff := cfg.MaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = defaultMaxBackoff
	}
	if maxBackoff < initial {
		maxBackoff = initial
	}

	return &WSClient{
		hubBaseURL:     u.String(),
		httpClient:     cfg.HTTPClient,
		initialBackoff: initial,
		maxBackoff:     maxBackoff,
	}, nil
}

func (c *WSClient) Run(ctx context.Context, tokens Tokens, onConnect func(), onEvent func(Event)) error {
	if tokens == nil {
		return errors.New("realtime: token source is required")
	}

	backoff := c.initialBackoff
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		connected, err := c.runOnce(ctx, tokens, onConnect, onEvent)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if connected {
			backoff = c.initialBackoff
		}
		if err != nil {
			if err := sleepWithJitter(ctx, backoff); err != nil {
				return err
			}
			backoff = min(backoff*2, c.maxBackoff)
		}
	}
}

func (c *WSClient) runOnce(ctx context.Context, tokens Tokens, onConnect func(), onEvent func(Event)) (bool, error) {
	token, err := tokens.Token()
	if err != nil {
		return false, err
	}

	u, err := url.Parse(c.hubBaseURL)
	if err != nil {
		return false, err
	}
	q := u.Query()
	q.Set("access_token", token)
	u.RawQuery = q.Encode()

	conn, resp, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{
		HTTPClient: c.httpClient,
	})
	if err != nil {
		if resp != nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
			tokens.Rejected(token)
		}
		return false, err
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	if err := conn.Write(ctx, websocket.MessageText, []byte(HandshakeRequest)); err != nil {
		return false, err
	}
	_, hsResp, err := conn.Read(ctx)
	if err != nil {
		return false, err
	}
	if err := ParseHandshakeResponse(hsResp); err != nil {
		return false, err
	}
	if onConnect != nil {
		onConnect()
	}

	for {
		msgType, data, err := conn.Read(ctx)
		if err != nil {
			return true, err
		}
		if msgType != websocket.MessageBinary {
			continue
		}

		frames, err := DecodeFrames(data)
		if err != nil {
			return true, err
		}
		for _, frame := range frames {
			signalType, ev, err := DecodeMessage(frame)
			if err != nil {
				return true, err
			}
			switch signalType {
			case MsgPing:
				if err := conn.Write(ctx, websocket.MessageBinary, EncodePing()); err != nil {
					return true, err
				}
			case MsgClose:
				return true, ErrConnectionClosed
			case MsgInvocation:
				if ev != nil && onEvent != nil {
					onEvent(*ev)
				}
			}
		}
	}
}

func sleepWithJitter(ctx context.Context, base time.Duration) error {
	jitter := time.Duration(rand.Int64N(int64(base/4 + 1)))
	timer := time.NewTimer(base + jitter)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
