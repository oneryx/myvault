package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestClient_TwoFactorLoginFlow(t *testing.T) {
	var emailReq map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/connect/token":
			_ = r.ParseForm()
			if r.FormValue("twoFactorToken") == "" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Two factor required.",` +
					`"TwoFactorProviders":["0","1",7],` +
					`"TwoFactorProviders2":{"0":null,"1":{"Email":"a***@example.com"},"7":{}}}`))
				return
			}
			if r.FormValue("twoFactorProvider") != "0" || r.FormValue("twoFactorToken") != "123456" || r.FormValue("twoFactorRemember") != "1" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Invalid TOTP code","ErrorModel":{"Message":"Invalid TOTP code"}}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"tok","refresh_token":"ref","Key":"k","TwoFactorToken":"remember-me"}`))
		case "/api/two-factor/send-email-login":
			if r.Method != http.MethodPost || r.Header.Get("Authorization") != "" {
				t.Errorf("send-email-login method=%s auth=%q", r.Method, r.Header.Get("Authorization"))
			}
			_ = json.NewDecoder(r.Body).Decode(&emailReq)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c, err := NewClient(ClientConfig{ServerURL: srv.URL, DeviceID: "dev-1", DeviceType: 7, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	_, err = c.LoginPassword(ctx, "alice@example.com", "hash", nil)
	var tfErr *TwoFactorRequiredError
	if !errors.As(err, &tfErr) || !errors.Is(err, ErrTwoFactorRequired) {
		t.Fatalf("got %v, want TwoFactorRequiredError", err)
	}
	want := []TwoFactorProvider{TwoFactorAuthenticator, TwoFactorEmail, TwoFactorWebAuthn}
	if !slices.Equal(tfErr.Challenge.Providers, want) {
		t.Fatalf("providers = %v, want %v", tfErr.Challenge.Providers, want)
	}
	if hint := tfErr.Challenge.EmailHint(); hint != "a***@example.com" {
		t.Fatalf("email hint = %q", hint)
	}

	_, err = c.LoginPassword(ctx, "alice@example.com", "hash", &TwoFactorLogin{Provider: TwoFactorAuthenticator, Token: "000000", Remember: true})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Message != "Invalid TOTP code" {
		t.Fatalf("wrong code got %v", err)
	}

	tok, err := c.LoginPassword(ctx, "alice@example.com", "hash", &TwoFactorLogin{Provider: TwoFactorAuthenticator, Token: "123 456", Remember: true})
	if err != nil || tok.TwoFactorToken != "remember-me" {
		t.Fatalf("2FA login = (%+v, %v)", tok, err)
	}

	if err := c.SendEmailTwoFactorLogin(ctx, " Alice@Example.com", "hash"); err != nil {
		t.Fatalf("SendEmailTwoFactorLogin: %v", err)
	}
	if emailReq["email"] != "alice@example.com" || emailReq["masterPasswordHash"] != "hash" || emailReq["deviceIdentifier"] != "dev-1" {
		t.Fatalf("send-email-login body = %v", emailReq)
	}
}
