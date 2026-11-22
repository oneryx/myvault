package health

import (
	"testing"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

func login(id, password string, uris ...string) *state.Cipher {
	l := &state.Login{Username: id + "@example.com", Password: password}
	for _, u := range uris {
		l.URIs = append(l.URIs, state.LoginURI{URI: u})
	}
	return &state.Cipher{ID: id, Name: id, Type: api.CipherTypeLogin, Login: l}
}

func card(id, month, year string) *state.Cipher {
	return &state.Cipher{ID: id, Name: id, Type: api.CipherTypeCard, Card: &state.Card{Brand: "Visa", ExpMonth: month, ExpYear: year}}
}

func ids(items []Issue) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.CipherID
	}
	return out
}

func TestWeakReason(t *testing.T) {
	weak := map[string]string{
		"P@ssw0rd":           "Common password",
		"Summer2024!":        "Common password",
		"Xk9#mQ":             "Shorter than 10 characters",
		"abcdefghij1":        "Mostly a sequence or repeated characters",
		"aaaaaaaaaaaaaa":     "Mostly a sequence or repeated characters",
		"9182736450":         "Uses only one type of character",
		"kitchenwindow":      "Uses only one type of character",
		"abababababababab12": "Easy to guess",
	}
	for pw, want := range weak {
		if got := WeakReason(pw); got != want {
			t.Errorf("WeakReason(%q) = %q, want %q", pw, got, want)
		}
	}
	for _, pw := range []string{"x7#Kq9!vLm2@Pz4w&Rt8", "Tr0ub4dor&3x", "correct horse battery staple", "lantern-orbit-meadow-42"} {
		if got := WeakReason(pw); got != "" {
			t.Errorf("WeakReason(%q) = %q, want strong", pw, got)
		}
	}
}

func TestAnalyze(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	deleted := now.Add(-time.Hour)
	const shared = "Shared-Secret-Value-99"

	trashed := login("trashed", shared)
	trashed.DeletedDate = &deleted
	hidden := login("hidden", "password")
	hidden.HidePassword = true

	report := Analyze([]*state.Cipher{
		login("a", shared, "https://a.example.com"),
		login("b", shared, "http://b.example.com/login"),
		login("c", shared),
		login("d", "Unique-Strong-Pass-123!"),
		login("e", "qwerty"),
		login("local", "Local-Dev-Strong-1!", "http://localhost:8080", "http://127.0.0.1", "http://[::1]:3000", "http://printer.local"),
		trashed,
		hidden,
		card("expired", "04", "2026"),
		card("soon", "6", "26"),
		card("valid", "12", "2027"),
		card("nodate", "", ""),
	}, now)

	if len(report.Reused) != 1 || report.Reused[0].Count != 3 || len(report.Reused[0].Items) != 3 || report.Reused[0].Items[0].Detail != "Used in 3 items" {
		t.Fatalf("Reused = %+v", report.Reused)
	}
	for _, it := range report.Reused[0].Items {
		if it.Detail == shared || it.Subtitle == shared {
			t.Fatalf("report leaks the password: %+v", it)
		}
	}
	if got := ids(report.Weak); len(got) != 1 || got[0] != "e" {
		t.Fatalf("Weak = %v", got)
	}
	if got := ids(report.Unsecured); len(got) != 1 || got[0] != "b" || report.Unsecured[0].Detail != "http://b.example.com/login" {
		t.Fatalf("Unsecured = %+v", report.Unsecured)
	}
	if len(report.Cards) != 2 || report.Cards[0].CipherID != "expired" || !report.Cards[0].Expired || report.Cards[0].Detail != "Expired 04/2026" ||
		report.Cards[1].CipherID != "soon" || report.Cards[1].Expired || report.Cards[1].Detail != "Expires 06/2026" {
		t.Fatalf("Cards = %+v", report.Cards)
	}
	if report.TotalIssues() != 3+1+1+2 {
		t.Fatalf("TotalIssues = %d", report.TotalIssues())
	}
	if (Report{}).TotalIssues() != 0 {
		t.Fatal("empty report has issues")
	}
}
