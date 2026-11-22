package app

import (
	"testing"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

// healthService is the mock vault with a reused, a weak, an unsecured and
// an expired item besides its own.
func healthService(withReused bool) *mockVaultService {
	svc := newMockVaultService(state.StatusUnlocked)
	add := func(c *state.Cipher) {
		svc.ciphers[c.ID] = c
		svc.order = append(svc.order, c.ID)
	}
	if withReused {
		add(&state.Cipher{ID: "c-gitlab", Type: api.CipherTypeLogin, Name: "GitLab", Login: &state.Login{Password: "gh-secret-password"}})
	}
	add(&state.Cipher{ID: "c-router", Type: api.CipherTypeLogin, Name: "Router", Login: &state.Login{Password: "admin", URIs: []state.LoginURI{{URI: "http://router.example.net"}}}})
	add(&state.Cipher{ID: "c-old-card", Type: api.CipherTypeCard, Name: "Old Card", Card: &state.Card{ExpMonth: "1", ExpYear: "2020"}})
	return svc
}

func TestHealthViewCountsAndOpensFlaggedItem(t *testing.T) {
	svc := healthService(true)
	app, model := startApp(t, svc, PlatformHooks{}, 1100, 900)

	app.WaitUntil(2*time.Second, func() bool { return model.Health.Get().TotalIssues() == 5 })
	app.Find("5") // the sidebar's badge
	app.Press("Vault Health")
	app.WaitFor("Checked on this device only. Nothing is sent to a server.", 2*time.Second)
	r := model.Health.Get()
	for cat, want := range map[HealthCategory]int{HealthReused: 2, HealthWeak: 1, HealthCards: 1, HealthUnsecured: 1} {
		if got := healthCount(r, cat); got != want {
			t.Errorf("%s count = %d, want %d", cat, got, want)
		}
	}
	app.Find("Expired 01/2020")
	if app.Contains("gh-secret-password") {
		t.Fatal("health view shows a raw password")
	}

	app.Press("Open Router")
	app.WaitUntil(2*time.Second, func() bool { c := model.ActiveCipher.Get(); return c != nil && c.ID == "c-router" })
	app.WaitFor("Router", 2*time.Second)
	if model.Route.Get() != RouteVault || model.SelectedID.Get() != "c-router" {
		t.Fatalf("route=%v selected=%q", model.Route.Get(), model.SelectedID.Get())
	}

	app.Post(func() {
		svc.ciphers["c-router"].Login.Password = "x7#Kq9!vLm2@Pz4w&Rt8"
		svc.ciphers["c-router"].Login.URIs = nil
		svc.ciphers["c-gitlab"].Login.Password = "Unique-Strong-Pass-123!"
		svc.ciphers["c-old-card"].DeletedDate = &time.Time{}
		model.RefreshVaultData()
		model.Route.Set(RouteHealth)
	})
	app.WaitFor("All clear", 2*time.Second)
	if model.Health.Get().TotalIssues() != 0 || app.Exists("5") {
		t.Fatal("badge shown with no issues")
	}
}

// Two logins for the same site and username show as one duplicate group.
func TestHealthViewListsDuplicateLogins(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	for _, id := range []string{"c-dup-a", "c-dup-b"} {
		svc.ciphers[id] = &state.Cipher{ID: id, Type: api.CipherTypeLogin, Name: "Dup " + id[6:],
			Login: &state.Login{Username: "sam", Password: "Unique-" + id + "-9!x", URIs: []state.LoginURI{{URI: "https://shop.example.org/" + id}}}}
		svc.order = append(svc.order, id)
	}
	app, model := startApp(t, svc, PlatformHooks{}, 1100, 900)
	app.WaitUntil(2*time.Second, func() bool { return len(model.Health.Get().Duplicates) > 0 })
	app.Press("Vault Health")
	app.WaitFor("Duplicate Logins", 2*time.Second)
	app.Find("example.org · sam · 2 items")
	app.Find("Open Dup a")
	app.Find("Open Dup b")
}
