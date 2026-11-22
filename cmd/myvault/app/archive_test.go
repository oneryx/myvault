package app

import (
	"testing"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

func TestArchiveAndUnarchiveFromTheDetailView(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers["c-mine"] = &state.Cipher{ID: "c-mine", Type: api.CipherTypeLogin, Name: "Mine", Login: &state.Login{Username: "b", Password: "p"}}
	svc.order = append(svc.order, "c-mine")
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})

	app.Post(func() { m.SelectCipher(root, "c-mine") })
	app.WaitFor("Clone item", 2*time.Second)
	app.PressLast("Archive")
	app.WaitUntil(2*time.Second, func() bool { return m.AllCounts.Get().Archive == 1 })
	for _, it := range m.Core.Search("", state.SearchFilter{Category: state.FilterAll}) {
		if it.ID == "c-mine" {
			t.Fatal("an archived item stays in All Items")
		}
	}

	app.Press("Archive")
	app.Post(func() { m.SelectCipher(root, "c-mine") })
	app.WaitFor("Unarchive", 2*time.Second)
	app.Find("Archived")
	app.Press("Unarchive")
	app.WaitUntil(2*time.Second, func() bool { return m.AllCounts.Get().Archive == 0 })
	if c, _ := svc.GetCipher("c-mine"); c.ArchivedDate != nil {
		t.Fatal("unarchive did not apply")
	}
}

func TestArchiveIsPremiumButUnarchiveIsNot(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.noPremium = true
	when := time.Now()
	svc.ciphers["c-old"] = &state.Cipher{ID: "c-old", Type: api.CipherTypeLogin, Name: "Old", ArchivedDate: &when, Login: &state.Login{}}
	svc.ciphers["c-mine"] = &state.Cipher{ID: "c-mine", Type: api.CipherTypeLogin, Name: "Mine", Login: &state.Login{}}
	svc.order = append(svc.order, "c-old", "c-mine")
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() { m.SelectCipher(root, "c-mine") })
	app.WaitFor("Clone item", 2*time.Second)
	if app.EnabledLast("Archive") {
		t.Fatal("Archive is offered without premium")
	}
	app.Post(func() { m.SelectCipher(root, "c-old") })
	app.WaitFor("Unarchive", 2*time.Second)
	if !app.EnabledLast("Unarchive") || app.EnabledLast("Toggle favorite") {
		t.Fatalf("without premium: unarchive enabled %v, favorite enabled %v", app.EnabledLast("Unarchive"), app.EnabledLast("Toggle favorite"))
	}
}

func TestArchiveAsksForTheMasterPasswordOnAProtectedItem(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers["c-mine"] = &state.Cipher{ID: "c-mine", Type: api.CipherTypeLogin, Name: "Mine", Reprompt: 1, Login: &state.Login{}}
	svc.order = append(svc.order, "c-mine")
	svc.session = 7
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() { m.SelectCipher(root, "c-mine") })
	app.WaitFor("Clone item", 2*time.Second)
	app.PressLast("Archive")
	app.WaitUntil(2*time.Second, func() bool { return m.Reprompt.Get().Open })
	if c, _ := svc.GetCipher("c-mine"); c.ArchivedDate != nil {
		t.Fatal("a protected item was archived before the master password was verified")
	}
	app.Post(func() { m.RepromptPW.Set("master-password"); m.SubmitReprompt() })
	app.WaitUntil(2*time.Second, func() bool { c, _ := svc.GetCipher("c-mine"); return c.ArchivedDate != nil })
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	if len(svc.archiveSessions) != 1 || svc.archiveSessions[0] != 7 {
		t.Fatalf("archive ran in session %v, want the one it was asked in", svc.archiveSessions)
	}
}

func TestEditorKeepsFavoriteOfAnArchivedItemWithoutPremium(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.noPremium = true
	when := time.Now()
	svc.ciphers["c-old"] = &state.Cipher{ID: "c-old", Type: api.CipherTypeLogin, Name: "Old", ArchivedDate: &when, Login: &state.Login{}}
	svc.ciphers["c-mine"] = &state.Cipher{ID: "c-mine", Type: api.CipherTypeLogin, Name: "Mine", Login: &state.Login{}}
	svc.order = append(svc.order, "c-old", "c-mine")
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})
	for id, want := range map[string]bool{"c-old": false, "c-mine": true} {
		app.Post(func() { m.EditMode.Set(false); m.EditDraft.Set(nil); m.SelectCipher(root, id) })
		app.WaitUntil(2*time.Second, func() bool { c := m.ActiveCipher.Get(); return c != nil && c.ID == id })
		app.Post(func() { m.StartEditCipher(root) })
		app.WaitFor("Favorite", 2*time.Second)
		if got := app.Enabled("Favorite"); got != want {
			t.Fatalf("%s: favorite enabled %v, want %v", id, got, want)
		}
	}
}
