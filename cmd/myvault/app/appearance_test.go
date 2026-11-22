package app

import (
	"testing"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/state"
)

// Settings → Theme remembers the choice and hands it to the shell.
func TestAppearanceSettingIsRememberedAndApplied(t *testing.T) {
	var applied []string
	svc := newMockVaultService(state.StatusUnlocked)
	app, model := startApp(t, svc, PlatformHooks{SetAppearance: func(a string) { applied = append(applied, a) }}, 1100, 900)
	app.Post(func() { model.Route.Set(RouteSettings) })
	app.WaitFor("Theme", 2*time.Second)

	app.Press("Dark")
	app.Settle()
	if model.Prefs.Get().Appearance != "dark" || len(applied) != 1 || applied[0] != "dark" {
		t.Fatalf("after Dark: pref %q, applied %v", model.Prefs.Get().Appearance, applied)
	}
	app.Press("System")
	app.Settle()
	if model.Prefs.Get().Appearance != "" || applied[len(applied)-1] != "" {
		t.Fatalf("after System: pref %q, applied %v", model.Prefs.Get().Appearance, applied)
	}
}
