package app

import (
	"testing"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/state"
)

type fakeUpdates struct {
	auto      bool
	checks    int
	available string
}

func (f *fakeUpdates) AutomaticChecks() bool      { return f.auto }
func (f *fakeUpdates) SetAutomaticChecks(on bool) { f.auto = on }
func (f *fakeUpdates) CheckNow()                  { f.checks++ }
func (f *fakeUpdates) AvailableVersion() string   { return f.available }
func (f *fakeUpdates) LastCheck() time.Time       { return time.Time{} }

// Settings → About offers update checks only in builds that can update.
func TestSettingsUpdateRows(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	app, model := startApp(t, svc, PlatformHooks{}, 1100, 900)
	app.Post(func() { model.Route.Set(RouteSettings) })
	app.WaitFor("About", 2*time.Second)
	if app.Exists("Check Now") {
		t.Fatal("update rows shown in a build that cannot update")
	}

	up := &fakeUpdates{auto: true, available: "0.2.0"}
	app, model = startApp(t, svc, PlatformHooks{Updates: up}, 1100, 1800)
	app.Post(func() { model.Route.Set(RouteSettings) })
	app.WaitFor("Check Now", 2*time.Second)
	app.Find("Version 0.2.0 is available.")

	app.Press("Check for updates automatically")
	app.Settle()
	if up.auto {
		t.Fatal("automatic checks still on after toggling the switch")
	}
	app.Press("Check Now")
	app.Settle()
	if up.checks != 1 {
		t.Fatalf("CheckNow called %d times, want 1", up.checks)
	}
}
