package app

import (
	"sync"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/oneryx/myvault/cmd/myvault/core"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

// testApp runs the model and the main window's view on the test goroutine,
// which stands in for the main thread: work the model posts waits in a
// queue until the test pumps it.
type testApp struct {
	t     *testing.T
	tt    *ui.Tester
	host  *core.Host
	scope *core.Scope
	m     *AppModel

	mu    sync.Mutex
	queue []func()

	// OnAlert answers the model's alerts with the index of an action.
	OnAlert func(core.AlertConfig) int
	// PickFiles answers the open dialog.
	PickFiles func(core.PickFilesOptions) []core.File

	BiometricAvailability core.BiometricKind
	BiometricAnswer       core.BiometricResult
	// AuthenticationReasons are the reasons biometrics were asked with.
	AuthenticationReasons []string
	// StorageDir holds the persisted settings.
	StorageDir string
}

// newTestApp starts a model of svc in a window of w by h. setup runs
// before the first frame.
func newTestApp(t *testing.T, svc state.VaultService, hooks PlatformHooks, w, h int, setup func(m *AppModel)) *testApp {
	t.Helper()
	a := &testApp{t: t, StorageDir: t.TempDir()}
	core.SetStorageDir(a.StorageDir)
	a.host = &core.Host{
		Post: func(fn func()) {
			a.mu.Lock()
			a.queue = append(a.queue, fn)
			a.mu.Unlock()
		},
		SetClipboard: func(string) {},
		BiometricAvailability: func() core.BiometricKind {
			a.mu.Lock()
			defer a.mu.Unlock()
			return a.BiometricAvailability
		},
		AuthenticateBiometric: func(reason string, done func(core.BiometricResult)) {
			a.mu.Lock()
			a.AuthenticationReasons = append(a.AuthenticationReasons, reason)
			answer := a.BiometricAnswer
			a.mu.Unlock()
			done(answer)
		},
		PickFiles: func(opts core.PickFilesOptions) ([]core.File, error) {
			a.mu.Lock()
			pick := a.PickFiles
			a.mu.Unlock()
			if pick == nil {
				return nil, nil
			}
			return pick(opts), nil
		},
	}
	a.scope = core.NewScope(a.host)
	a.m = NewAppModel(a.scope, svc, hooks)
	if setup != nil {
		setup(a.m)
	}
	a.tt = ui.NewTester(func(c *ui.Context) { MainWindowView(c, a.m) }, w, h)
	t.Cleanup(func() {
		a.scope.Dispose()
		a.host.ClearAlerts()
	})
	a.pump()
	return a
}

// startSecurityApp starts an unlocked-capable app whose master password
// checks always pass.
func startSecurityApp(t *testing.T, svc *mockVaultService, hooks PlatformHooks) (*testApp, *AppModel, *core.Scope) {
	t.Helper()
	if hooks.VerifyMasterPassword == nil {
		hooks.VerifyMasterPassword = func(string, []byte) error { return nil }
	}
	a := newTestApp(t, svc, hooks, 1100, 900, func(m *AppModel) {
		m.MainWinVisible.Set(true)
		m.RefreshVaultData()
	})
	return a, a.m, a.scope
}

// pump runs the posted work and answers alerts until nothing is left,
// drawing a frame after each round.
func (a *testApp) pump() {
	for range 100 {
		a.mu.Lock()
		queue := a.queue
		a.queue = nil
		a.mu.Unlock()
		for _, fn := range queue {
			fn()
		}
		answered := false
		if a.OnAlert != nil {
			if al := a.host.Alert(); al != nil {
				a.host.Answer(al, a.OnAlert(al.Config))
				answered = true
			}
		}
		a.tt.Frame()
		a.mu.Lock()
		idle := len(a.queue) == 0
		a.mu.Unlock()
		if idle && !answered {
			return
		}
	}
}

// Post runs fn on the main thread, then what it posted.
func (a *testApp) Post(fn func()) {
	a.host.Post(func() { a.scope.Batch(fn) })
	a.pump()
}

// Settle lets background work finish and the view catch up.
func (a *testApp) Settle() {
	for range 5 {
		time.Sleep(10 * time.Millisecond)
		a.pump()
	}
}

// WaitUntil pumps until cond holds, failing the test after d.
func (a *testApp) WaitUntil(d time.Duration, cond func() bool) {
	a.t.Helper()
	deadline := time.Now().Add(d)
	for {
		a.pump()
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			a.t.Fatalf("condition not met in %v; texts: %q", d, a.tt.Texts())
		}
		time.Sleep(time.Millisecond)
	}
}

// Exists reports whether a text, or an element named s, shows.
func (a *testApp) Exists(s string) bool {
	if _, ok := a.tt.Find(s); ok {
		return true
	}
	if info, ok := a.tt.Access(s); ok && !info.Offscreen {
		return true
	}
	return false
}

// Contains reports whether some text shows that contains s.
func (a *testApp) Contains(s string) bool { return a.tt.HasText(s) }

// Find fails unless s shows.
func (a *testApp) Find(s string) {
	a.t.Helper()
	if !a.Exists(s) {
		a.t.Fatalf("%q not shown; texts: %q", s, a.tt.Texts())
	}
}

func (a *testApp) WaitFor(s string, d time.Duration) {
	a.t.Helper()
	a.WaitUntil(d, func() bool { return a.Exists(s) })
}

func (a *testApp) WaitForGone(s string, d time.Duration) {
	a.t.Helper()
	a.WaitUntil(d, func() bool { return !a.Exists(s) })
}

// Press clicks the text or the element named s.
func (a *testApp) Press(s string) {
	a.t.Helper()
	all := a.tt.AccessAll()
	for _, info := range all {
		if info.Role != ui.RoleText && info.Name == s && !info.Disabled && !info.Offscreen && info.Bounds.W > 0 && info.Bounds.H > 0 {
			b := info.Bounds
			a.tt.ClickAt(b.X+b.W/2, b.Y+b.H/2)
			a.pump()
			return
		}
	}
	for _, info := range all {
		if info.Name == s && !info.Disabled && !info.Offscreen && info.Bounds.W > 0 && info.Bounds.H > 0 {
			b := info.Bounds
			a.tt.ClickAt(b.X+b.W/2, b.Y+b.H/2)
			a.pump()
			return
		}
	}
	if err := a.tt.Click(s); err != nil {
		a.t.Fatalf("click %q: %v; texts: %q", s, err, a.tt.Texts())
	}
	a.pump()
}

// Type replaces the text of the input named s.
func (a *testApp) Type(s, text string) {
	a.t.Helper()
	info, ok := a.tt.AccessByRole(ui.RoleTextField, s)
	if !ok {
		a.t.Fatalf("no input named %q; texts: %q", s, a.tt.Texts())
	}
	b := info.Bounds
	a.tt.ClickAt(b.X+b.W/2, b.Y+b.H/2)
	a.pump()
	a.tt.Key(ui.Cmd, ui.KeyA)
	a.tt.Type(text)
	a.pump()
}

// Key presses a key.
func (a *testApp) Key(mods ui.Modifiers, key ui.Key) {
	a.tt.Key(mods, key)
	a.pump()
}

// Enabled reports whether the element named s takes input.
func (a *testApp) Enabled(s string) bool {
	a.t.Helper()
	for _, info := range a.tt.AccessAll() {
		if info.Role != ui.RoleText && info.Name == s {
			return !info.Disabled
		}
	}
	a.t.Fatalf("no control named %q", s)
	return false
}

// PressLast clicks the last control named s, as the detail pane's when the
// sidebar has one of the same name.
func (a *testApp) PressLast(s string) {
	a.t.Helper()
	all := a.tt.AccessAll()
	for i := len(all) - 1; i >= 0; i-- {
		info := all[i]
		if info.Role != ui.RoleText && info.Name == s && !info.Offscreen && info.Bounds.W > 0 {
			b := info.Bounds
			a.tt.ClickAt(b.X+b.W/2, b.Y+b.H/2)
			a.pump()
			return
		}
	}
	a.t.Fatalf("no control named %q", s)
}

// EnabledLast reports whether the last control named s takes input.
func (a *testApp) EnabledLast(s string) bool {
	a.t.Helper()
	all := a.tt.AccessAll()
	for i := len(all) - 1; i >= 0; i-- {
		if all[i].Role != ui.RoleText && all[i].Name == s {
			return !all[i].Disabled
		}
	}
	a.t.Fatalf("no control named %q", s)
	return false
}
