//go:build shot

package main

import (
	"os"
	"strings"
	"time"

	"github.com/egoist/mygo"
	vaultapp "github.com/oneryx/myvault/cmd/myvault/app"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

// MYVAULT_SHOT=path captures the main window after a moment, then quits.
// MYVAULT_SHOT_DO runs named steps before that.
func init() {
	path := os.Getenv("MYVAULT_SHOT")
	if path == "" {
		return
	}
	go func() {
		time.Sleep(1500 * time.Millisecond)
		for _, step := range strings.Split(os.Getenv("MYVAULT_SHOT_DO"), ",") {
			if step == "" {
				continue
			}
			mygo.RunOnMain(func() { shotStep(step) })
			time.Sleep(700 * time.Millisecond)
		}
		var png []byte
		mygo.RunOnMain(func() {})
		for _, w := range mygo.Windows() {
			png, _ = w.CapturePage()
			break
		}
		_ = os.WriteFile(path, png, 0o644)
		mygo.App.Exit(0)
	}()
}

func shotStep(step string) {
	m := activeShell.model
	switch {
	case step == "lock":
		m.Lock()
	case step == "add":
		m.AddAccount()
	case strings.HasPrefix(step, "select:"):
		m.SelectCipher(m.Scope, strings.TrimPrefix(step, "select:"))
	case step == "edit":
		m.StartEditCipher(m.Scope)
	case step == "new":
		m.StartCreateCipher(m.Scope)
	case step == "generator":
		m.Route.Set(vaultapp.RouteGenerator)
	case step == "settings":
		m.Route.Set(vaultapp.RouteSettings)
	case step == "health":
		m.Route.Set(vaultapp.RouteHealth)
	case step == "light":
		mygo.Theme.SetSource(mygo.ThemeLight)
	case step == "trash":
		m.SetSidebarFilter(state.SearchFilter{Category: state.FilterTrash})
	case step == "search":
		m.SetSearchQuery("zzz")
	case step == "dark":
		mygo.Theme.SetSource(mygo.ThemeDark)
	}
}
