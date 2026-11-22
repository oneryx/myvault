package main

import (
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/plugins/updater"
	vaultapp "github.com/oneryx/myvault/cmd/myvault/app"
)

// appUpdates is the updater for the Settings page, or nil when this build
// cannot update itself (development builds, package-manager installs).
func appUpdates(redraw func()) vaultapp.UpdateHost {
	if !mygo.Updater.Enabled() {
		return nil
	}
	updater.OnChange(redraw)
	return updateHost{}
}

type updateHost struct{}

func (updateHost) AutomaticChecks() bool      { return updater.AutomaticChecks() }
func (updateHost) SetAutomaticChecks(on bool) { updater.SetAutomaticChecks(on) }
func (updateHost) CheckNow()                  { updater.CheckForUpdates() }
func (updateHost) AvailableVersion() string   { return updater.AvailableVersion() }
func (updateHost) LastCheck() time.Time       { return updater.LastCheck() }
