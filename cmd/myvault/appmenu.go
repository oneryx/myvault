package main

import (
	"runtime"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/plugins/updater"
)

// applicationMenu is the menu bar. On macOS it keeps the standard app, Edit
// and Window menus and their system shortcuts; elsewhere the window's menu
// bar stays hidden until Alt and only offers the app items.
func applicationMenu() *mygo.Menu {
	if runtime.GOOS != "darwin" {
		return mygo.NewMenu([]*mygo.MenuItem{
			{Label: "MyVault", Submenu: []*mygo.MenuItem{
				updater.MenuItem(),
				mygo.Separator(),
				{Role: mygo.RoleQuit},
			}},
		})
	}
	return mygo.NewMenu([]*mygo.MenuItem{
		{Role: mygo.RoleAppMenu, Submenu: []*mygo.MenuItem{
			{Role: mygo.RoleAbout},
			updater.MenuItem(),
			mygo.Separator(),
			{Role: mygo.RoleServices},
			mygo.Separator(),
			{Role: mygo.RoleHide},
			{Role: mygo.RoleHideOthers},
			{Role: mygo.RoleUnhide},
			mygo.Separator(),
			{Role: mygo.RoleQuit},
		}},
		{Role: mygo.RoleEditMenu},
		{Role: mygo.RoleWindowMenu},
	})
}
