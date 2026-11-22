package app

import (
	"runtime"
	"strings"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
)

func appVersionLabel() string {
	v := mygo.App.Version()
	if v == "" {
		return "(development)"
	}
	if mygo.IsDev() {
		return v + " (development)"
	}
	return v
}

// updateStatus describes the newest version found, or when the app last checked.
func updateStatus(up UpdateHost) string {
	if v := up.AvailableVersion(); v != "" {
		return "Version " + v + " is available."
	}
	last := up.LastCheck()
	if last.IsZero() {
		return "Not checked yet."
	}
	return "Up to date. Last checked " + last.Local().Format("2 Jan 2006 15:04") + "."
}

func trayLabel() string {
	if runtime.GOOS == "darwin" {
		return "Menu Bar"
	}
	return "Tray"
}

// SettingsView shows the account and the app's settings.
func SettingsView(c *ui.Context, m *AppModel) {
	pageScroll(c, 620, 24, func() {
		// Check biometrics again each time the page opens.
		ui.Local(ui.Box(c), "refresh", func() bool {
			m.RefreshBiometricAvailability()
			m.RefreshBiometricProtection()
			return true
		})
		prefs := m.Prefs.Get()
		p := pal(c)
		section(c, "Account", func() {
			card(c,
				func() {
					ui.Row(c).Gap(12).Padding(14, 16).Children(func() {
						avatar(c, prefs.Email, 40)
						ui.Column(c).Grow(1).Shrink(1).Gap(2).Clip().Children(func() {
							ui.Text(c, prefs.Email).FontSize(14).FontWeight(600).TextColor(p.Fg).SingleLine()
							ui.Text(c, prefs.ServerURL).FontSize(12).TextColor(p.Fg2).SingleLine()
						})
						syncing := m.SyncState.Get() == SyncInProgress
						ui.Button(c, "").Disabled(syncing).OnClick(func() { m.SyncNow(false) }).Children(func() {
							if syncing {
								ui.Spinner(c).Size(12, 12)
							} else {
								ui.Icon(c, iconRefreshCw).Size(13, 13)
							}
							ui.Text(c, "Sync Now").SingleLine()
						})
					})
				},
				func() {
					kdf := prefs.KDFSummary
					if kdf == "" {
						kdf = "—"
					}
					pageMetaRow(c, "Key derivation", kdf)
				},
				func() {
					last := "Not yet synced"
					if ts := m.LastSync.Get(); !ts.IsZero() {
						last = ts.Local().Format("Jan 2, 2006 at 3:04 PM")
					}
					pageMetaRow(c, "Last sync", last)
				},
				func() {
					ui.Row(c).Justify(ui.SpaceBetween).Padding(8, 6, 8, 16).Children(func() {
						ui.Text(c, "Logging out removes the local vault cache.").FontSize(12).TextColor(p.Fg3)
						b := ui.ButtonBase(c).Label("Log Out").Height(26).Padding(0, 10).Radius(6).Gap(6)
						if b.Hovered() || b.Pressed() {
							b.Background(p.Danger.Alpha(0.10))
						}
						b.OnClick(func() { m.Logout(m.Scope) }).Children(func() {
							icon(c, iconLogOut, 13, p.Danger)
							ui.Text(c, "Log Out").FontSize(12.5).FontWeight(500).TextColor(p.Danger)
						})
					})
				},
			)
		})

		section(c, "Security", func() {
			var rows []func()
			if runtime.GOOS == "darwin" || m.CanUseBiometric() {
				rows = append(rows, pageBiometricRows(c, m, m.CanUseBiometric(), prefs.BiometricEnabled())...)
			}
			rows = append(rows, func() {
				pageOptionRow(c, "Auto-lock", "Lock the vault after a period of inactivity.", func() {
					pageSelect(c, "Auto-lock", prefs.AutoLockMinutes,
						[]int{1, 5, 15, 60, 0},
						[]string{"After 1 minute", "After 5 minutes", "After 15 minutes", "After 1 hour", "Never"}, 172,
						func(mins int) {
							m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.AutoLockMinutes = mins; return p })
							m.ResetIdleTimer()
						})
				})
			})
			if m.Hooks.SleepLockSupported {
				rows = append(rows, func() {
					pageOptionRow(c, "Lock on sleep or screen lock", "Lock the vault when your computer sleeps or the screen locks.", func() {
						pageSwitch(c, "Lock on sleep or screen lock", prefs.LockOnSleep, false, func(on bool) {
							m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.LockOnSleep = on; return p })
						})
					})
				})
			}
			card(c, rows...)
		})

		if m.Hooks.SSHAgent != nil {
			pageSSHAgentSection(c, m)
		}

		section(c, "Backup", func() {
			card(c,
				func() {
					pageOptionRow(c, "Export encrypted backup", "A Bitwarden-compatible JSON file protected by a password you choose.", func() {
						pageIconButton(c, iconFileOutput, "Export…", false).OnClick(m.StartExport)
					})
				},
				func() {
					pageOptionRow(c, "Import backup", "Bitwarden JSON, encrypted or plain. Review every item before anything changes.", func() {
						pageIconButton(c, iconFileInput, "Import…", false).
							Disabled(m.SyncState.Get() == SyncOffline).OnClick(func() { m.StartImport(m.Scope) })
					})
				},
			)
		})

		section(c, "Appearance", func() {
			card(c, func() {
				pageOptionRow(c, "Theme", "Light, dark, or the same as the system.", func() {
					values := []string{"", "light", "dark"}
					sel := 0
					for i, v := range values {
						if v == prefs.Appearance {
							sel = i
						}
					}
					if ui.Segmented(c.Key("appearance"), &sel, "System", "Light", "Dark").Label("Theme").Changed() {
						m.SetAppearance(values[sel])
					}
				})
			})
		})

		section(c, "Privacy", func() {
			card(c,
				func() {
					pageOptionRow(c, "Show website icons", "Fetch site icons from your Vaultwarden server.", func() {
						pageSwitch(c, "Show website icons", prefs.FaviconsEnabled(), false, m.SetShowFavicons)
					})
				},
				func() {
					pageOptionRow(c, "Icon cache", "Remove downloaded site icons from this device.", func() {
						ui.Button(c, "Clear Icon Cache").OnClick(m.ClearIconCache)
					})
				},
			)
		})

		section(c, "Clipboard", func() {
			card(c,
				func() {
					pageOptionRow(c, "Clear copied secrets", "Clears the clipboard if it still holds the copied value.", func() {
						pageSelect(c, "Clear copied secrets", prefs.ClipboardClearSeconds,
							[]int{15, 30, 60, 0},
							[]string{"After 15 seconds", "After 30 seconds", "After 60 seconds", "Never"}, 172,
							func(secs int) {
								m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.ClipboardClearSeconds = secs; return p })
							})
					})
				},
				func() {
					pageOptionRow(c, "Concealed clipboard", "Marks secrets so clipboard managers skip them.", func() {
						ui.Badge(c, "Active").Background(p.Success.Alpha(0.14)).TextColor(p.Success)
					})
				},
			)
		})

		tray := strings.ToLower(trayLabel())
		section(c, trayLabel(), func() {
			rows := []func(){
				func() {
					pageOptionRow(c, "Show "+tray+" icon", "Open MyVault, sync or lock from the "+tray+".", func() {
						pageSwitch(c, "Show "+tray+" icon", prefs.ShowTrayIcon, false, m.SetShowTrayIcon)
					})
				},
				func() {
					pageOptionRow(c, "Launch at login", "Start MyVault automatically when you sign in.", func() {
						pageSwitch(c, "Launch at login", prefs.LaunchAtLogin, false, func(on bool) {
							m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.LaunchAtLogin = on; return p })
							if m.Hooks.SetLaunchAtLogin != nil {
								m.Hooks.SetLaunchAtLogin(on)
							}
						})
					})
				},
			}
			if runtime.GOOS == "darwin" {
				desc := "Keep MyVault in the menu bar only."
				if !prefs.ShowTrayIcon {
					desc = "Turn on the menu bar icon first, so MyVault stays reachable."
				}
				rows = append(rows, func() {
					pageOptionRow(c, "Hide Dock icon", desc, func() {
						pageSwitch(c, "Hide Dock icon", prefs.ShowTrayIcon && prefs.HideDockIcon, !prefs.ShowTrayIcon, func(on bool) {
							m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.HideDockIcon = on; return p })
							if m.Hooks.SetDockVisible != nil {
								m.Hooks.SetDockVisible(!on)
							}
						})
					})
				})
			}
			card(c, rows...)
		})

		section(c, "About", func() {
			rows := []func(){func() { pageMetaRow(c, "MyVault", appVersionLabel()) }}
			if up := m.Hooks.Updates; up != nil {
				rows = append(rows, func() {
					pageOptionRow(c, "Check for updates automatically", "Look for a new version once a day.", func() {
						pageSwitch(c, "Check for updates automatically", up.AutomaticChecks(), false, up.SetAutomaticChecks)
					})
				}, func() {
					pageOptionRow(c, "Updates", updateStatus(up), func() {
						ui.Button(c, "Check Now").OnClick(up.CheckNow)
					})
				})
			}
			card(c, rows...)
		})
	})
}

func pageSSHAgentSection(c *ui.Context, m *AppModel) {
	p := pal(c)
	on := m.Prefs.Get().SSHAgentEnabled
	section(c, "SSH Agent", func() {
		rows := []func(){func() {
			pageOptionRow(c, "Enable SSH agent", "Serve SSH keys from the unlocked vault. Keys with master password reprompt are not served.", func() {
				pageSwitch(c, "Enable SSH agent", on, false, m.SetSSHAgentEnabled)
			})
		}}
		if on {
			rows = append(rows, func() {
				ui.Row(c).Gap(12).Padding(10, 10, 10, 16).Children(func() {
					ui.Column(c).Grow(1).Shrink(1).Gap(3).Clip().Children(func() {
						ui.Text(c, "Socket").FontSize(13).TextColor(p.Fg)
						ui.Text(c, m.SSHAgentSocketPath()).FontSize(12).Font(monoFont).TextColor(p.Fg2).Selectable()
					})
					pageIconButton(c, iconCopy, "Copy SSH_AUTH_SOCK", false).OnClick(m.CopySSHAuthSock)
				})
			})
			if msg := m.SSHAgentError.Get(); msg != "" {
				rows = append(rows, func() {
					ui.Row(c).Gap(8).Padding(10, 16).Children(func() {
						icon(c, iconTriangleAlert, 13, p.Warn)
						ui.Text(c, "Agent unavailable: "+msg).FontSize(12).TextColor(p.Fg2).Grow(1)
					})
				})
			}
		}
		card(c, rows...)
	})
}

func pageBiometricRows(c *ui.Context, m *AppModel, available, enabled bool) []func() {
	p := pal(c)
	if !available {
		return []func(){func() {
			pageOptionRow(c, "Unlock with Touch ID", "Touch ID unavailable on this Mac — pair a Touch ID keyboard or enroll in System Settings.", func() {
				pageSwitch(c, "Unlock with Touch ID", false, true, nil)
			})
		}}
	}
	title := "Unlock with " + m.BiometricLabel()
	rows := []func(){func() {
		pageOptionRow(c, title, "Keeps a wrapped key in the system keychain for fast unlock.", func() {
			pageSwitch(c, title, m.Prefs.Get().BiometricEnabled(), false, func(on bool) { m.ToggleBiometric(m.Scope, on) })
		})
	}}
	if enabled && runtime.GOOS == "darwin" {
		rows = append(rows, func() {
			ui.Row(c).Gap(8).Padding(10, 16).Children(func() {
				glyph, text := iconKeyRound, "App-gated: the key is in your login keychain and MyVault asks for "+m.BiometricLabel()+" before reading it."
				if m.BiometricHardware.Get() {
					glyph, text = iconShieldCheck, "Hardware-enforced: macOS releases the key only after Touch ID."
				}
				icon(c, glyph, 13, p.Fg3)
				ui.Text(c, text).FontSize(12).TextColor(p.Fg2).Grow(1).Shrink(1)
			})
		})
	}
	if enabled {
		rows = append(rows, func() {
			pageOptionRow(c, "Prompt automatically", "Ask for "+m.BiometricLabel()+" as soon as the locked window opens.", func() {
				pageSwitch(c, "Prompt automatically", m.Prefs.Get().AutoPromptBiometric, false, func(on bool) {
					m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.AutoPromptBiometric = on; return p })
				})
			})
		})
	}
	return rows
}
