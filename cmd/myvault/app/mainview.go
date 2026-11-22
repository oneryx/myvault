package app

import (
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/oneryx/myvault/cmd/myvault/core"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

// MainWindowView builds the main window from the model, every frame.
func MainWindowView(c *ui.Context, m *AppModel) {
	applyTheme(c)
	p := pal(c)
	c.Root().Background(p.Canvas)
	bindMainWindowShortcuts(c, m)

	ui.Column(c).Fill().Children(func() {
		switch m.LockState.Get() {
		case state.StatusUnlocked:
			UnlockedShellView(c, m)
		case state.StatusLocked:
			if m.ReSignIn.Get() {
				LoginView(c, m)
			} else {
				LockView(c, m)
			}
		default:
			LoginView(c, m)
		}
	})

	if m.LockState.Get() == state.StatusUnlocked {
		repromptDialog(c, m)
		backupDialog(c, m)
		folderDialog(c, m)
	}
	alertDialog(c, m)
	toastViewport(c, m)
}

func bindMainWindowShortcuts(c *ui.Context, m *AppModel) {
	cx := m.Scope
	unlocked := func() bool { return m.LockState.Get() == state.StatusUnlocked }
	inVault := func() bool { return unlocked() && m.Route.Get() == RouteVault && !m.EditMode.Get() }

	c.OnWindowShortcut(ui.Cmd, ui.KeyF, func() {
		if !unlocked() {
			return
		}
		m.ResetIdleTimer()
		m.Route.Set(RouteVault)
		m.SearchRef.Focus()
	})
	c.OnWindowShortcut(ui.Cmd, ui.KeyBracketLeft, func() { m.GoBack(cx) })
	c.OnWindowShortcut(ui.Cmd, ui.KeyBracketRight, func() { m.GoForward(cx) })
	c.OnWindowShortcut(0, ui.KeyBack, func() { m.GoBack(cx) })
	c.OnWindowShortcut(0, ui.KeyForward, func() { m.GoForward(cx) })
	c.OnWindowShortcut(ui.Cmd, ui.KeyN, func() {
		if unlocked() && m.SyncState.Get() != SyncOffline {
			m.StartCreateCipher(cx)
		}
	})
	c.OnWindowShortcut(ui.Cmd, ui.KeyE, func() {
		if inVault() && m.SyncState.Get() != SyncOffline {
			m.StartEditCipher(cx)
		}
	})
	c.OnWindowShortcut(ui.Cmd, ui.KeyS, func() {
		if unlocked() && m.EditMode.Get() {
			m.SaveDraft(cx)
		}
	})
	if unlocked() && m.EditMode.Get() {
		c.OnWindowShortcut(0, ui.KeyEscape, func() { m.CancelEdit(cx) })
	}
	if !c.FocusTakesText() {
		c.OnWindowShortcut(ui.Cmd, ui.KeyC, func() {
			if !inVault() {
				return
			}
			ci := m.ActiveCipher.Get()
			if ci == nil || ci.Login == nil || ci.Login.Password == "" || m.PasswordHidden(ci) {
				return
			}
			m.GateReprompt(cx, ci, "copy password", func() {
				m.CopySecretValue("Password", ci.Login.Password)
			})
		})
		c.OnWindowShortcut(0, ui.KeyDown, func() {
			if inVault() {
				m.MoveListSelection(cx, 1)
			}
		})
		c.OnWindowShortcut(0, ui.KeyUp, func() {
			if inVault() {
				m.MoveListSelection(cx, -1)
			}
		})
	}
	c.OnWindowShortcut(ui.Cmd|ui.Shift, ui.KeyU, func() {
		if !inVault() {
			return
		}
		ci := m.ActiveCipher.Get()
		if ci != nil && ci.Login != nil && ci.Login.Username != "" {
			m.CopyPlainValue("Username", ci.Login.Username)
		}
	})
	c.OnWindowShortcut(ui.Cmd|ui.Shift, ui.KeyT, func() {
		if !inVault() {
			return
		}
		ci := m.ActiveCipher.Get()
		if ci == nil || ci.Login == nil || strings.TrimSpace(ci.Login.TOTP) == "" {
			return
		}
		m.GateReprompt(cx, ci, "copy TOTP code", func() {
			if code := m.TOTPCode.Get(); code != "" {
				m.CopySecretValue("TOTP code", code)
			}
		})
	})
	c.OnWindowShortcut(ui.Cmd, ui.KeyL, func() {
		if unlocked() {
			m.Lock()
		}
	})
	c.OnWindowShortcut(ui.Cmd, ui.KeyR, func() {
		if unlocked() {
			m.SyncNow(false)
		}
	})
	c.OnWindowShortcut(ui.Cmd, ui.KeyComma, func() {
		if unlocked() {
			m.GuardDirty(cx, func() { m.Route.Set(RouteSettings) })
		}
	})
}

// dialogPanel builds the common look of the app's dialogs.
func dialogPanel(c *ui.Context, open *bool, title, description string, body func(), footer func()) ui.Element {
	return ui.DialogBase(c, open, func(backdrop, panel ui.Element) {
		p := pal(c)
		backdrop.Background(ui.RGBA(0, 0, 0, 0.32))
		panel.Width(400).Padding(22).Gap(14).Radius(14).Background(p.Card).Border(1, p.Line).
			Shadow(0, 24, 60, -12, rgba(0x000000, 0.35))
		ui.Column(c).Gap(6).Children(func() {
			ui.Text(c, title).FontSize(15).FontWeight(600).TextColor(p.Fg)
			if description != "" {
				ui.Text(c, description).FontSize(12.5).TextColor(p.Fg2)
			}
		})
		ui.Column(c).Gap(10).Children(body)
		ui.Row(c).Gap(8).Justify(ui.End).Children(footer)
	})
}

// passwordInput is a masked single-line input bound to a string signal.
func passwordInput(c *ui.Context, key string, sig *core.Signal[string], placeholder string, autoFocus bool, onSubmit func()) ui.Element {
	return bindString(sig.Get, sig.Set, func(v *string) ui.Element {
		in := fieldInput(c, ui.TextInput(c.Key(key), v).Password().Placeholder(placeholder).Label(placeholder).Autocorrect(false), 32)
		if autoFocus {
			in.AutoFocus()
		}
		if in.Submitted() && onSubmit != nil {
			onSubmit()
		}
		return in
	})
}

func busyButton(c *ui.Context, text string, busy bool, primary bool) ui.Element {
	var b ui.Element
	if primary {
		b = ui.PrimaryButton(c, "")
	} else {
		b = ui.Button(c, "")
	}
	b.Disabled(busy).Busy(busy).Children(func() {
		if busy {
			ui.Spinner(c).Size(12, 12)
		}
		ui.Text(c, text).SingleLine()
	})
	return b
}

func repromptDialog(c *ui.Context, m *AppModel) {
	r := m.Reprompt.Get()
	if !r.Open {
		return
	}
	open := true
	desc := "Enter your master password to continue."
	if r.Action != "" {
		desc = "Enter your master password to " + r.Action + "."
	}
	dialogPanel(c, &open, "Master Password Verification", desc, func() {
		passwordInput(c, "reprompt-password", m.RepromptPW, "Master Password", true, m.SubmitReprompt)
		if e := m.RepromptError.Get(); e != "" {
			ui.Text(c, e).FontSize(12).TextColor(pal(c).Danger)
		}
	}, func() {
		ui.Button(c, "Cancel").OnClick(m.CloseReprompt)
		busyButton(c, "Verify", m.RepromptBusy.Get(), true).OnClick(m.SubmitReprompt)
	})
	if !open {
		m.CloseReprompt()
	}
}

func backupDialog(c *ui.Context, m *AppModel) {
	mode := m.BackupDialog.Get()
	if mode == BackupNone {
		return
	}
	open := true
	title, desc, confirm := "Protect Your Backup", "Choose a password for the encrypted backup. It cannot be recovered if you forget it.", "Export"
	if mode == BackupImport {
		title, desc, confirm = "Backup Password", "Enter the password this backup was exported with.", "Decrypt"
	}
	submit := func() { m.ConfirmBackupDialog(m.Scope) }
	dialogPanel(c, &open, title, desc, func() {
		passwordInput(c, "backup-password", m.BackupPW, "Backup password", true, submit)
		if mode == BackupExport {
			passwordInput(c, "backup-password-confirm", m.BackupPW2, "Confirm password", false, submit)
		}
		if e := m.BackupError.Get(); e != "" {
			ui.Text(c, e).FontSize(12).TextColor(pal(c).Danger)
		}
	}, func() {
		ui.Button(c, "Cancel").OnClick(m.CloseBackupDialog)
		busyButton(c, confirm, m.BackupBusy.Get(), true).OnClick(submit)
	})
	if !open {
		m.CloseBackupDialog()
	}
}

func folderDialog(c *ui.Context, m *AppModel) {
	dlg := m.FolderDialog.Get()
	if !dlg.Open {
		return
	}
	open := true
	title := "Rename Folder"
	if dlg.FolderID == "" {
		title = "New Folder"
	}
	closeDialog := func() {
		m.FolderError.Set("")
		m.FolderDialog.Set(FolderModal{})
	}
	dialogPanel(c, &open, title, "", func() {
		name := dlg.Name
		in := fieldInput(c, ui.TextInput(c.Key("folder-name-input"), &name).Placeholder("Folder name").Label("Folder name").AutoFocus(), 32)
		if name != dlg.Name {
			d := m.FolderDialog.Get()
			d.Name = name
			m.FolderDialog.Set(d)
		}
		if in.Submitted() {
			m.SaveFolderModal()
		}
		if e := m.FolderError.Get(); e != "" {
			ui.Text(c, e).FontSize(12).TextColor(pal(c).Danger)
		}
	}, func() {
		ui.Button(c, "Cancel").OnClick(closeDialog)
		busyButton(c, "Save", m.FolderBusy.Get(), true).OnClick(m.SaveFolderModal)
	})
	if !open {
		closeDialog()
	}
}

// alertDialog shows the model's pending alert.
func alertDialog(c *ui.Context, m *AppModel) {
	h := m.Scope.Host()
	if h == nil {
		return
	}
	a := h.Alert()
	if a == nil {
		return
	}
	labels := make([]string, len(a.Config.Actions))
	for i, act := range a.Config.Actions {
		labels[i] = act.Label
	}
	switch idx := ui.AlertDialog(c.Key(a), &a.Open, a.Config.Title, a.Config.Message, labels...); {
	case idx == ui.AlertDismissed:
		h.Answer(a, -1)
	case idx >= 0:
		h.Answer(a, idx)
	}
}

// toastViewport shows the model's toasts in the bottom right corner.
func toastViewport(c *ui.Context, m *AppModel) {
	m.Toaster.Flush(c)
	ui.ToastViewportBase(c, func(viewport ui.Element, toasts []ui.Toast) {
		p := pal(c)
		viewport.Padding(16).Justify(ui.End).AlignItems(ui.End).Gap(8)
		for _, t := range toasts {
			toast := ui.ToastBase(c, t)
			toast.Root.Row().AlignItems(ui.Start).Gap(10).Padding(10, 12).Width(320).Radius(10).
				Background(p.Card).Border(1, p.Line).Shadow(0, 10, 30, -8, rgba(0x000000, 0.28))
			toast.Root.Transition(ui.ElementTransition{Enter: &ui.Motion{Y: 8}, Exit: &ui.Motion{}})
			toast.Root.Children(func() {
				glyph, color := iconInfo, p.Accent
				switch ToastType(t.Type) {
				case ToastSuccess:
					glyph, color = iconCircleCheck, p.Success
				case ToastWarning:
					glyph, color = iconTriangleAlert, p.Warn
				case ToastError:
					glyph, color = iconCircleX, p.Danger
				}
				icon(c, glyph, 15, color).Margin(1, 0, 0, 0)
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					ui.Text(c, t.Title).FontSize(12.5).FontWeight(600).TextColor(p.Fg)
					if t.Description != "" {
						ui.Text(c, t.Description).FontSize(12).TextColor(p.Fg2)
					}
				})
				if t.Action != "" {
					toast.ActionButton().Children(func() {
						ui.Text(c, t.Action).FontSize(12).FontWeight(600).TextColor(p.Accent)
					})
				}
				toast.CloseButton().Label("Close").Children(func() { icon(c, iconX, 12, p.Fg3) })
			})
		}
	})
}

// clock is the time a view shows, which tests may fix.
var clock = time.Now
