package app

import (
	"github.com/egoist/mygo/ui"
	"github.com/oneryx/myvault/cmd/myvault/core"
	"github.com/oneryx/myvault/internal/vaultcore/api"
)

const authFieldHeight = 34

// LoginView is the sign-in screen, or the two-step verification after it.
func LoginView(c *ui.Context, m *AppModel) {
	if prompt := m.TwoFactor.Get(); prompt != nil {
		TwoFactorView(c, m, prompt)
		return
	}
	signInView(c, m)
}

func signInView(c *ui.Context, m *AppModel) {
	authScreen(c, func() {
		p := pal(c)
		busy := m.LoginBusy.Get()
		adding := m.AddingFrom.Get() != ""
		ui.Column(c).AlignItems(ui.Center).Gap(10).Padding(0, 0, 4, 0).Children(func() {
			brandEmblem(c, 56)
			title := "Sign in to MyVault"
			if adding {
				title = "Add an Account"
			}
			ui.Text(c, title).FontSize(19).FontWeight(600).TextColor(p.Fg).Margin(6, 0, 0, 0)
			ui.Text(c, "Connect to your Bitwarden or Vaultwarden server.").FontSize(12.5).TextColor(p.Fg2).TextAlign(ui.Center)
		})
		ui.Column(c).Gap(14).Children(func() {
			formField(c, "Server URL", func() {
				bindString(m.LoginServer.Get, m.LoginServer.Set, func(v *string) ui.Element {
					return fieldInput(c, ui.TextInput(c.Key("login-server"), v), authFieldHeight).
						Placeholder("https://vault.example.com").Label("Server URL").Autocorrect(false).
						Disabled(busy || (m.CanReturnToUnlock() && m.ReSignInServer.Get() != ""))
				})
			})
			formField(c, "Email", func() {
				bindString(m.LoginEmail.Get, m.LoginEmail.Set, func(v *string) ui.Element {
					return fieldInput(c, ui.TextInput(c.Key("login-email"), v), authFieldHeight).
						Placeholder("name@example.com").Label("Email").Autocorrect(false).
						Disabled(busy || m.CanReturnToUnlock())
				})
			})
			formField(c, "Master Password", func() {
				secretField(c, m, "login-password", m.LoginPassword.Get, m.LoginPassword.Set, m.LoginShowPW, "Required", busy, false, m.Login, nil)
			})
		})
		if api.InsecureServer(m.LoginServer.Get()) {
			ui.Text(c, "This server does not use HTTPS. Your master password and vault data are sent unencrypted; use it only on a network you trust.").
				FontSize(12).TextColor(p.Warn)
		}
		if e := m.LoginError.Get(); e != "" {
			errorBanner(c, e)
		}
		busyButton(c, "Sign In", busy, true).FillWidth().Height(34).OnClick(m.Login)
		if m.CanReturnToUnlock() {
			ui.Button(c, "Back to Unlock").FillWidth().Height(34).OnClick(m.BackToUnlock)
		}
		if adding {
			ui.Button(c, "Cancel").FillWidth().Height(34).OnClick(m.CancelAddAccount)
		}
	}, "End-to-end encrypted. Your master password never leaves this device.")
}

// authScreen centers a card over the canvas, under a strip that drags the
// window.
func authScreen(c *ui.Context, body func(), footnote string) {
	p := pal(c)
	ui.Column(c).Fill().Children(func() {
		ui.Box(c).Height(titleBarHeight).FillWidth().DragWindow()
		ui.Column(c).Grow(1).Children(func() {
			ui.Column(c).Grow(1).AlignItems(ui.Center).Justify(ui.Center).Padding(0, 32, 52, 32).Gap(20).Children(func() {
				ui.Column(c).Width(380).Padding(32, 32, 28, 32).Gap(20).Radius(16).Background(p.Card).Border(1, p.Line).
					Shadow(0, 1, 3, 0, rgba(0x000000, 0.05)).
					Shadow(0, 18, 40, -16, rgba(0x000000, 0.22)).
					Children(body)
				ui.Row(c).Gap(6).Children(func() {
					icon(c, iconLockKeyhole, 11, p.Fg3)
					ui.Text(c, footnote).FontSize(11.5).TextColor(p.Fg3)
				})
			})
		})
	})
}

// secretField is a masked input with a reveal toggle and optional trailing
// controls inside its rim.
func secretField(c *ui.Context, m *AppModel, key string, get func() string, set func(string), showSig *core.Signal[bool], placeholder string, disabled, autoFocus bool, submit func(), trailing func()) {
	p := pal(c)
	shown := showSig.Get()
	show := &shown
	defer func() {
		if shown != showSig.Get() {
			showSig.Set(shown)
		}
	}()
	ui.Box(c).Children(func() {
		inset := float32(34)
		if trailing != nil {
			inset += 28
		}
		bindString(get, set, func(v *string) ui.Element {
			in := fieldInput(c, ui.TextInput(c.Key(key), v), authFieldHeight).
				Placeholder(placeholder).Label("Master password").Autocorrect(false).Disabled(disabled).
				PaddingStart(10).PaddingEnd(inset)
			if !*show {
				in.Password()
			}
			if autoFocus {
				in.AutoFocus()
			}
			if key == "lock-password" {
				in.Bind(&m.LockPasswordRef.Handle)
			}
			if in.Submitted() && submit != nil {
				submit()
			}
			return in
		})
		ui.Row(c).Absolute().Top(0).Bottom(0).Right(4).Gap(2).Children(func() {
			name := "Show password"
			if *show {
				name = "Hide password"
			}
			if ghostIconButton(c, name, eyeIcon(*show), authFieldHeight-8, 14, p.Fg3).Disabled(disabled).Clicked() {
				*show = !*show
			}
			if trailing != nil {
				trailing()
			}
		})
	})
}

// LockView unlocks a saved vault with the master password or biometrics.
func LockView(c *ui.Context, m *AppModel) {
	cx := m.Scope
	prefs := m.Prefs.Get()
	biometric := m.CanUseBiometric() && prefs.BiometricEnabled()
	if m.MainWinVisible.Get() && !m.LockAutoFired && biometric && prefs.AutoPromptBiometric {
		m.LockAutoFired = true
		m.UnlockWithBiometric(cx)
	}
	busy := m.LockBusy.Get()

	authScreen(c, func() {
		p := pal(c)
		ui.Column(c).AlignItems(ui.Center).Gap(4).Padding(0, 0, 4, 0).Children(func() {
			ui.Box(c).Margin(0, 0, 10, 0).Children(func() {
				avatar(c, prefs.Email, 64)
				ui.Box(c).Absolute().Right(-4).Bottom(-4).Size(26, 26).Radius(13).Center().
					Background(p.Accent).Border(2.5, p.Card).Children(func() {
					icon(c, iconLock, 12, p.White)
				})
			})
			ui.Text(c, "MyVault is Locked").FontSize(18).FontWeight(600).TextColor(p.Fg)
			ui.Text(c, prefs.Email).FontSize(13).TextColor(p.Fg2).SingleLine()
			ui.Text(c, prefs.ServerURL).FontSize(11.5).TextColor(p.Fg3).SingleLine()
		})
		unlock := func() { m.UnlockWithPassword() }
		if biometric {
			ui.Column(c).Gap(16).Children(func() {
				ui.PrimaryButton(c, "").FillWidth().Height(34).Disabled(busy).OnClick(func() { m.UnlockWithBiometric(cx) }).Children(func() {
					ui.Icon(c, iconFingerprintPattern).Size(15, 15)
					ui.Text(c, "Unlock with "+m.BiometricLabel()).SingleLine()
				})
				ui.Row(c).Gap(10).Children(func() {
					ui.Box(c).Grow(1).Height(1).Background(p.Line)
					ui.Text(c, "or use your master password").FontSize(11).TextColor(p.Fg3)
					ui.Box(c).Grow(1).Height(1).Background(p.Line)
				})
				secretField(c, m, "lock-password", m.LockPassword.Get, m.LockPassword.Set, m.LockShowPW, "Master password", busy, false, unlock, func() {
					side := float32(authFieldHeight - 10)
					ui.PrimaryButton(c, "").Label("Unlock").Size(side, side).Radius(side / 2).Padding(0).Disabled(busy).OnClick(unlock).Children(func() {
						ui.Icon(c, iconArrowRight).Size(13, 13)
					})
				})
			})
		} else {
			ui.Column(c).Gap(16).Children(func() {
				formField(c, "Master Password", func() {
					secretField(c, m, "lock-password", m.LockPassword.Get, m.LockPassword.Set, m.LockShowPW, "Master password", busy, true, unlock, nil)
				})
				busyButton(c, "Unlock", busy, true).FillWidth().Height(34).OnClick(unlock)
			})
		}
		if e := m.LockError.Get(); e != "" {
			errorBanner(c, e)
		}
		ui.Row(c).Justify(ui.Center).Children(func() {
			b := ui.ButtonBase(c).Label("Switch Account or Log Out").Height(24).Padding(0, 8).Radius(6).Gap(4).Center()
			if b.Pressed() || b.Hovered() {
				b.Background(p.Fill)
			}
			b.Menu(func(mn *ui.Menu) { accountMenu(mn, m) }).Children(func() {
				ui.Text(c, "Switch Account or Log Out").FontSize(12).FontWeight(500).TextColor(p.Fg2)
				icon(c, iconChevronDown, 12, p.Fg3)
			})
		})
	}, "Locked vaults stay encrypted at rest on this device.")
}

// TwoFactorView asks for the code of the second step of a sign-in.
func TwoFactorView(c *ui.Context, m *AppModel, prompt *TwoFactorPrompt) {
	busy := m.LoginBusy.Get()
	email := m.TwoFactorProvider.Get() == api.TwoFactorEmail
	authScreen(c, func() {
		p := pal(c)
		ui.Column(c).AlignItems(ui.Center).Gap(10).Padding(0, 0, 4, 0).Children(func() {
			ui.Box(c).Size(56, 56).Radius(56*0.28).Center().
				Gradient(rgb(0x3f7dff), rgb(0x1748b8), 160).
				Shadow(0, 56*0.12, 56*0.36, -56*0.12, rgba(0x1748b8, 0.55)).
				Children(func() { icon(c, iconShieldCheck, 28, p.White) })
			ui.Text(c, "Two-step verification").FontSize(19).FontWeight(600).TextColor(p.Fg).Margin(6, 0, 0, 0)
			hint := "Enter the 6-digit code from your authenticator app."
			if email {
				hint = "Enter the code sent to your email."
				if prompt.EmailHint != "" {
					hint = "Enter the code sent to " + prompt.EmailHint + "."
				}
			}
			ui.Text(c, hint).FontSize(12.5).TextColor(p.Fg2).TextAlign(ui.Center)
		})
		if prompt.Has(api.TwoFactorAuthenticator) && prompt.Has(api.TwoFactorEmail) {
			ui.Row(c).Justify(ui.Center).Children(func() {
				sel := 0
				if email {
					sel = 1
				}
				if ui.Segmented(c, &sel, api.TwoFactorAuthenticator.String(), api.TwoFactorEmail.String()).
					Label("Verification method").Disabled(busy).Changed() {
					if sel == 1 {
						m.SelectTwoFactorProvider(api.TwoFactorEmail)
					} else {
						m.SelectTwoFactorProvider(api.TwoFactorAuthenticator)
					}
				}
			})
		}
		ui.Column(c).Gap(12).Children(func() {
			formField(c, "Verification Code", func() {
				bindString(m.TwoFactorCode.Get, m.TwoFactorCode.Set, func(v *string) ui.Element {
					in := fieldInput(c, ui.TextInput(c.Key("twofactor-code"), v), authFieldHeight).
						Placeholder("123456").Label("Verification Code").Autocorrect(false).AutoFocus().
						MaxLength(12).Disabled(busy).Font(monoFont).FontSize(15).LetterSpacing(2)
					if in.Submitted() {
						m.VerifyTwoFactor()
					}
					return in
				})
			})
			if email {
				ui.Row(c).Gap(8).Children(func() {
					ui.Text(c, m.TwoFactorNotice.Get()).FontSize(11.5).TextColor(p.Fg2).Grow(1)
					text := "Send Code"
					if m.TwoFactorNotice.Get() != "" {
						text = "Resend Code"
					}
					sending := m.TwoFactorSending.Get()
					ui.Button(c, "").Disabled(busy || sending).OnClick(m.SendTwoFactorEmail).Children(func() {
						if sending {
							ui.Spinner(c).Size(12, 12)
						} else {
							ui.Icon(c, iconSend).Size(13, 13)
						}
						ui.Text(c, text).SingleLine()
					})
				})
			}
			remember := m.TwoFactorRemember.Get()
			if ui.Checkbox(c, &remember, "Remember this device").Disabled(busy).Changed() {
				m.TwoFactorRemember.Set(remember)
			}
		})
		if e := m.LoginError.Get(); e != "" {
			errorBanner(c, e)
		}
		ui.Column(c).Gap(8).Children(func() {
			busyButton(c, "Verify", busy, true).FillWidth().Height(34).OnClick(m.VerifyTwoFactor)
			ui.Button(c, "Back to Sign In").FillWidth().Disabled(busy).OnClick(m.CancelTwoFactor)
		})
	}, "Two-step login keeps your vault safe even if your password leaks.")
}
