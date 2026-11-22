package app

import (
	"fmt"
	"math"
	"runtime"
	"strings"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

// detailState is the view-only state of the detail pane, for the item it
// shows: which secrets are revealed and whether the password history is
// open. It starts afresh for every item.
var detailState struct {
	id          string
	revealed    map[string]bool
	historyOpen bool
}

func detailSync(id string) {
	if detailState.id != id || detailState.revealed == nil {
		detailState.id = id
		detailState.revealed = map[string]bool{}
		detailState.historyOpen = false
	}
}

// DetailPaneView shows the selected item.
func DetailPaneView(c *ui.Context, m *AppModel) {
	if ids := shellMultiSelected(m); len(ids) > 1 {
		detailSync("")
		detailMultiState(c, m, ids)
		return
	}
	ci := m.ActiveCipher.Get()
	if ci == nil {
		detailSync("")
		detailEmptyState(c)
		return
	}
	detailSync(ci.ID)
	detailContent(c, m, ci)
}

func detailEmptyState(c *ui.Context) {
	p := pal(c)
	ui.Column(c.Key("detail-empty")).Grow(1).FillWidth().AlignItems(ui.Center).Justify(ui.Center).Padding(32).Gap(12).Children(func() {
		ui.Box(c).Opacity(0.9).Margin(0, 0, 4, 0).Children(func() { brandEmblem(c, 56) })
		ui.Text(c, "No Item Selected").FontSize(15).FontWeight(600).TextColor(p.Fg)
		ui.Text(c, "Choose an item from the list to see its details.").FontSize(12.5).TextColor(p.Fg2)
		ui.Row(c).Gap(16).Margin(8, 0, 0, 0).Children(func() {
			detailShortcutHint(c, "F", "Search")
			detailShortcutHint(c, "N", "New Item")
			detailShortcutHint(c, "L", "Lock")
		})
	})
}

// detailMultiState shows how many items are chosen in the list and what
// can be done to them: one column of equal buttons, the destructive one
// last.
func detailMultiState(c *ui.Context, m *AppModel, ids []string) {
	p := pal(c)
	cx := m.Scope
	b := m.bulkSelection(ids)
	off := !m.bulkWritable()
	ui.Column(c.Key("detail-multi")).Grow(1).FillWidth().AlignItems(ui.Center).Justify(ui.Center).Padding(32).Gap(12).Children(func() {
		ui.Box(c).Size(56, 56).Radius(28).Center().Background(p.Fill).Margin(0, 0, 4, 0).Children(func() {
			icon(c, iconLayoutGrid, 24, p.Fg3)
		})
		ui.Text(c, fmt.Sprintf("%d Items Selected", len(ids))).FontSize(15).FontWeight(600).TextColor(p.Fg)
		ui.Column(c).Gap(8).Margin(4, 0, 0, 0).Children(func() {
			button := func(glyph *ui.SVG, text string, n int, press func()) {
				pageIconButton(c, glyph, text, false).Width(220).Disabled(off || n == 0).OnClick(press)
			}
			if b.inTrash {
				button(iconRotateCcw, "Restore", len(b.restorable), func() { m.RestoreItems(ids) })
				button(iconTrash, "Delete Permanently…", len(b.deletable), func() { m.DeleteItemsPermanently(cx, ids) })
				return
			}
			ui.MenuButton(c, "", func(mn *ui.Menu) { shellFolderChoices(mn, m, ids, false) }).
				Label("Move to Folder").Width(220).Disabled(off || len(b.movable) == 0).Children(func() {
				ui.Icon(c, iconFolder).Size(13, 13)
				ui.Text(c, "Move to Folder").SingleLine()
			})
			if len(b.unarchivable) > 0 {
				button(iconArchiveRestore, "Unarchive", len(b.unarchivable), func() { m.ArchiveItems(cx, ids, false) })
			}
			if len(b.unarchivable) < len(b.all) {
				button(iconArchive, "Archive", len(b.archivable), func() { m.ArchiveItems(cx, ids, true) })
			}
			button(iconTrash, "Move to Trash…", len(b.trashable), func() { m.TrashItems(cx, ids) })
		})
		if m.SyncState.Get() == SyncOffline {
			ui.Text(c, "Offline: the items can be viewed, not changed.").FontSize(12).TextColor(p.Fg3)
		} else {
			ui.Text(c, "Or drag them onto a folder in the sidebar.").FontSize(12).TextColor(p.Fg3)
		}
	})
}

func detailShortcutHint(c *ui.Context, key, text string) {
	ui.Row(c).Gap(6).Children(func() {
		if runtime.GOOS == "darwin" {
			keycap(c, "⌘"+key)
		} else {
			keycap(c, "Ctrl+"+key)
		}
		ui.Text(c, text).FontSize(11.5).TextColor(pal(c).Fg3)
	})
}

// detailAction is a ghost icon button of a field row.
func detailAction(c *ui.Context, name string, glyph *ui.SVG, onPress func()) ui.Element {
	return ghostIconButton(c, name, glyph, 28, 14, pal(c).Fg2).OnClick(onPress)
}

// detailField is one labeled value of a card, with its actions on the right.
type detailField struct {
	mono    bool
	accent  bool
	value   string
	spans   []ui.Span
	actions func()
}

func detailFieldRow(c *ui.Context, title string, f detailField) {
	p := pal(c)
	ui.Row(c).Gap(12).Padding(10, 10, 10, 16).MinHeight(52).Children(func() {
		ui.Column(c).Grow(1).Shrink(1).MinWidth(0).Gap(3).Children(func() {
			ui.Text(c, title).FontSize(11.5).FontWeight(500).TextColor(p.Fg2)
			if f.spans != nil {
				ui.RichText(c, f.spans...).Selectable()
				return
			}
			v := ui.Text(c, f.value).FontSize(13.5).TextColor(p.Fg).Selectable()
			if f.mono {
				v.Font(monoFont)
			}
			if f.accent {
				v.TextColor(p.Accent)
			}
		})
		if f.actions != nil {
			ui.Row(c).Gap(2).Children(f.actions)
		}
	})
}

// detailSecretRow is a masked value the user reveals and copies, after the
// item's master password reprompt.
func detailSecretRow(c *ui.Context, m *AppModel, ci *state.Cipher, title, name, value, key, action string, mono bool, copySecret func()) {
	p := pal(c)
	shown := detailState.revealed[key]
	var spans []ui.Span
	switch {
	case !shown:
		spans = []ui.Span{{Text: maskedDots(len(value)), Color: p.Fg2, Size: 13.5, Font: monoFont}}
	case mono:
		spans = passwordSpans(c, value, 13.5, true)
	default:
		spans = []ui.Span{{Text: value, Color: p.Fg, Size: 13.5}}
	}
	detailFieldRow(c, title, detailField{spans: spans, actions: func() {
		detailRevealButton(c, m, ci, "Reveal "+name, shown, action, func(on bool) { detailState.revealed[key] = on })
		detailAction(c, "Copy "+name, iconCopy, copySecret)
	}})
}

// detailRevealButton toggles a secret, asking for the master password
// first where the item needs it.
func detailRevealButton(c *ui.Context, m *AppModel, ci *state.Cipher, name string, shown bool, action string, set func(bool)) {
	detailAction(c, name, eyeIcon(shown), func() {
		if shown {
			set(false)
			return
		}
		m.GateReprompt(m.Scope, ci, "reveal "+action, func() { set(true) })
	})
}

func detailContent(c *ui.Context, m *AppModel, ci *state.Cipher) {
	cx := m.Scope
	isTrash := ci.DeletedDate != nil
	offline := m.SyncState.Get() == SyncOffline
	copyPlain := func(title, v string) func() { return func() { m.CopyPlainValue(title, v) } }
	plain := func(v string) detailField { return detailField{value: v} }

	ui.Scroll(c.Key("detail-view")).Grow(1).FillWidth().Children(func() {
		ui.Column(c).FillWidth().MaxWidth(680).AlignSelf(ui.Center).Padding(24, 28, 32, 28).Gap(20).Children(func() {
			detailHeader(c, m, ci, isTrash, offline)

			if ci.Card != nil {
				detailCardVisual(c, m, ci)
			}

			if l := ci.Login; l != nil {
				var rows []func()
				if l.Username != "" {
					rows = append(rows, func() {
						f := plain(l.Username)
						f.actions = func() { detailAction(c, "Copy username", iconCopy, copyPlain("Username", l.Username)) }
						detailFieldRow(c, "Username", f)
					})
				}
				if l.Password != "" && m.PasswordHidden(ci) {
					rows = append(rows, func() { detailFieldRow(c, "Password", plain("Hidden by your organization")) })
				} else if l.Password != "" {
					rows = append(rows, func() {
						p := pal(c)
						shown := m.RevealPW.Get()
						spans := []ui.Span{{Text: maskedDots(len(l.Password)), Color: p.Fg2, Size: 13.5, Font: monoFont}}
						if shown {
							spans = passwordSpans(c, l.Password, 13.5, true)
						}
						detailFieldRow(c, "Password", detailField{spans: spans, actions: func() {
							detailRevealButton(c, m, ci, "Reveal password", shown, "password", m.RevealPW.Set)
							detailAction(c, "Copy password", iconCopy, func() {
								m.GateReprompt(cx, ci, "copy password", func() { m.CopySecretValue("Password", l.Password) })
							})
						}})
					})
				}
				if strings.TrimSpace(l.TOTP) != "" {
					rows = append(rows, func() { detailTOTPRow(c, m, ci) })
				}
				for i := range l.Fido2Credentials {
					text := passkeyText(&l.Fido2Credentials[i])
					rows = append(rows, func() { detailFieldRow(c, "Passkey", plain(text)) })
				}
				if len(rows) > 0 {
					section(c, "Credentials", func() { card(c, rows...) })
				}

				if len(l.URIs) > 0 {
					var uriRows []func()
					for i, u := range l.URIs {
						uri := u.URI
						title := "Website"
						if len(l.URIs) > 1 {
							title = fmt.Sprintf("Website %d", i+1)
						}
						uriRows = append(uriRows, func() {
							detailFieldRow(c, title, detailField{accent: true, value: uri, actions: func() {
								detailAction(c, "Open website", iconExternalLink, func() { _ = mygo.Shell.OpenExternal(detailURL(uri)) })
								detailAction(c, "Copy website", iconCopy, copyPlain("URL", uri))
							}})
						})
					}
					section(c, "Websites", func() { card(c, uriRows...) })
				}
			}

			if k := ci.SSHKey; k != nil {
				detailSSHKeySection(c, m, ci, k)
			}

			if cd := ci.Card; cd != nil {
				var rows []func()
				if cd.CardholderName != "" {
					rows = append(rows, func() {
						f := plain(cd.CardholderName)
						f.actions = func() { detailAction(c, "Copy cardholder", iconCopy, copyPlain("Cardholder", cd.CardholderName)) }
						detailFieldRow(c, "Cardholder Name", f)
					})
				}
				if cd.Number != "" {
					rows = append(rows, func() {
						shown := m.RevealCard.Get()
						v := maskCardNumber(cd.Number)
						if shown {
							v = cd.Number
						}
						detailFieldRow(c, "Card Number", detailField{mono: true, value: v, actions: func() {
							detailRevealButton(c, m, ci, "Reveal card number", shown, "card", m.RevealCard.Set)
							detailAction(c, "Copy card number", iconCopy, func() {
								m.GateReprompt(cx, ci, "copy card number", func() { m.CopySecretValue("Card number", cd.Number) })
							})
						}})
					})
				}
				if cd.ExpMonth != "" || cd.ExpYear != "" {
					exp := strings.Trim(cd.ExpMonth+" / "+cd.ExpYear, " /")
					rows = append(rows, func() {
						detailFieldRow(c, "Expiration", detailField{mono: true, value: exp, actions: func() {
							detailAction(c, "Copy expiration", iconCopy, copyPlain("Expiration", exp))
						}})
					})
				}
				if cd.Code != "" {
					rows = append(rows, func() {
						detailSecretRow(c, m, ci, "Security Code", "security code", cd.Code, "card-code", "security code", true, func() {
							m.GateReprompt(cx, ci, "copy security code", func() { m.CopySecretValue("Security code", cd.Code) })
						})
					})
				}
				if cd.Brand != "" {
					rows = append(rows, func() { detailFieldRow(c, "Brand", plain(cd.Brand)) })
				}
				if len(rows) > 0 {
					section(c, "Card Details", func() { card(c, rows...) })
				}
			}

			if id := ci.Identity; id != nil {
				detailIdentity(c, m, ci, id, copyPlain)
			}

			if len(ci.Fields) > 0 {
				var rows []func()
				for i, f := range ci.Fields {
					field := f
					key := fmt.Sprintf("field-%d", i)
					switch {
					case field.Type == 1 && m.PasswordHidden(ci):
						rows = append(rows, func() { detailFieldRow(c, field.Name, plain("Hidden by your organization")) })
					case field.Type == 1:
						rows = append(rows, func() {
							detailSecretRow(c, m, ci, field.Name, strings.ToLower(field.Name), field.Value, key, "custom field", true, func() {
								m.GateReprompt(cx, ci, "copy custom field", func() { m.CopySecretValue(field.Name, field.Value) })
							})
						})
					default:
						rows = append(rows, func() {
							f := plain(field.Value)
							f.actions = func() { detailAction(c, "Copy "+field.Name, iconCopy, copyPlain(field.Name, field.Value)) }
							detailFieldRow(c, field.Name, f)
						})
					}
				}
				section(c, "Custom Fields", func() { card(c, rows...) })
			}

			if ci.Login != nil && len(ci.PasswordHistory) > 0 && !m.PasswordHidden(ci) {
				detailPasswordHistory(c, m, ci)
			}

			if strings.TrimSpace(ci.Notes) != "" {
				section(c, "Notes", func() {
					card(c, func() {
						ui.Text(c, ci.Notes).FontSize(13).LineHeight(19.0/13).TextColor(pal(c).Fg).Selectable().Padding(12, 16)
					})
				})
			}

			detailAttachments(c, m, ci)
			detailMetadataFooter(c, m, ci, isTrash, offline)
		})
	})
}

// detailURL gives a website without a scheme one, as browsers do.
func detailURL(uri string) string {
	if strings.Contains(uri, "://") {
		return uri
	}
	return "https://" + uri
}

func detailIdentity(c *ui.Context, m *AppModel, ci *state.Cipher, id *state.Identity, copyPlain func(string, string) func()) {
	cx := m.Scope
	plainRow := func(title, v string) func() {
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return func() {
			detailFieldRow(c, title, detailField{value: v, actions: func() {
				detailAction(c, "Copy "+strings.ToLower(title), iconCopy, copyPlain(title, v))
			}})
		}
	}
	fullName := strings.Join(strings.Fields(strings.Join([]string{id.Title, id.FirstName, id.MiddleName, id.LastName}, " ")), " ")
	personal := detailNonNil(
		plainRow("Full Name", fullName),
		plainRow("Company", id.Company),
		plainRow("Email", id.Email),
		plainRow("Phone", id.Phone),
		plainRow("Username", id.Username),
	)
	if len(personal) > 0 {
		section(c, "Personal", func() { card(c, personal...) })
	}
	street := strings.TrimSpace(id.Address1)
	cityLine := strings.TrimSpace(strings.Join(strings.Fields(strings.Join([]string{id.City + ",", id.State, id.PostalCode}, " ")), " "))
	cityLine = strings.Trim(cityLine, ", ")
	addr := strings.Trim(strings.Join(nonEmpty(street, cityLine, id.Country), "\n"), "\n")
	if addr != "" {
		section(c, "Address", func() {
			card(c, func() {
				detailFieldRow(c, "Address", detailField{value: addr, actions: func() {
					detailAction(c, "Copy address", iconCopy, copyPlain("Address", strings.ReplaceAll(addr, "\n", ", ")))
				}})
			})
		})
	}
	var docs []func()
	if id.SSN != "" {
		docs = append(docs, func() {
			detailSecretRow(c, m, ci, "Social Security Number", "social security number", id.SSN, "ssn", "SSN", false, func() {
				m.GateReprompt(cx, ci, "copy SSN", func() { m.CopySecretValue("SSN", id.SSN) })
			})
		})
	}
	if id.PassportNumber != "" {
		docs = append(docs, func() {
			detailFieldRow(c, "Passport Number", detailField{mono: true, value: id.PassportNumber, actions: func() {
				detailAction(c, "Copy passport number", iconCopy, func() { m.CopySecretValue("Passport", id.PassportNumber) })
			}})
		})
	}
	if id.LicenseNumber != "" {
		docs = append(docs, func() {
			detailFieldRow(c, "License Number", detailField{mono: true, value: id.LicenseNumber, actions: func() {
				detailAction(c, "Copy license number", iconCopy, func() { m.CopySecretValue("License", id.LicenseNumber) })
			}})
		})
	}
	if len(docs) > 0 {
		section(c, "Documents", func() { card(c, docs...) })
	}
}

func detailNonNil(rows ...func()) []func() {
	var out []func()
	for _, r := range rows {
		if r != nil {
			out = append(out, r)
		}
	}
	return out
}

func detailSSHKeySection(c *ui.Context, m *AppModel, ci *state.Cipher, k *state.SSHKey) {
	var rows []func()
	if k.KeyFingerprint != "" {
		rows = append(rows, func() {
			detailFieldRow(c, "Fingerprint", detailField{mono: true, value: k.KeyFingerprint, actions: func() {
				detailAction(c, "Copy fingerprint", iconCopy, func() { m.CopyPlainValue("Fingerprint", k.KeyFingerprint) })
			}})
		})
	}
	if k.PublicKey != "" {
		rows = append(rows, func() {
			detailFieldRow(c, "Public Key", detailField{mono: true, value: k.PublicKey, actions: func() {
				detailAction(c, "Copy public key", iconCopy, func() { m.CopyPlainValue("Public key", k.PublicKey) })
			}})
		})
	}
	if k.PrivateKey != "" && m.PasswordHidden(ci) {
		rows = append(rows, func() { detailFieldRow(c, "Private Key", detailField{value: "Hidden by your organization"}) })
	} else if k.PrivateKey != "" {
		priv := strings.TrimSpace(k.PrivateKey)
		rows = append(rows, func() {
			detailSecretRow(c, m, ci, "Private Key", "private key", priv, "ssh-private", "private key", false, func() {
				m.GateReprompt(m.Scope, ci, "copy private key", func() { m.CopySecretValue("Private key", k.PrivateKey) })
			})
		})
	}
	section(c, "SSH Key", func() { card(c, rows...) })
}

func detailPasswordHistory(c *ui.Context, m *AppModel, ci *state.Cipher) {
	p := pal(c)
	title := fmt.Sprintf("Password History (%d)", len(ci.PasswordHistory))
	open := detailState.historyOpen
	ui.Column(c).Gap(6).Children(func() {
		toggle := ui.ButtonBase(c).Label(title).Expanded(open).AlignSelf(ui.Start).Gap(4).Padding(0, 4)
		toggle.OnClick(func() { detailState.historyOpen = !detailState.historyOpen }).Children(func() {
			ui.Text(c, title).FontSize(11.5).FontWeight(600).TextColor(p.Fg2)
			glyph := iconChevronRight
			if open {
				glyph = iconChevronDown
			}
			icon(c, glyph, 11, p.Fg2)
		})
		if !open {
			return
		}
		rows := make([]func(), 0, len(ci.PasswordHistory))
		for i, h := range ci.PasswordHistory {
			pw := h.Password
			when := "Used until " + h.LastUsedDate.Local().Format("Jan 2, 2006 at 3:04 PM")
			key := fmt.Sprintf("history-%d", i)
			rows = append(rows, func() {
				detailSecretRow(c, m, ci, when, "old password", pw, key, "old password", true, func() {
					m.GateReprompt(m.Scope, ci, "copy old password", func() { m.CopySecretValue("Old password", pw) })
				})
			})
		}
		card(c, rows...)
	})
}

func detailHeader(c *ui.Context, m *AppModel, ci *state.Cipher, isTrash, offline bool) {
	cx := m.Scope
	p := pal(c)
	readOnly := m.CipherReadOnly(ci)
	editLocked := offline || readOnly || m.PasswordHidden(ci)

	ui.Row(c).Gap(16).Padding(0, 0, 4, 0).Children(func() {
		siteEmblem(c, m, cipherURIs(ci), ci.Name, ci.Type, cipherBrand(ci), 56)
		ui.Column(c).Grow(1).Shrink(1).MinWidth(0).Gap(6).Children(func() {
			ui.Text(c, ci.Name).FontSize(21).FontWeight(600).TextColor(p.Fg).SingleLine()
			ui.Row(c).Gap(6).Wrap().Children(func() {
				pill(c, typeGlyphOrGlobe(ci.Type), CipherTypeLabel(ci.Type))
				if ci.FolderID != nil && *ci.FolderID != "" {
					for _, f := range m.Folders.Get() {
						if f.ID == *ci.FolderID {
							pill(c, iconFolder, f.Name)
							break
						}
					}
				}
				if org := m.OrganizationName(ci.OrganizationID); org != "" {
					pill(c, iconBuilding, org)
				}
				for _, col := range m.cipherCollections(ci) {
					pill(c, iconLibrary, col.Name)
				}
				if readOnly {
					pill(c, iconEye, "View only")
				}
				if ci.Reprompt == 1 {
					pill(c, iconShieldCheck, "Password reprompt")
				}
				if isTrash {
					pill(c, iconTrash, "In Trash")
				}
				if ci.ArchivedDate != nil {
					pill(c, iconArchive, "Archived")
				}
			})
		})
		ui.Row(c).Gap(8).Children(func() {
			switch {
			case isTrash && readOnly:
			case isTrash:
				ui.Button(c, "Delete Permanently").Disabled(offline).OnClick(func() { m.HardDeleteActive(cx) })
				ui.PrimaryButton(c, "").Disabled(offline).OnClick(m.RestoreActive).Children(func() {
					ui.Icon(c, iconRotateCcw).Size(13, 13)
					ui.Text(c, "Restore").SingleLine()
				})
			default:
				star, starColor := iconStar, p.Fg2
				if ci.Favorite {
					star, starColor = filledStar, p.Star
				}
				ghostIconButton(c, "Toggle favorite", star, 28, 16, starColor).
					Disabled(offline || readOnly || !m.CanFavorite(ci)).OnClick(m.ToggleFavorite)
				if ci.ArchivedDate != nil {
					ghostIconButton(c, "Unarchive", iconArchiveRestore, 28, 15, p.Fg2).
						Disabled(!m.CanUnarchiveItem(ci)).OnClick(func() { m.ArchiveActive(cx, false) })
				} else {
					ghostIconButton(c, "Archive", iconArchive, 28, 15, p.Fg2).
						Disabled(!m.CanArchiveItem(ci)).OnClick(func() { m.ArchiveActive(cx, true) })
				}
				ghostIconButton(c, "Clone item", iconCopyPlus, 28, 15, p.Fg2).
					Disabled(!m.CanClone(ci)).OnClick(func() { m.CloneActive(cx) })
				ui.Button(c, "").Disabled(editLocked).OnClick(func() { m.StartEditCipher(cx) }).Children(func() {
					ui.Icon(c, iconPencil).Size(13, 13)
					ui.Text(c, "Edit").SingleLine()
				})
			}
		})
	})
}

func detailTOTPRow(c *ui.Context, m *AppModel, ci *state.Cipher) {
	cx := m.Scope
	p := pal(c)
	rem, period := m.TOTPRemaining.Get(), m.TOTPPeriod.Get()
	urgent := rem > 0 && rem <= 5
	tint := p.Accent
	if urgent {
		tint = p.Danger
	}
	code := m.TOTPCode.Get()
	hidden := ci.Reprompt == 1 && m.TOTPRevealedID.Get() != ci.ID
	text := "––– –––"
	switch {
	case code == "":
	case hidden:
		text = strings.Repeat("•", len(code)/2) + " " + strings.Repeat("•", len(code)-len(code)/2)
	default:
		text = FormatTOTPCode(code)
	}
	frac := float32(0)
	if period > 0 {
		frac = float32(rem) / float32(period)
	}

	ui.Row(c).Gap(12).Padding(10, 10, 10, 16).MinHeight(60).Children(func() {
		ui.Column(c).Grow(1).Gap(3).Children(func() {
			ui.Text(c, "Verification Code").FontSize(11.5).FontWeight(500).TextColor(p.Fg2)
			ui.Row(c).Gap(12).Children(func() {
				ui.Text(c, text).FontSize(22).FontWeight(600).Font(monoFont).LetterSpacing(1).TextColor(tint).Selectable()
				ui.Row(c).Gap(6).Children(func() {
					ui.Box(c).Size(16, 16).Label("Time remaining").Draw(func(pt *ui.Painter, r ui.Rect) {
						detailRing(pt, r, frac, p.FillStrong, tint)
					})
					if rem > 0 {
						ui.Text(c, fmt.Sprintf("%ds", rem)).FontSize(12).TextColor(p.Fg2).FontFeatures("tnum")
					}
				})
			})
		})
		ui.Row(c).Gap(2).Children(func() {
			if ci.Reprompt == 1 {
				shown := m.TOTPRevealedID.Get() == ci.ID
				detailAction(c, "Reveal verification code", eyeIcon(shown), func() {
					if shown {
						m.TOTPRevealedID.Set("")
						return
					}
					id := ci.ID
					m.GateReprompt(cx, ci, "reveal verification code", func() {
						if cur := m.ActiveCipher.Get(); cur != nil && cur.ID == id {
							m.TOTPRevealedID.Set(id)
						}
					})
				})
			}
			detailAction(c, "Copy verification code", iconCopy, func() {
				m.GateReprompt(cx, ci, "copy TOTP code", func() {
					if code := m.TOTPCode.Get(); code != "" {
						m.CopySecretValue("TOTP code", code)
					}
				})
			})
		})
	})
}

// detailRing draws a countdown ring: a track, and the part of it left.
func detailRing(pt *ui.Painter, r ui.Rect, frac float32, track, fill ui.Color) {
	const width = 2.2
	cx, cy := r.X+r.W/2, r.Y+r.H/2
	rad := min(r.W, r.H)/2 - width/2
	arc := func(from, to float32) [][2]float32 {
		n := max(2, int(48*(to-from))+1)
		pts := make([][2]float32, 0, n+1)
		for i := 0; i <= n; i++ {
			a := float64(from+(to-from)*float32(i)/float32(n))*2*math.Pi - math.Pi/2
			pts = append(pts, [2]float32{cx + rad*float32(math.Cos(a)), cy + rad*float32(math.Sin(a))})
		}
		return pts
	}
	pt.StrokePolyline(arc(0, 1), width, track)
	if frac > 0 {
		pt.StrokePolyline(arc(1-frac, 1), width, fill)
	}
}

func detailCardVisual(c *ui.Context, m *AppModel, ci *state.Cipher) {
	cd := ci.Card
	pl := paletteFor(ci.Name, ci.Type, cd.Brand)
	brand := strings.ToUpper(cd.Brand)
	if brand == "" {
		brand = "CARD"
	}
	exp := ""
	if cd.ExpMonth != "" || cd.ExpYear != "" {
		yr := cd.ExpYear
		if len(yr) == 4 {
			yr = yr[2:]
		}
		exp = cd.ExpMonth + "/" + yr
	}
	number := maskCardNumber(cd.Number)
	if m.RevealCard.Get() {
		number = cd.Number
	}
	white := rgb(0xffffff)
	caption := func(s string) {
		ui.Text(c, s).FontSize(9).FontWeight(600).TextColor(rgba(0xffffff, 0.65)).LetterSpacing(0.8)
	}
	ui.Row(c).Justify(ui.Center).Padding(4, 0).Children(func() {
		ui.Column(c).Size(320, 196).Padding(20).Radius(16).Justify(ui.SpaceBetween).
			Gradient(rgb(pl.top), rgb(pl.bottom), 160).
			Shadow(0, 14, 30, -12, rgba(pl.bottom, 0.6)).
			Shadow(0, 0, 0, 0.5, rgba(0x000000, 0.12)).
			Children(func() {
				ui.Box(c).Absolute().Top(0).Left(0).Right(0).Bottom(0).Radius(16).PassThrough().
					Gradient(rgba(0xffffff, 0.18), rgba(0xffffff, 0), 135)
				ui.Row(c).Justify(ui.SpaceBetween).Children(func() {
					ui.Box(c).Size(36, 27).Radius(5).Gradient(rgb(0xf6dd9a), rgb(0xc79a3c), 135).
						Shadow(0, 0, 0, 0.5, rgba(0x000000, 0.2))
					ui.Text(c, brand).FontSize(17).FontWeight(700).TextColor(white).LetterSpacing(1.2).SingleLine()
				})
				ui.Text(c, number).Font(monoFont).FontSize(17).TextColor(white).LetterSpacing(1).SingleLine()
				ui.Row(c).AlignItems(ui.End).Justify(ui.SpaceBetween).Children(func() {
					ui.Column(c).Gap(2).Children(func() {
						caption("CARDHOLDER")
						ui.Text(c, strings.ToUpper(cd.CardholderName)).FontSize(12.5).FontWeight(500).TextColor(white).LetterSpacing(0.6).SingleLine()
					})
					ui.Column(c).Gap(2).AlignItems(ui.End).Children(func() {
						caption("EXPIRES")
						ui.Text(c, exp).Font(monoFont).FontSize(12.5).TextColor(white).SingleLine()
					})
				})
			})
	})
}

func detailAttachments(c *ui.Context, m *AppModel, ci *state.Cipher) {
	cx := m.Scope
	canModify := m.CanModifyAttachments(ci)
	if len(ci.Attachments) == 0 && !canModify {
		return
	}
	p := pal(c)
	busy := m.AttachmentBusy.Get()
	rows := make([]func(), 0, len(ci.Attachments)+1)
	for _, a := range ci.Attachments {
		att := a
		rows = append(rows, func() {
			ui.Row(c.Key("detail-attachment-"+att.ID)).Gap(12).Padding(8, 10, 8, 16).MinHeight(48).Children(func() {
				icon(c, iconPaperclip, 14, p.Fg3)
				ui.Column(c).Grow(1).Shrink(1).MinWidth(0).Gap(2).Children(func() {
					ui.Text(c, att.FileName).FontSize(13.5).TextColor(p.Fg).SingleLine()
					ui.Text(c, attachmentSizeLabel(att)).FontSize(11.5).TextColor(p.Fg3).FontFeatures("tnum")
				})
				ui.Row(c).Gap(2).Children(func() {
					if m.CanDownloadAttachments(ci) {
						if busy == att.ID {
							ui.Box(c).Size(28, 28).Center().Children(func() { ui.Spinner(c).Size(14, 14) })
						} else {
							detailAction(c, "Download "+att.FileName, iconDownload, func() { m.DownloadAttachment(cx, ci, att) })
						}
					}
					if canModify {
						detailAction(c, "Delete "+att.FileName, iconTrash, func() { m.DeleteAttachment(cx, ci, att) })
					}
				})
			})
		})
	}
	if canModify {
		rows = append(rows, func() {
			ui.Row(c).Padding(6, 10).Children(func() {
				uploading := busy == attachmentUploadBusy
				b := ui.ButtonBase(c).Label("Attach File").Height(26).Padding(0, 8).Gap(6).Radius(6).Disabled(uploading)
				if b.Hovered() {
					b.Background(p.Fill)
				}
				b.OnClick(func() { m.AttachFile(cx, ci) }).Children(func() {
					if uploading {
						ui.Spinner(c).Size(13, 13)
					} else {
						icon(c, iconPlus, 13, p.Accent)
					}
					ui.Text(c, "Attach File").FontSize(12.5).FontWeight(500).TextColor(p.Accent)
				})
			})
		})
	}
	section(c, "Attachments", func() { card(c, rows...) })
}

func detailMetadataFooter(c *ui.Context, m *AppModel, ci *state.Cipher, isTrash, offline bool) {
	p := pal(c)
	ui.Row(c).Padding(4, 4, 0, 4).Children(func() {
		ui.Column(c).Grow(1).Gap(2).Children(func() {
			if ci.RevisionDate != nil {
				ui.Text(c, "Updated "+ci.RevisionDate.Local().Format("Jan 2, 2006 at 3:04 PM")).FontSize(11.5).TextColor(p.Fg3)
			}
			if ci.CreationDate != nil {
				ui.Text(c, "Created "+ci.CreationDate.Local().Format("Jan 2, 2006")).FontSize(11.5).TextColor(p.Fg3)
			}
			if isTrash && ci.DeletedDate != nil {
				ui.Text(c, "Deleted "+formatRelativeTime(*ci.DeletedDate)).FontSize(11.5).TextColor(p.Fg3)
			}
		})
		if !isTrash && !m.CipherReadOnly(ci) {
			b := ui.ButtonBase(c).Label("Move to Trash").Height(26).Padding(0, 10).Gap(6).Radius(6).Disabled(offline)
			if b.Hovered() || b.Pressed() {
				b.Background(p.Danger.Alpha(0.10))
			}
			b.OnClick(func() {
				if !offline {
					m.SoftDeleteActive()
				}
			}).Children(func() {
				icon(c, iconTrash, 13, p.Danger)
				ui.Text(c, "Move to Trash").FontSize(12).FontWeight(500).TextColor(p.Danger)
			})
		}
	})
}
