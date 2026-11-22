package app

import (
	"fmt"
	"slices"
	"strings"

	"github.com/egoist/mygo/ui"
	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/gen"
)

const editorFieldHeight = 28

// editorShowPW reveals the password of the draft being edited.
var editorShowPW struct {
	session uint64
	on      bool
}

var editorTypes = []struct {
	t     api.CipherType
	label string
}{
	{api.CipherTypeLogin, "Login"},
	{api.CipherTypeSecureNote, "Secure Note"},
	{api.CipherTypeCard, "Card"},
	{api.CipherTypeIdentity, "Identity"},
	{api.CipherTypeSSHKey, "SSH Key"},
}

// EditorPaneView edits the draft.
func EditorPaneView(c *ui.Context, m *AppModel) {
	d := m.EditDraft.Get()
	if d == nil {
		return
	}
	p := pal(c)
	busy := m.EditBusy.Get()
	if editorShowPW.session != d.session {
		editorShowPW.session, editorShowPW.on = d.session, false
	}

	ui.Column(c.Key(d.session)).Grow(1).FillHeight().Background(p.Canvas).Children(func() {
		ui.Row(c).Gap(12).Padding(0, 28).Height(60).Shrink(0).BorderWidth(0, 0, 1, 0).BorderColor(p.Line).Children(func() {
			name := d.Name
			if name == "" {
				name = CipherTypeLabel(d.Type)
			}
			itemEmblem(c, name, d.Type, "", 32)
			ui.Column(c).Grow(1).Gap(1).Children(func() {
				title := "Edit " + CipherTypeLabel(d.Type)
				if d.IsNew {
					title = "New " + CipherTypeLabel(d.Type)
				}
				ui.Text(c, title).FontSize(15).FontWeight(600).TextColor(p.Fg).SingleLine()
				status := "No changes"
				if m.EditDirty.Get() {
					status = "Unsaved changes"
				}
				ui.Text(c, status).FontSize(11.5).TextColor(p.Fg3).SingleLine()
			})
			ui.Button(c, "Cancel").Disabled(busy).OnClick(func() { m.CancelEdit(m.Scope) })
			busyButton(c, "Save", busy, true).OnClick(func() { m.SaveDraft(m.Scope) })
		})
		ui.Scroll(c).Grow(1).Children(func() {
			ui.Column(c).FillWidth().MaxWidth(680).Margin(0, ui.Auto).Padding(20, 28, 40, 28).Gap(20).Children(func() {
				if e := m.EditError.Get(); e != "" {
					errorBanner(c, e)
				}
				section(c, "Item", func() {
					var rows []func()
					if d.IsNew {
						rows = append(rows, func() { editorTypeRow(c, m, d, busy) })
					}
					rows = append(rows,
						func() {
							editorRow(c, "Name", func() {
								editorInput(c, m, d, "name", "Required", false, func(d *EditDraft) *string { return &d.Name }).Label("Name")
							})
						},
						func() { editorFolderRow(c, m, d, busy) },
						func() {
							editorSwitchRow(c, "Favorite", d.Favorite, busy || !m.CanFavorite(d.Source), func(v bool) {
								m.MutateDraft(func(d *EditDraft) { d.Favorite = v })
							})
						},
						func() {
							editorSwitchRow(c, "Master password reprompt", d.Reprompt, busy, func(v bool) {
								m.MutateDraft(func(d *EditDraft) { d.Reprompt = v })
							})
						},
					)
					card(c, rows...)
				})
				switch d.Type {
				case api.CipherTypeLogin:
					editorLoginFields(c, m, d, busy)
				case api.CipherTypeCard:
					editorCardFields(c, m, d)
				case api.CipherTypeIdentity:
					editorIdentityFields(c, m, d)
				case api.CipherTypeSSHKey:
					editorSSHKeyFields(c, m, d, busy)
				}
				editorCustomFields(c, m, d, busy)
				section(c, "Notes", func() {
					card(c, func() {
						ui.Box(c).Padding(8).Children(func() {
							notes := d.Notes
							ui.TextArea(c.Key("notes"), &notes).Placeholder("Add a note").Label("Notes").
								MinHeight(96).FontSize(13).Disabled(busy).
								Background(ui.Transparent).Border(0, ui.Transparent)
							if notes != d.Notes {
								m.MutateDraft(func(d *EditDraft) { d.Notes = notes })
							}
						})
					})
				})
			})
		})
	})
}

// editorRow is a labeled row of a card.
func editorRow(c *ui.Context, title string, control func()) {
	ui.Row(c).Gap(12).Padding(8, 16).MinHeight(44).Children(func() {
		ui.Text(c, title).Width(112).Shrink(0).FontSize(12.5).TextColor(pal(c).Fg2)
		ui.Row(c).Grow(1).Gap(8).Children(control)
	})
}

func editorSwitchRow(c *ui.Context, title string, on, disabled bool, set func(bool)) {
	ui.Row(c).Gap(12).Padding(8, 16).MinHeight(44).Children(func() {
		ui.Text(c, title).Grow(1).FontSize(13).TextColor(pal(c).Fg)
		v := on
		if ui.Switch(c.Key(title), &v).Label(title).Disabled(disabled).Changed() {
			set(v)
		}
	})
}

// editorInput is a text input bound to the field of the draft that field
// returns.
func editorInput(c *ui.Context, m *AppModel, d *EditDraft, key, placeholder string, mono bool, field func(*EditDraft) *string) ui.Element {
	v := *field(d)
	in := fieldInput(c, ui.TextInput(c.Key(key), &v), editorFieldHeight).
		Placeholder(placeholder).Label(placeholder).Autocorrect(false).Disabled(m.EditBusy.Get()).Grow(1)
	if mono {
		in.Font(monoFont)
	}
	if v != *field(d) {
		m.MutateDraft(func(d *EditDraft) { *field(d) = v })
	}
	return in
}

func editorTypeRow(c *ui.Context, m *AppModel, d *EditDraft, busy bool) {
	editorRow(c, "Type", func() {
		labels := make([]string, len(editorTypes))
		cur := ""
		for i, t := range editorTypes {
			labels[i] = t.label
			if t.t == d.Type {
				cur = t.label
			}
		}
		sel := cur
		ui.Select(c.Key("type"), &sel, labels).Label("Type").Width(180).Disabled(busy)
		if sel != cur {
			for _, t := range editorTypes {
				if t.label == sel {
					m.MutateDraft(func(d *EditDraft) { d.Type = t.t })
				}
			}
		}
	})
}

func editorFolderRow(c *ui.Context, m *AppModel, d *EditDraft, busy bool) {
	editorRow(c, "Folder", func() {
		labels := []string{"No Folder"}
		ids := []string{""}
		seen := map[string]int{}
		for _, f := range m.Folders.Get() {
			name := f.Name
			if n := seen[f.Name]; n > 0 {
				name = fmt.Sprintf("%s (%d)", f.Name, n+1)
			}
			seen[f.Name]++
			labels = append(labels, name)
			ids = append(ids, f.ID)
		}
		cur := labels[0]
		for i, id := range ids {
			if id == d.FolderID {
				cur = labels[i]
			}
		}
		sel := cur
		ui.Select(c.Key("folder"), &sel, labels).Label("Folder").Width(180).Disabled(busy)
		if sel != cur {
			if i := slices.Index(labels, sel); i >= 0 {
				id := ids[i]
				m.MutateDraft(func(d *EditDraft) { d.FolderID = id })
			}
		}
	})
}

func editorLoginFields(c *ui.Context, m *AppModel, d *EditDraft, busy bool) {
	p := pal(c)
	section(c, "Credentials", func() {
		card(c,
			func() {
				editorRow(c, "Username", func() {
					editorInput(c, m, d, "username", "name@example.com", false, func(d *EditDraft) *string { return &d.Username }).Label("Username")
				})
			},
			func() {
				editorRow(c, "Password", func() {
					ui.Box(c).Grow(1).Children(func() {
						v := d.Password
						in := fieldInput(c, ui.TextInput(c.Key("password"), &v), editorFieldHeight).
							Placeholder("Password").Label("Password").Autocorrect(false).Disabled(busy).
							Font(monoFont).PaddingStart(10).PaddingEnd(62)
						if !editorShowPW.on {
							in.Password()
						}
						if v != d.Password {
							m.MutateDraft(func(d *EditDraft) { d.Password = v })
						}
						ui.Row(c).Absolute().Top(0).Bottom(0).Right(4).Gap(2).Children(func() {
							name := "Show password"
							if editorShowPW.on {
								name = "Hide password"
							}
							if ghostIconButton(c, name, eyeIcon(editorShowPW.on), editorFieldHeight-8, 13, p.Fg3).Disabled(busy).Clicked() {
								editorShowPW.on = !editorShowPW.on
							}
							if ghostIconButton(c, "Generate password", iconWandSparkles, editorFieldHeight-8, 13, p.Accent).Disabled(busy).Clicked() {
								pw := m.GenerateInlinePassword()
								m.MutateDraft(func(d *EditDraft) { d.Password = pw })
							}
						})
					})
				})
			},
			func() {
				editorRow(c, "Authenticator", func() {
					editorInput(c, m, d, "totp", "otpauth:// URI or setup key", true, func(d *EditDraft) *string { return &d.TOTP })
				})
			},
		)
	})
	if len(d.DraftPasskeys()) > 0 {
		editorPasskeyRows(c, m, d, busy)
	}
	section(c, "Websites", func() {
		rows := make([]func(), 0, len(d.URIs)+1)
		for i := range d.URIs {
			rows = append(rows, func() {
				ui.Row(c.Key(fmt.Sprintf("uri-%d", i))).Gap(8).Padding(8, 8, 8, 16).Children(func() {
					icon(c, iconGlobe, 14, p.Fg3)
					editorInput(c, m, d, "uri", "https://example.com", false, func(d *EditDraft) *string {
						if i < len(d.URIs) {
							return &d.URIs[i].URI
						}
						return new(string)
					})
					editorRemoveButton(c, "Remove website", busy, func() {
						m.MutateDraft(func(d *EditDraft) {
							if i < len(d.URIs) {
								d.URIs = slices.Delete(d.URIs, i, i+1)
							}
						})
					})
				})
			})
		}
		rows = append(rows, func() {
			editorAddRow(c, "Add Website", busy, func() {
				m.MutateDraft(func(d *EditDraft) { d.URIs = append(d.URIs, EditURIDraft{}) })
			})
		})
		card(c, rows...)
	})
}

func editorRemoveButton(c *ui.Context, name string, disabled bool, onPress func()) {
	ghostIconButton(c, name, iconX, 24, 12, pal(c).Fg3).Disabled(disabled).OnClick(onPress)
}

func editorAddRow(c *ui.Context, title string, disabled bool, onPress func()) {
	p := pal(c)
	b := ui.ButtonBase(c.Key(title)).Label(title).Gap(8).Padding(0, 16).Height(40).Justify(ui.Start).Disabled(disabled).OnClick(onPress)
	if b.Pressed() {
		b.Background(p.Fill)
	}
	b.Children(func() {
		ui.Box(c).Size(16, 16).Radius(8).Center().Background(p.Accent).Children(func() {
			icon(c, iconPlus, 11, p.White)
		})
		ui.Text(c, title).FontSize(13).FontWeight(500).TextColor(p.Accent)
	})
}

func editorCardFields(c *ui.Context, m *AppModel, d *EditDraft) {
	p := pal(c)
	section(c, "Card Details", func() {
		card(c,
			func() {
				editorRow(c, "Cardholder", func() {
					editorInput(c, m, d, "cardholder", "Name on card", false, func(d *EditDraft) *string { return &d.Cardholder })
				})
			},
			func() {
				editorRow(c, "Brand", func() {
					editorInput(c, m, d, "brand", "Visa, Mastercard, Amex…", false, func(d *EditDraft) *string { return &d.Brand })
				})
			},
			func() {
				editorRow(c, "Number", func() {
					editorInput(c, m, d, "card-number", "1234 5678 9012 3456", true, func(d *EditDraft) *string { return &d.CardNumber })
				})
			},
			func() {
				editorRow(c, "Expiration", func() {
					editorInput(c, m, d, "exp-month", "MM", false, func(d *EditDraft) *string { return &d.ExpMonth })
					ui.Text(c, "/").FontSize(13).TextColor(p.Fg3)
					editorInput(c, m, d, "exp-year", "YYYY", false, func(d *EditDraft) *string { return &d.ExpYear })
				})
			},
			func() {
				editorRow(c, "Security Code", func() {
					editorInput(c, m, d, "card-code", "CVV", true, func(d *EditDraft) *string { return &d.CardCode })
				})
			},
		)
	})
}

func editorIdentityFields(c *ui.Context, m *AppModel, d *EditDraft) {
	in := func(key, placeholder string, field func(*EditDraft) *string) func() {
		return func() { editorInput(c, m, d, key, placeholder, false, field) }
	}
	row := func(title string, fields ...func()) func() {
		return func() {
			editorRow(c, title, func() {
				for _, f := range fields {
					f()
				}
			})
		}
	}
	section(c, "Personal", func() {
		card(c,
			row("Name",
				in("first-name", "First", func(d *EditDraft) *string { return &d.FirstName }),
				in("last-name", "Last", func(d *EditDraft) *string { return &d.LastName })),
			row("Company", in("company", "Company", func(d *EditDraft) *string { return &d.Company })),
			row("Email", in("ident-email", "name@example.com", func(d *EditDraft) *string { return &d.Email })),
			row("Phone", in("ident-phone", "+1 555 0100", func(d *EditDraft) *string { return &d.Phone })),
		)
	})
	section(c, "Address", func() {
		card(c,
			row("Street", in("ident-addr", "123 Main St", func(d *EditDraft) *string { return &d.Address1 })),
			row("City", in("ident-city", "City", func(d *EditDraft) *string { return &d.City })),
			row("State / ZIP",
				in("ident-state", "State", func(d *EditDraft) *string { return &d.State }),
				in("ident-postal", "Postal code", func(d *EditDraft) *string { return &d.PostalCode })),
			row("Country", in("ident-country", "Country", func(d *EditDraft) *string { return &d.Country })),
		)
	})
}

func editorSSHKeyFields(c *ui.Context, m *AppModel, d *EditDraft, busy bool) {
	section(c, "SSH Key", func() {
		card(c,
			func() {
				editorRow(c, "Private Key", func() {
					v := d.SSHPrivate
					ui.TextArea(c.Key("ssh-private"), &v).Placeholder("-----BEGIN OPENSSH PRIVATE KEY-----").
						Label("Private Key").Lines(6, 10).Grow(1).Font(monoFont).FontSize(12).Disabled(busy)
					if v != d.SSHPrivate {
						m.MutateDraft(func(d *EditDraft) {
							d.SSHPrivate = v
							if k, err := gen.InspectSSHPrivateKey(v, sshKeyComment(d)); err == nil {
								d.SSHPublic, d.SSHFinger = k.PublicKey, k.KeyFingerprint
							}
						})
					}
				})
			},
			func() {
				editorRow(c, "Public Key", func() {
					editorInput(c, m, d, "ssh-public", "ssh-ed25519 AAAA…", true, func(d *EditDraft) *string { return &d.SSHPublic })
				})
			},
			func() {
				editorRow(c, "Fingerprint", func() {
					editorInput(c, m, d, "ssh-fingerprint", "SHA256:…", true, func(d *EditDraft) *string { return &d.SSHFinger })
				})
			},
			func() {
				ui.Row(c).Justify(ui.End).Padding(8, 16).Children(func() {
					ui.Button(c, "").Disabled(busy).OnClick(m.GenerateDraftSSHKey).Children(func() {
						ui.Icon(c, iconWandSparkles).Size(13, 13)
						ui.Text(c, "Generate Ed25519 Key").SingleLine()
					})
				})
			},
		)
	})
}

func editorCustomFields(c *ui.Context, m *AppModel, d *EditDraft, busy bool) {
	section(c, "Custom Fields", func() {
		rows := make([]func(), 0, len(d.Fields)+1)
		for i := range d.Fields {
			field := func(d *EditDraft) *EditFieldDraft {
				if i < len(d.Fields) {
					return &d.Fields[i]
				}
				return &EditFieldDraft{}
			}
			rows = append(rows, func() {
				ui.Row(c.Key(fmt.Sprintf("field-%d", i))).Gap(8).Padding(8, 8, 8, 16).Children(func() {
					kinds := []string{"Text", "Hidden"}
					cur := kinds[0]
					if d.Fields[i].Type == 1 {
						cur = kinds[1]
					}
					sel := cur
					ui.Select(c.Key("type"), &sel, kinds).Label("Field type").Width(92).Disabled(busy)
					if sel != cur {
						t := slices.Index(kinds, sel)
						m.MutateDraft(func(d *EditDraft) { field(d).Type = t })
					}
					editorInput(c, m, d, "name", "Field name", false, func(d *EditDraft) *string { return &field(d).Name })
					editorInput(c, m, d, "value", "Value", false, func(d *EditDraft) *string { return &field(d).Value })
					editorRemoveButton(c, "Remove field", busy, func() {
						m.MutateDraft(func(d *EditDraft) {
							if i < len(d.Fields) {
								d.Fields = slices.Delete(d.Fields, i, i+1)
							}
						})
					})
				})
			})
		}
		rows = append(rows, func() {
			editorAddRow(c, "Add Field", busy, func() {
				m.MutateDraft(func(d *EditDraft) { d.Fields = append(d.Fields, EditFieldDraft{Type: 0}) })
			})
		})
		card(c, rows...)
	})
}

// editorPasskeyRows lists the passkeys of the item being edited, each with
// its own remove button, or Undo once removed.
func editorPasskeyRows(c *ui.Context, m *AppModel, d *EditDraft, busy bool) {
	p := pal(c)
	passkeys := d.DraftPasskeys()
	rows := make([]func(), 0, len(passkeys))
	for i := range passkeys {
		rows = append(rows, func() {
			editorRow(c, "Passkey", func() {
				if d.PasskeyRemoved(i) {
					ui.Text(c, "Removed when you save").Grow(1).FontSize(13).TextColor(p.Fg2)
					ui.Button(c.Key(fmt.Sprintf("passkey-undo-%d", i)), "Undo").Disabled(busy).OnClick(func() {
						m.MutateDraft(func(d *EditDraft) {
							d.RemovedPasskeys = slices.DeleteFunc(d.RemovedPasskeys, func(x int) bool { return x == i })
						})
					})
					return
				}
				ui.Text(c, passkeyText(&passkeys[i])).Grow(1).FontSize(13).TextColor(p.Fg).SingleLine()
				ghostIconButton(c.Key(fmt.Sprintf("passkey-remove-%d", i)), "Remove passkey", iconTrash, 24, 13, p.Danger).
					Disabled(busy).OnClick(func() { m.ConfirmRemovePasskey(m.Scope, i) })
			})
		})
	}
	card(c, rows...)
}

func sshKeyComment(d *EditDraft) string {
	return strings.TrimSpace(d.Name)
}

func (m *AppModel) GenerateDraftSSHKey() {
	d := m.EditDraft.Get()
	if d == nil {
		return
	}
	k, err := gen.GenerateEd25519SSHKey(sshKeyComment(d))
	if err != nil {
		m.EditError.Set("Could not generate SSH key: " + err.Error())
		return
	}
	m.MutateDraft(func(d *EditDraft) {
		d.SSHPrivate, d.SSHPublic, d.SSHFinger = k.PrivateKey, k.PublicKey, k.KeyFingerprint
	})
}
