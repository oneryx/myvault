package app

import (
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/egoist/mygo/ui"
	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

// Sizes of the main window.
const (
	MainWindowWidth     = 1100
	MainWindowHeight    = 720
	MainWindowMinWidth  = 900
	MainWindowMinHeight = 560
)

// titleBarHeight is the height of the toolbar under the window controls.
const titleBarHeight = 52

// Palette holds the app's colors for one appearance.
type Palette struct {
	Sidebar, List, Canvas, Card, Panel ui.Color
	Line, LineSoft                     ui.Color
	Fg, Fg2, Fg3                       ui.Color
	Sel, Accent, AccentSoft            ui.Color
	Fill, FillStrong                   ui.Color
	Digit, Symbol, Star                ui.Color
	Danger, Success, Warn, WarnSoft    ui.Color
	Field, FieldBorder, Inset          ui.Color
	White                              ui.Color
}

func rgb(hex uint32) ui.Color { return ui.RGB(uint8(hex>>16), uint8(hex>>8), uint8(hex)) }

func rgba(hex uint32, a float32) ui.Color {
	return ui.RGBA(uint8(hex>>16), uint8(hex>>8), uint8(hex), a)
}

var lightPalette = Palette{
	Sidebar:     rgb(0xeeeef1),
	List:        rgb(0xffffff),
	Canvas:      rgb(0xf5f5f7),
	Card:        rgb(0xffffff),
	Panel:       rgb(0xfbfbfc),
	Line:        rgba(0x000000, 0.09),
	LineSoft:    rgba(0x000000, 0.06),
	Fg:          rgb(0x1d1d1f),
	Fg2:         rgb(0x6e6e73),
	Fg3:         rgb(0x9b9ba1),
	Sel:         rgba(0x000000, 0.075),
	Accent:      rgb(0x175ddc),
	AccentSoft:  rgba(0x175ddc, 0.10),
	Fill:        rgba(0x000000, 0.045),
	FillStrong:  rgba(0x000000, 0.075),
	Digit:       rgb(0x175ddc),
	Symbol:      rgb(0xc4420f),
	Star:        rgb(0xf2a60c),
	Danger:      rgb(0xd93025),
	Success:     rgb(0x1e9e5a),
	Warn:        rgb(0xb86e00),
	WarnSoft:    rgba(0xf2a60c, 0.14),
	Field:       rgb(0xffffff),
	FieldBorder: rgba(0x000000, 0.14),
	Inset:       rgb(0xf0f0f3),
	White:       rgb(0xffffff),
}

var darkPalette = Palette{
	Sidebar:     rgb(0x242427),
	List:        rgb(0x1c1c1e),
	Canvas:      rgb(0x161618),
	Card:        rgb(0x212124),
	Panel:       rgb(0x1f1f22),
	Line:        rgba(0xffffff, 0.085),
	LineSoft:    rgba(0xffffff, 0.06),
	Fg:          rgb(0xf2f2f4),
	Fg2:         rgb(0xa1a1a8),
	Fg3:         rgb(0x6f6f77),
	Sel:         rgba(0xffffff, 0.09),
	Accent:      rgb(0x4c8dff),
	AccentSoft:  rgba(0x4c8dff, 0.17),
	Fill:        rgba(0xffffff, 0.06),
	FillStrong:  rgba(0xffffff, 0.10),
	Digit:       rgb(0x74abff),
	Symbol:      rgb(0xff9f5a),
	Star:        rgb(0xffc23d),
	Danger:      rgb(0xff6b5e),
	Success:     rgb(0x3ccf82),
	Warn:        rgb(0xffb547),
	WarnSoft:    rgba(0xffb547, 0.14),
	Field:       rgb(0x2a2a2e),
	FieldBorder: rgba(0xffffff, 0.12),
	Inset:       rgb(0x2a2a2e),
	White:       rgb(0xffffff),
}

var lightTheme, darkTheme = buildTheme(false), buildTheme(true)

func buildTheme(dark bool) *ui.Theme {
	p, t := &lightPalette, ui.LightTheme()
	hover, pressed := rgb(0x1452c4), rgb(0x1046ab)
	if dark {
		p, t = &darkPalette, ui.DarkTheme()
		hover, pressed = rgb(0x66a0ff), rgb(0x3b7cf0)
	}
	t = t.WithAccent(p.Accent)
	t.Radius = 7
	t.Background, t.Surface = p.List, p.Card
	t.Text, t.TextMuted, t.Border = p.Fg, p.Fg2, p.Line
	t.AccentHover, t.AccentPressed = hover, pressed
	t.Danger, t.Success, t.Warning = p.Danger, p.Success, p.Warn
	t.InactiveAccent = p.Accent
	return t
}

// pal returns the palette of the appearance the window shows.
func pal(c *ui.Context) *Palette {
	if c.Theme().Dark {
		return &darkPalette
	}
	return &lightPalette
}

// applyTheme sets the app's theme for the appearance the system shows. Call
// it first in the view.
func applyTheme(c *ui.Context) {
	if c.Theme().Dark {
		c.SetTheme(darkTheme)
	} else {
		c.SetTheme(lightTheme)
	}
}

var filledStar = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"><path d="M11.525 2.295a.53.53 0 0 1 .95 0l2.31 4.679a2.123 2.123 0 0 0 1.595 1.16l5.166.756a.53.53 0 0 1 .294.904l-3.736 3.638a2.123 2.123 0 0 0-.611 1.878l.882 5.14a.53.53 0 0 1-.771.56l-4.618-2.428a2.122 2.122 0 0 0-1.973 0L6.396 21.01a.53.53 0 0 1-.77-.56l.881-5.139a2.122 2.122 0 0 0-.611-1.879L2.16 9.795a.53.53 0 0 1 .294-.906l5.165-.755a2.122 2.122 0 0 0 1.597-1.16z"/></svg>`))

var shieldMark = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.6 4.6 5.4v5.8c0 4.7 3.1 8.6 7.4 10.2 4.3-1.6 7.4-5.5 7.4-10.2V5.4z" fill="currentColor" fill-opacity="0.18"/><circle cx="12" cy="10.6" r="2.3"/><path d="M12 12.9v3.4"/></svg>`))

// icon shows an SVG icon size DIPs high in color.
func icon(c *ui.Context, svg *ui.SVG, size float32, color ui.Color) ui.Element {
	return ui.Icon(c, svg).Size(size, size).TextColor(color)
}

// label is text in size and color.
func label(c *ui.Context, s string, size float32, color ui.Color) ui.Element {
	return ui.Text(c, s).FontSize(size).TextColor(color)
}

// brandEmblem is the app's mark on a deep-blue squircle.
func brandEmblem(c *ui.Context, size float32) {
	ui.Box(c).Size(size, size).Radius(size*0.28).Center().
		Gradient(rgb(0x3f7dff), rgb(0x1748b8), 160).
		Shadow(0, size*0.12, size*0.36, -size*0.12, rgba(0x1748b8, 0.55)).
		Shadow(0, 0, 0, 0.5, rgba(0x000000, 0.08)).
		Children(func() {
			icon(c, shieldMark, size*0.56, rgb(0xffffff))
		})
}

func typeGlyph(t api.CipherType) *ui.SVG {
	switch t {
	case api.CipherTypeCard:
		return iconCreditCard
	case api.CipherTypeIdentity:
		return iconIdCard
	case api.CipherTypeSecureNote:
		return iconStickyNote
	case api.CipherTypeSSHKey:
		return iconKeyRound
	}
	return nil
}

func typeGlyphOrGlobe(t api.CipherType) *ui.SVG {
	if g := typeGlyph(t); g != nil {
		return g
	}
	return iconGlobe
}

// itemEmblem is the colored badge that identifies an item at a glance.
func itemEmblem(c *ui.Context, name string, t api.CipherType, brand string, size float32) {
	p := paletteFor(name, t, brand)
	ui.Box(c).Size(size, size).Shrink(0).Radius(size*0.26).Center().
		Gradient(rgb(p.top), rgb(p.bottom), 180).
		Shadow(0, 0, 0, 0.5, rgba(0x000000, 0.10)).
		Children(func() {
			if glyph := typeGlyph(t); glyph != nil {
				icon(c, glyph, size*0.52, rgb(0xffffff))
				return
			}
			ui.Text(c, monogram(name)).FontSize(size * 0.46).FontWeight(600).TextColor(rgb(0xffffff)).SingleLine()
		})
}

// iconTile is a sidebar glyph on a small colored squircle.
func iconTile(c *ui.Context, glyph *ui.SVG, color uint32) {
	ui.Box(c).Size(20, 20).Shrink(0).Radius(5.5).Center().Background(rgb(color)).Children(func() {
		icon(c, glyph, 12, rgb(0xffffff))
	})
}

// keycap shows a key of a shortcut.
func keycap(c *ui.Context, s string) {
	p := pal(c)
	ui.Box(c).Height(18).MinWidth(18).Padding(0, 5).Radius(4).Center().
		Background(p.FillStrong).Border(1, p.Line).Children(func() {
		ui.Text(c, s).FontSize(10.5).FontWeight(600).TextColor(p.Fg2).SingleLine()
	})
}

// pill is a small rounded tag.
func pill(c *ui.Context, glyph *ui.SVG, s string) {
	p := pal(c)
	ui.Row(c).Gap(4).Height(20).Padding(0, 8).Radius(999).Background(p.Fill).Children(func() {
		if glyph != nil {
			icon(c, glyph, 11, p.Fg2)
		}
		ui.Text(c, s).FontSize(11.5).FontWeight(500).TextColor(p.Fg2).SingleLine()
	})
}

// card is a rounded group of rows separated by hairlines. rows builds each
// row; nil entries are skipped.
func card(c *ui.Context, rows ...func()) ui.Element {
	p := pal(c)
	return ui.Column(c).Radius(10).Background(p.Card).Border(1, p.Line).Clip().
		Shadow(0, 1, 2, 0, rgba(0x000000, 0.04)).Children(func() {
		first := true
		for _, row := range rows {
			if row == nil {
				continue
			}
			if !first {
				ui.Box(c).Height(1).Margin(0, 0, 0, 16).Background(p.LineSoft)
			}
			first = false
			row()
		}
	})
}

// section is a titled group.
func section(c *ui.Context, title string, body func()) {
	if title == "" {
		body()
		return
	}
	ui.Column(c).Gap(6).Children(func() {
		ui.Text(c, title).FontSize(11.5).FontWeight(600).TextColor(pal(c).Fg2).Padding(0, 4)
		body()
	})
}

// passwordSpans colors the digits and symbols of a revealed secret.
func passwordSpans(c *ui.Context, secret string, size float32, mono bool) []ui.Span {
	p := pal(c)
	font := ""
	if mono {
		font = monoFont
	}
	var spans []ui.Span
	var buf strings.Builder
	color := p.Fg
	flush := func() {
		if buf.Len() > 0 {
			spans = append(spans, ui.Span{Text: buf.String(), Color: color, Size: size, Font: font})
			buf.Reset()
		}
	}
	for _, r := range secret {
		next := p.Fg
		switch {
		case unicode.IsDigit(r):
			next = p.Digit
		case !unicode.IsLetter(r):
			next = p.Symbol
		}
		if next != color {
			flush()
			color = next
		}
		buf.WriteRune(r)
	}
	flush()
	return spans
}

// monoFont is the family of monospaced text.
const monoFont = "monospace"

// avatar is a circle with the initials of an email address.
func avatar(c *ui.Context, email string, size float32) {
	ui.Box(c).Size(size, size).Shrink(0).Radius(size/2).Center().
		Gradient(rgb(0x8e9bb0), rgb(0x5b6678), 160).Children(func() {
		ui.Text(c, initials(email)).FontSize(size * 0.4).FontWeight(600).TextColor(rgb(0xffffff)).SingleLine()
	})
}

// accountMenu lists the accounts on this device to switch to, then adding
// another one and logging out of the current one.
func accountMenu(mn *ui.Menu, m *AppModel) {
	cur := m.Prefs.Get().AccountID
	accts := m.Accounts.Get()
	for _, a := range accts {
		label := a.Email
		if slices.ContainsFunc(accts, func(o state.Account) bool { return o.ID != a.ID && o.Email == a.Email }) {
			label += " (" + hostOf(a.ServerURL) + ")"
		}
		if mn.Item(label).Checked(a.ID == cur).Chosen() {
			m.SwitchAccount(a.ID)
		}
	}
	if len(accts) > 0 {
		mn.Separator()
	}
	if mn.Item("Add Account…").Chosen() {
		m.AddAccount()
	}
	if mn.Item("Log Out…").Chosen() {
		m.Logout(m.Scope)
	}
}

// hostOf is the host of a server address, or the address itself.
func hostOf(server string) string {
	if u, err := url.Parse(server); err == nil && u.Host != "" {
		return u.Host
	}
	return server
}

// errorBanner shows msg in a red box.
func errorBanner(c *ui.Context, msg string) {
	p := pal(c)
	ui.Row(c).AlignItems(ui.Start).Gap(8).Padding(8, 12).Radius(8).
		Background(p.Danger.Alpha(0.10)).Border(1, p.Danger.Alpha(0.25)).Children(func() {
		icon(c, iconTriangleAlert, 13, p.Danger).Margin(1, 0, 0, 0)
		ui.Text(c, msg).FontSize(12).TextColor(p.Danger).Grow(1)
	})
}

// ghostIconButton is a borderless button showing only an icon.
func ghostIconButton(c *ui.Context, name string, glyph *ui.SVG, side, iconSize float32, color ui.Color) ui.Element {
	b := ui.ButtonBase(c).Label(name).Tooltip(name).Size(side, side).Radius(6).Center()
	if b.Hovered() {
		b.Background(pal(c).Fill)
	}
	if b.Pressed() {
		b.Background(pal(c).FillStrong)
	}
	b.Children(func() { icon(c, glyph, iconSize, color) })
	return b
}

// textField is a text input bound to a string signal.
func bindString(get func() string, set func(string), build func(v *string) ui.Element) ui.Element {
	v := get()
	e := build(&v)
	if v != get() {
		set(v)
	}
	return e
}

// fieldInput styles a text input as the app's fields.
func fieldInput(c *ui.Context, e ui.Element, height float32) ui.Element {
	return e.Height(height).FontSize(13).Radius(7)
}

// formField puts a label above a field.
func formField(c *ui.Context, title string, field func()) {
	ui.Column(c).Gap(6).Children(func() {
		ui.Text(c, title).FontSize(12).FontWeight(500).TextColor(pal(c).Fg2)
		field()
	})
}

func eyeIcon(visible bool) *ui.SVG {
	if visible {
		return iconEyeOff
	}
	return iconEye
}
