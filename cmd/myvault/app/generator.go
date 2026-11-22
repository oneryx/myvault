package app

import (
	"fmt"
	"math"

	"github.com/egoist/mygo/ui"
	"github.com/oneryx/myvault/internal/vaultcore/gen"
)

type strength struct {
	bits  float64
	label string
	level int
}

func (m *AppModel) generatorStrength() strength {
	p := m.Prefs.Get()
	var bits float64
	if p.GeneratorMode == "passphrase" {
		bits = gen.PassphraseBits(p.PassphraseOpts)
	} else {
		pool := 0
		o := p.PasswordOpts
		if o.Uppercase {
			pool += 26
		}
		if o.Lowercase {
			pool += 26
		}
		if o.Numbers {
			pool += 10
		}
		if o.Special {
			pool += 8
		}
		if o.AvoidAmbiguous && pool > 5 {
			pool -= 5
		}
		if pool > 1 {
			bits = float64(o.Length) * math.Log2(float64(pool))
		}
	}
	switch {
	case bits < 45:
		return strength{bits, "Weak", 1}
	case bits < 64:
		return strength{bits, "Fair", 2}
	case bits < 90:
		return strength{bits, "Strong", 3}
	default:
		return strength{bits, "Very Strong", 4}
	}
}

// GeneratorView makes passwords and passphrases.
func GeneratorView(c *ui.Context, m *AppModel) {
	pageScroll(c, 600, 20, func() {
		pageGeneratorOutput(c, m)
		mode := 0
		if m.Prefs.Get().GeneratorMode == "passphrase" {
			mode = 1
		}
		if ui.Segmented(c.Key("generator-mode-tabs"), &mode, "Password", "Passphrase").FillWidth().FillEqually().Changed() {
			m.UpdatePrefs(func(p UserPrefs) UserPrefs {
				p.GeneratorMode = "password"
				if mode == 1 {
					p.GeneratorMode = "passphrase"
				}
				return p
			})
			m.RegenerateSecret()
		}
		if mode == 1 {
			pagePassphraseOptions(c, m)
		} else {
			pagePasswordOptions(c, m)
		}
	})
}

func pageGeneratorOutput(c *ui.Context, m *AppModel) {
	p := pal(c)
	s := m.generatorStrength()
	levelColor := p.Success
	switch s.level {
	case 1:
		levelColor = p.Danger
	case 2:
		levelColor = p.Warn
	}
	card(c, func() {
		ui.Column(c).Padding(28, 24, 20, 24).Gap(20).Children(func() {
			ui.Column(c).MinHeight(56).AlignItems(ui.Center).Justify(ui.Center).Children(func() {
				ui.RichText(c, passwordSpans(c, m.GenResult.Get(), 20, true)...).
					FontWeight(500).TextAlign(ui.Center).Selectable()
			})
			ui.Column(c).Gap(8).Children(func() {
				ui.Row(c).Gap(4).Children(func() {
					for i := 1; i <= 4; i++ {
						seg := ui.Box(c).Grow(1).Height(4).Radius(2)
						if i <= s.level {
							seg.Background(levelColor)
						} else {
							seg.Background(p.FillStrong)
						}
					}
				})
				ui.Row(c).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, s.label).FontSize(12).FontWeight(600).TextColor(p.Fg)
					ui.Text(c, fmt.Sprintf("≈ %d bits of entropy", int(math.Round(s.bits)))).FontSize(11.5).TextColor(p.Fg3).FontFeatures("tnum")
				})
			})
			ui.Row(c).Gap(8).Children(func() {
				pageIconButton(c, iconRefreshCw, "Regenerate", false).Grow(1).OnClick(m.RegenerateSecret)
				pageIconButton(c, iconCopy, "Copy", true).Grow(1).OnClick(func() {
					m.CopySecretValue("Generated secret", m.GenResult.Get())
				})
			})
		})
	})
}

// pageSliderRow is a slider of whole numbers with its value beside it.
func pageSliderRow(c *ui.Context, title string, value, lo, hi int, set func(int)) {
	p := pal(c)
	ui.Row(c).Gap(16).Padding(12, 16).MinHeight(50).Children(func() {
		ui.Text(c, title).FontSize(13).TextColor(p.Fg).Width(70)
		v := float64(value)
		if ui.StepSlider(c.Key(title), &v, float64(lo), float64(hi), 1).Label(title).Grow(1).Shrink(1).Changed() {
			if n := int(math.Round(v)); n != value {
				set(n)
			}
		}
		ui.Box(c).Size(40, 24).Radius(6).Center().Background(p.Fill).Children(func() {
			ui.Text(c, fmt.Sprintf("%d", value)).FontSize(12.5).FontWeight(600).TextColor(p.Fg).FontFeatures("tnum")
		})
	})
}

func pagePasswordOptions(c *ui.Context, m *AppModel) {
	o := m.Prefs.Get().PasswordOpts
	update := func(fn func(o *gen.PasswordOptions)) {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs { fn(&p.PasswordOpts); return p })
		m.RegenerateSecret()
	}
	toggle := func(title, desc string, on bool, set func(o *gen.PasswordOptions, v bool)) func() {
		return func() {
			pageOptionRow(c, title, desc, func() {
				pageSwitch(c, title, on, false, func(v bool) { update(func(o *gen.PasswordOptions) { set(o, v) }) })
			})
		}
	}
	ui.Column(c).Gap(16).Children(func() {
		card(c, func() {
			pageSliderRow(c, "Length", o.Length, 8, 128, func(n int) { update(func(o *gen.PasswordOptions) { o.Length = n }) })
		})
		section(c, "Characters", func() {
			card(c,
				toggle("Uppercase", "A–Z", o.Uppercase, func(o *gen.PasswordOptions, v bool) { o.Uppercase = v }),
				toggle("Lowercase", "a–z", o.Lowercase, func(o *gen.PasswordOptions, v bool) { o.Lowercase = v }),
				toggle("Numbers", "0–9", o.Numbers, func(o *gen.PasswordOptions, v bool) {
					o.Numbers = v
					if !v {
						o.MinNumbers = 0
					} else if o.MinNumbers == 0 {
						o.MinNumbers = 1
					}
				}),
				toggle("Symbols", "! @ # $ % ^ & *", o.Special, func(o *gen.PasswordOptions, v bool) {
					o.Special = v
					if !v {
						o.MinSpecial = 0
					} else if o.MinSpecial == 0 {
						o.MinSpecial = 1
					}
				}),
				toggle("Avoid ambiguous characters", "Excludes l, 1, I, O and 0", o.AvoidAmbiguous, func(o *gen.PasswordOptions, v bool) { o.AvoidAmbiguous = v }),
			)
		})
	})
}

func pagePassphraseOptions(c *ui.Context, m *AppModel) {
	o := m.Prefs.Get().PassphraseOpts
	update := func(fn func(o *gen.PassphraseOptions)) {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs { fn(&p.PassphraseOpts); return p })
		m.RegenerateSecret()
	}
	toggle := func(title, desc string, on bool, set func(o *gen.PassphraseOptions, v bool)) func() {
		return func() {
			pageOptionRow(c, title, desc, func() {
				pageSwitch(c, title, on, false, func(v bool) { update(func(o *gen.PassphraseOptions) { set(o, v) }) })
			})
		}
	}
	ui.Column(c).Gap(16).Children(func() {
		card(c, func() {
			pageSliderRow(c, "Words", o.NumWords, 3, 12, func(n int) { update(func(o *gen.PassphraseOptions) { o.NumWords = n }) })
		})
		section(c, "Options", func() {
			card(c,
				func() {
					pageOptionRow(c, "Word separator", "Placed between each word", func() {
						sep := o.Separator
						fieldInput(c, ui.TextInput(c.Key("generator-separator"), &sep), 28).
							Placeholder("-").Label("Word separator").Width(64).TextAlign(ui.Center)
						if sep != o.Separator {
							update(func(o *gen.PassphraseOptions) { o.Separator = sep })
						}
					})
				},
				toggle("Capitalize words", "Correct-Horse-Battery", o.Capitalize, func(o *gen.PassphraseOptions, v bool) { o.Capitalize = v }),
				toggle("Include a number", "Appends a digit to one word", o.IncludeNum, func(o *gen.PassphraseOptions, v bool) { o.IncludeNum = v }),
			)
		})
	})
}
