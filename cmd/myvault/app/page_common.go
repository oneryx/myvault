package app

import (
	"github.com/egoist/mygo/ui"
)

// pageScroll is a scrolling page over the canvas, its content centered in a
// column at most maxWidth wide.
func pageScroll(c *ui.Context, maxWidth float32, gap float32, body func()) {
	ui.Scroll(c).Grow(1).FillWidth().Background(pal(c).Canvas).Children(func() {
		ui.Column(c).FillWidth().Padding(24, 28, 40, 28).Children(func() {
			ui.Column(c).FillWidth().MaxWidth(maxWidth).AlignSelf(ui.Center).Gap(gap).Children(body)
		})
	})
}

// pageOptionRow is a titled row with a control at its end.
func pageOptionRow(c *ui.Context, title, desc string, control func()) {
	p := pal(c)
	ui.Row(c).Gap(16).Padding(10, 16).MinHeight(46).Children(func() {
		ui.Column(c).Grow(1).Shrink(1).Gap(2).Children(func() {
			ui.Text(c, title).FontSize(13).TextColor(p.Fg)
			if desc != "" {
				ui.Text(c, desc).FontSize(11.5).TextColor(p.Fg3)
			}
		})
		control()
	})
}

// pageMetaRow shows a label and its value.
func pageMetaRow(c *ui.Context, title, value string) {
	p := pal(c)
	ui.Row(c).Gap(16).Padding(10, 16).Justify(ui.SpaceBetween).Children(func() {
		ui.Text(c, title).FontSize(13).TextColor(p.Fg).Shrink(0)
		ui.Text(c, value).FontSize(12.5).TextColor(p.Fg2).SingleLine().Shrink(1).TextAlign(ui.End)
	})
}

// pageIconButton is a secondary button with an icon before its label.
func pageIconButton(c *ui.Context, glyph *ui.SVG, text string, primary bool) ui.Element {
	var b ui.Element
	if primary {
		b = ui.PrimaryButton(c, "")
	} else {
		b = ui.Button(c, "")
	}
	return b.Children(func() {
		if glyph != nil {
			ui.Icon(c, glyph).Size(13, 13)
		}
		ui.Text(c, text).SingleLine()
	})
}

// pageSwitch is a switch reading on and reporting a change to set.
func pageSwitch(c *ui.Context, name string, on bool, disabled bool, set func(bool)) {
	v := on
	if ui.Switch(c.Key(name), &v).Label(name).Disabled(disabled).Changed() && set != nil {
		set(v)
	}
}

// pageSelect is a drop-down of labeled int values.
func pageSelect(c *ui.Context, name string, value int, values []int, labels []string, width float32, set func(int)) {
	sel := ""
	for i, v := range values {
		if v == value {
			sel = labels[i]
		}
	}
	if ui.Select(c.Key(name), &sel, labels).Label(name).Width(width).Changed() {
		for i, l := range labels {
			if l == sel {
				set(values[i])
			}
		}
	}
}
