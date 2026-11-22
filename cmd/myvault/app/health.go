package app

import (
	"fmt"

	"github.com/egoist/mygo/ui"
	"github.com/oneryx/myvault/internal/vaultcore/health"
)

func healthCount(r health.Report, c HealthCategory) int {
	switch c {
	case HealthReused:
		return r.ReusedItems()
	case HealthWeak:
		return len(r.Weak)
	case HealthCards:
		return len(r.Cards)
	case HealthUnsecured:
		return len(r.Unsecured)
	case HealthDuplicates:
		return len(r.Duplicates)
	}
	return r.TotalIssues()
}

// SetHealthFilter shows only category c, or every category when c is the
// active one.
func (m *AppModel) SetHealthFilter(c HealthCategory) {
	m.ResetIdleTimer()
	if m.HealthFilter.Get() == c {
		c = HealthAll
	}
	m.HealthFilter.Set(c)
}

// HealthView reports reused and weak passwords, expiring cards, unsecured
// websites and duplicate logins.
func HealthView(c *ui.Context, m *AppModel) {
	p := pal(c)
	r := m.Health.Get()
	filter := m.HealthFilter.Get()
	show := func(cat HealthCategory) bool { return filter == HealthAll || filter == cat }
	pageScroll(c, 680, 20, func() {
		ui.Row(c).Gap(12).AlignItems(ui.Stretch).Children(func() {
			pageHealthTile(c, m, HealthReused, iconRepeat, 0xf08a0a, r.ReusedItems(), "Reused", filter)
			pageHealthTile(c, m, HealthWeak, iconShieldAlert, 0xe5484d, len(r.Weak), "Weak", filter)
			pageHealthTile(c, m, HealthCards, iconCalendarClock, 0xa25ddc, len(r.Cards), "Expiring Cards", filter)
			pageHealthTile(c, m, HealthUnsecured, iconLockOpen, 0x0a84ff, len(r.Unsecured), "Unsecured", filter)
			pageHealthTile(c, m, HealthDuplicates, iconCopy, 0x12a594, len(r.Duplicates), "Duplicates", filter)
		})
		if filter != HealthAll && healthCount(r, filter) == 0 && r.TotalIssues() > 0 {
			ui.Text(c, "No issues in this category.").FontSize(12.5).TextColor(p.Fg2).Padding(0, 4)
		}
		if r.TotalIssues() == 0 {
			card(c, func() {
				ui.Row(c).Gap(12).Padding(16).Children(func() {
					icon(c, iconCircleCheck, 22, p.Success)
					ui.Column(c).Grow(1).Gap(2).Children(func() {
						ui.Text(c, "All clear").FontSize(14).FontWeight(600).TextColor(p.Fg)
						ui.Text(c, "No reused or weak passwords, expiring cards, unsecured websites or duplicate logins.").FontSize(12).TextColor(p.Fg2)
					})
				})
			})
		}
		if show(HealthReused) {
			for i, g := range r.Reused {
				title := ""
				if i == 0 {
					title = "Reused Passwords"
				}
				section(c, title, func() { pageHealthList(c, m, g.Items) })
			}
		}
		if len(r.Weak) > 0 && show(HealthWeak) {
			section(c, "Weak Passwords", func() { pageHealthList(c, m, r.Weak) })
		}
		if len(r.Cards) > 0 && show(HealthCards) {
			items := make([]health.Issue, len(r.Cards))
			for i, ci := range r.Cards {
				items[i] = ci.Issue
			}
			section(c, "Expiring Cards", func() { pageHealthList(c, m, items) })
		}
		if len(r.Unsecured) > 0 && show(HealthUnsecured) {
			section(c, "Unsecured Websites", func() { pageHealthList(c, m, r.Unsecured) })
		}
		if show(HealthDuplicates) {
			for i, g := range r.Duplicates {
				title := ""
				if i == 0 {
					title = "Duplicate Logins"
				}
				header := fmt.Sprintf("%s · %s · %d items", g.Site, g.Username, len(g.Items))
				if g.Username == "" {
					header = fmt.Sprintf("%s · no username · %d items", g.Site, len(g.Items))
				}
				section(c, title, func() {
					ui.Text(c, header).FontSize(12).TextColor(p.Fg2).SingleLine().Padding(0, 4)
					pageHealthList(c, m, g.Items)
				})
			}
		}
		ui.Text(c, "Checked on this device only. Nothing is sent to a server.").FontSize(11.5).TextColor(p.Fg3).Padding(0, 4)
	})
}

func pageHealthTile(c *ui.Context, m *AppModel, cat HealthCategory, glyph *ui.SVG, tint uint32, count int, title string, filter HealthCategory) {
	p := pal(c)
	selected := filter == cat
	b := ui.ButtonBase(c.Key("health-"+string(cat))).Label(title).AccessSelected(selected).
		Grow(1).Basis(0).Column().AlignItems(ui.Start).Gap(6).Padding(12, 14).Radius(10)
	if selected {
		b.Background(p.AccentSoft).Border(1, p.Accent)
	} else {
		b.Background(p.Card).Border(1, p.Line)
		if b.Hovered() {
			b.Background(p.Fill.Over(p.Card))
		}
	}
	b.OnClick(func() { m.SetHealthFilter(cat) }).Children(func() {
		ui.Box(c).Size(24, 24).Radius(6).Center().Background(rgb(tint)).Children(func() {
			icon(c, glyph, 13, p.White)
		})
		countColor := p.Fg
		if count == 0 {
			countColor = p.Fg3
		}
		ui.Text(c, fmt.Sprintf("%d", count)).FontSize(22).FontWeight(600).TextColor(countColor).FontFeatures("tnum")
		ui.Text(c, title).FontSize(12).TextColor(p.Fg2).SingleLine()
	})
}

func pageHealthList(c *ui.Context, m *AppModel, items []health.Issue) {
	p := pal(c)
	rows := make([]func(), len(items))
	for i, issue := range items {
		rows[i] = func() {
			b := ui.ButtonBase(c.Key(issue.CipherID)).Label("Open "+issue.Name).Gap(12).Padding(8, 12, 8, 14).MinHeight(48)
			if b.Pressed() {
				b.Background(p.Fill)
			}
			b.OnClick(func() { m.OpenHealthItem(m.Scope, issue.CipherID) }).Children(func() {
				itemEmblem(c, issue.Name, issue.Type, "", 28)
				ui.Column(c).Grow(1).Shrink(1).Gap(2).Clip().Children(func() {
					ui.Text(c, issue.Name).FontSize(13.5).TextColor(p.Fg).SingleLine()
					ui.Text(c, issue.Subtitle).FontSize(11.5).TextColor(p.Fg3).SingleLine()
				})
				ui.Text(c, issue.Detail).FontSize(12).TextColor(p.Fg2).SingleLine().TextAlign(ui.End)
				icon(c, iconChevronRight, 12, p.Fg3)
			})
		}
	}
	card(c, rows...)
}
