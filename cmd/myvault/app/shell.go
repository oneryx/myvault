package app

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/egoist/mygo/ui"
	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

// View state of the shell that lasts from frame to frame.
var (
	shellList         ui.ListState
	shellSelection    ui.Selection[string]
	shellSelRow       = -1
	shellListSelected string
)

// UnlockedShellView is the unlocked window: toolbar, sidebar, list and the
// pages of the other routes.
func UnlockedShellView(c *ui.Context, m *AppModel) {
	p := pal(c)
	shellW, _ := c.Size()
	if sw, lw := ClampPaneWidths(m.SidebarW.Get(), m.ListW.Get(), shellW); sw != m.SidebarW.Get() || lw != m.ListW.Get() {
		m.SidebarW.Set(sw)
		m.ListW.Set(lw)
	}
	ui.Row(c).Fill().AlignItems(ui.Stretch).Background(p.List).Children(func() {
		shellSidebar(c, m)
		shellPaneHandle(c, m, func(dx float32) {
			sw, _ := ClampPaneWidths(m.SidebarW.Get()+dx, m.ListW.Get(), shellW)
			m.SidebarW.Set(sw)
		}, func() {
			sw, _ := ClampPaneWidths(DefaultSidebarWidth, m.ListW.Get(), shellW)
			m.SidebarW.Set(sw)
		})
		ui.Column(c).Grow(1).Basis(0).Clip().Children(func() {
			shellToolbar(c, m)
			if m.SyncState.Get() == SyncAuthExpired || m.CredentialsNotSaved.Get() {
				shellSignInBanner(c, m)
			}
			page := map[MainRoute]func(*ui.Context, *AppModel){
				RouteGenerator: GeneratorView,
				RouteSettings:  SettingsView,
				RouteHealth:    HealthView,
				RouteImport:    ImportView,
			}[m.Route.Get()]
			if page == nil {
				shellSplitPanes(c, m, shellW)
				return
			}
			ui.Column(c.Key(m.Route.Get())).Grow(1).Basis(0).Clip().Children(func() { page(c, m) })
		})
	})
}

func shellSignInBanner(c *ui.Context, m *AppModel) {
	p := pal(c)
	ui.Row(c).Gap(12).Padding(8, 16).Background(p.WarnSoft).BorderWidth(0, 0, 1, 0).BorderColor(p.Line).Children(func() {
		icon(c, iconTriangleAlert, 14, p.Warn)
		msg := "Your sign-in could not be saved. Sign in again so MyVault can still sync after you lock."
		switch {
		case m.LocalOnly.Get():
			msg = "Sign in again to sync. Your vault is available offline until then."
		case m.SyncState.Get() == SyncAuthExpired:
			msg = "Session expired — your cached vault is still readable. Sign in again to resume syncing."
		}
		ui.Text(c, msg).FontSize(12).TextColor(p.Fg).Grow(1)
		ui.Button(c, "Sign In Again").FontSize(12).OnClick(m.SignInAgain)
	})
}

// shellPaneHandle is a divider the user drags to resize the pane before it.
func shellPaneHandle(c *ui.Context, m *AppModel, drag func(dx float32), reset func()) {
	p := pal(c)
	ui.Box(c).Width(1).FillHeight().Background(p.Line).Children(func() {
		h := ui.Box(c).Absolute().Top(0).Bottom(0).Left(-3).Width(7).Cursor(ui.CursorResizeColumn).
			Label("Resize pane").ZIndex(10)
		if dx, _, ok := h.Dragged(); ok && dx != 0 {
			drag(dx)
		}
		if _, _, ok := h.DragEnded(); ok {
			m.PersistPaneWidths()
		}
		if h.DoubleClicked() {
			reset()
			m.PersistPaneWidths()
		}
	})
}

func shellSplitPanes(c *ui.Context, m *AppModel, shellW float32) {
	p := pal(c)
	ui.Row(c).Grow(1).AlignItems(ui.Stretch).Clip().Children(func() {
		shellListPane(c, m)
		shellPaneHandle(c, m, func(dx float32) {
			_, lw := ClampPaneWidths(m.SidebarW.Get(), m.ListW.Get()+dx, shellW)
			m.ListW.Set(lw)
		}, func() {
			_, lw := ClampPaneWidths(m.SidebarW.Get(), DefaultListWidth, shellW)
			m.ListW.Set(lw)
		})
		ui.Column(c).Grow(1).Basis(0).Background(p.Canvas).Clip().Children(func() {
			if m.EditMode.Get() {
				EditorPaneView(c, m)
			} else {
				DetailPaneView(c, m)
			}
		})
	})
}

// shellKeyLabel is how the platform writes Cmd (or Ctrl) with key.
func shellKeyLabel(key string) string {
	if runtime.GOOS == "darwin" {
		return "⌘" + key
	}
	return "Ctrl+" + key
}

// shellToolButton is a borderless toolbar button showing an icon.
func shellToolButton(c *ui.Context, name string, glyph *ui.SVG, side, size float32, disabled bool, onClick func()) ui.Element {
	p := pal(c)
	color := p.Fg2
	if disabled {
		color = p.Fg3.Alpha(0.6)
	}
	return ghostIconButton(c, name, glyph, side, size, color).Disabled(disabled).OnClick(onClick)
}

func shellToolbar(c *ui.Context, m *AppModel) {
	p := pal(c)
	cx := m.Scope
	bar := c.TitleBar()
	ui.Row(c).Height(titleBarHeight).Shrink(0).Gap(12).Padding(0, 12+bar.Right, 0, 12).
		Background(p.List).BorderWidth(0, 0, 1, 0).BorderColor(p.Line).DragWindow().Children(func() {
		ui.Row(c).Gap(2).Children(func() {
			shellToolButton(c, "Back", iconChevronLeft, 26, 15, !m.CanGoBack.Get(), func() { m.GoBack(cx) })
			shellToolButton(c, "Forward", iconChevronRight, 26, 15, !m.CanGoForward.Get(), func() { m.GoForward(cx) })
		})
		ui.Row(c).AlignItems(ui.Baseline).Gap(8).Shrink(1).MinWidth(0).Children(func() {
			ui.Text(c, m.filterTitle()).FontSize(15).FontWeight(600).TextColor(p.Fg).SingleLine()
			if m.Route.Get() == RouteVault {
				n := m.FilteredItems.Len()
				s := fmt.Sprintf("%d items", n)
				if n == 1 {
					s = "1 item"
				}
				ui.Text(c, s).FontSize(12).TextColor(p.Fg3).SingleLine().FontFeatures("tnum")
				shellSortButton(c, m)
			}
		})
		ui.Spacer(c)
		ui.Box(c).Grow(1).Shrink(1).MinWidth(260).MaxWidth(400).Children(func() {
			shellSearchField(c, m)
		})
		ui.Row(c).Gap(4).Children(func() {
			if m.SyncState.Get() == SyncOffline {
				ui.Row(c).Gap(6).Height(22).Padding(0, 8).Margin(0, 4, 0, 0).Radius(999).Background(p.WarnSoft).Children(func() {
					icon(c, iconCloudOff, 12, p.Warn)
					ui.Text(c, "Offline").FontSize(11.5).FontWeight(500).TextColor(p.Warn).SingleLine()
				})
			}
			syncing := m.SyncState.Get() == SyncInProgress
			sync := shellToolButton(c, "Sync now", iconRefreshCw, 30, 16, syncing, func() { m.SyncNow(false) })
			if syncing {
				sync.Busy(true)
			}
			shellToolButton(c, "Lock vault", iconLock, 30, 16, false, m.Lock)
			ui.Box(c).Width(1).Height(18).Margin(0, 6).Background(p.Line)
			ui.PrimaryButton(c, "").Disabled(m.SyncState.Get() == SyncOffline).
				OnClick(func() { m.StartCreateCipher(cx) }).Children(func() {
				ui.Icon(c, iconPlus).Size(14, 14)
				ui.Text(c, "New Item").SingleLine()
			})
		})
	})
}

// shellSortButton chooses the order of the vault list, which every view and
// search keeps.
func shellSortButton(c *ui.Context, m *AppModel) {
	p := pal(c)
	cur := m.Prefs.Get().ListSort
	ui.MenuButton(c, "", func(mn *ui.Menu) {
		for _, s := range listSorts {
			if mn.Item(s.Label).Checked(s.Sort == cur).Chosen() {
				m.SetListSort(s.Sort)
			}
		}
	}).Label("Sort items").Size(22, 22).Padding(0).Radius(5).Background(ui.Transparent).Border(0, ui.Transparent).
		NoShadow().Children(func() { icon(c, iconArrowUpDown, 13, p.Fg3) })
}

func shellSearchField(c *ui.Context, m *AppModel) {
	p := pal(c)
	box := ui.Row(c).Gap(6).Height(30).Padding(0, 6, 0, 10).Radius(8).Cursor(ui.CursorText)
	focused := m.SearchRef.Handle.FocusWithin(c)
	if focused {
		box.Background(p.Card).Border(1, p.Accent).Shadow(0, 0, 0, 3, p.Accent.Alpha(0.22))
	} else {
		box.Background(p.Fill).Border(1, ui.Transparent)
	}
	box.Children(func() {
		icon(c, iconSearch, 13, p.Fg3)
		q := m.SearchQuery.Get()
		in := ui.TextInputBase(c.Key("vault-search"), &q).Grow(1).FontSize(13).TextColor(p.Fg).
			Placeholder("Search vault").PlaceholderColor(p.Fg3).CaretColor(p.Accent).
			Label("Search vault").Autocorrect(false).Bind(&m.SearchRef.Handle)
		if q != m.SearchQuery.Get() {
			m.SetSearchQuery(q)
		}
		if q == "" {
			keycap(c, shellKeyLabel("F"))
		} else {
			if ghostIconButton(c, "Clear search", iconCircleX, 20, 13, p.Fg3).Clicked() {
				m.SetSearchQuery("")
			}
			if in.Focused() && c.Shortcut(0, ui.KeyEscape) {
				m.SetSearchQuery("")
			}
		}
	})
}

type shellEntry struct {
	label  string
	glyph  *ui.SVG
	tint   uint32
	count  int
	counts bool
	badge  bool
	active bool
	press  func()
	// folderDrop makes the row take items dropped on it into this folder,
	// "" for No Folder.
	folderDrop *string
}

func shellSidebar(c *ui.Context, m *AppModel) {
	p := pal(c)
	cx := m.Scope
	route := m.Route.Get()
	filter := m.SidebarFilter.Get()
	counts := m.AllCounts.Get()
	inVault := func(match bool) bool { return route == RouteVault && match }
	typeEntry := func(label string, t api.CipherType, glyph *ui.SVG, tint uint32, n int) shellEntry {
		return shellEntry{
			label: label, glyph: glyph, tint: tint, count: n, counts: true,
			active: inVault(filter.Type != nil && *filter.Type == t),
			press:  func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll, Type: &t}) },
		}
	}
	goRoute := func(r MainRoute) func() {
		return func() {
			m.GuardDirty(cx, func() {
				m.ResetIdleTimer()
				m.Route.Set(r)
			})
		}
	}
	offline := m.SyncState.Get() == SyncOffline

	ui.Column(c).Width(m.SidebarW.Get()).Shrink(0).Background(p.Sidebar).Children(func() {
		ui.Box(c).Height(titleBarHeight).Shrink(0).FillWidth().DragWindow()
		ui.Column(c).Padding(0, 10, 6, 10).Gap(1).Children(func() {
			shellRow(c, m, shellEntry{
				label: "All Items", glyph: iconLayoutGrid, tint: 0x2f6fe4, count: counts.All, counts: true,
				active: inVault(IsAllItemsFilter(filter)),
				press:  func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll}) },
			})
			shellRow(c, m, shellEntry{
				label: "Favorites", glyph: iconStar, tint: 0xf0a20b, count: counts.Favorites, counts: true,
				active: inVault(filter.Category == state.FilterFavorites),
				press:  func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterFavorites}) },
			})
		})
		ui.Scroll(c.Key("sidebar-scroll")).Grow(1).Basis(0).Children(func() {
			ui.Column(c).Padding(0, 10, 12, 10).Gap(1).Children(func() {
				shellHeader(c, "Categories")
				shellRow(c, m, typeEntry("Logins", api.CipherTypeLogin, iconGlobe, 0x0a84ff, counts.Login))
				shellRow(c, m, typeEntry("Cards", api.CipherTypeCard, iconCreditCard, 0x2fb35a, counts.Card))
				shellRow(c, m, typeEntry("Identities", api.CipherTypeIdentity, iconIdCard, 0xa25ddc, counts.Identity))
				shellRow(c, m, typeEntry("Secure Notes", api.CipherTypeSecureNote, iconStickyNote, 0xf08a0a, counts.SecureNote))
				shellRow(c, m, typeEntry("SSH Keys", api.CipherTypeSSHKey, iconKeyRound, 0x6b7a90, counts.SSHKey))

				prefs := m.Prefs.Get()
				shellCollapsibleHeader(c, "Folders", prefs.FoldersCollapsed, len(m.Folders.Get()), func() {
					m.UpdatePrefs(func(p UserPrefs) UserPrefs {
						p.FoldersCollapsed = !p.FoldersCollapsed
						return p
					})
				}, func() {
					if shellToolButton(c, "New Folder", iconPlus, 20, 13, offline, m.OpenNewFolderModal).Clicked() {
						return
					}
				})
				if !prefs.FoldersCollapsed {
					for _, f := range m.Folders.Get() {
						shellFolderRow(c.Key(f.ID), m, f, route == RouteVault && filter.FolderID == f.ID, counts.ByFolder[f.ID], offline)
					}
					shellRow(c, m, shellEntry{
						label: "No Folder", glyph: iconFolder, count: counts.NoFolder, counts: true, folderDrop: new(string),
						active: inVault(filter.Category == state.FilterNoFolder),
						press:  func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterNoFolder}) },
					})
				}
				if cols := m.Collections.Get(); len(cols) > 0 {
					shellCollapsibleHeader(c, "Collections", prefs.CollectionsCollapsed, len(cols), func() {
						m.UpdatePrefs(func(p UserPrefs) UserPrefs {
							p.CollectionsCollapsed = !p.CollectionsCollapsed
							return p
						})
					}, nil)
					if !prefs.CollectionsCollapsed {
						shellCollections(c, m, cols, filter, route, counts)
					}
				}

				shellHeader(c, "Tools")
				shellRow(c, m, shellEntry{
					label: "Generator", glyph: iconWandSparkles, tint: 0x14a3b8,
					active: route == RouteGenerator, press: goRoute(RouteGenerator),
				})
				shellRow(c, m, shellEntry{
					label: "Vault Health", glyph: iconHeartPulse, tint: 0xe5484d,
					count: m.Health.Get().TotalIssues(), counts: true, badge: true,
					active: route == RouteHealth, press: goRoute(RouteHealth),
				})
				shellRow(c, m, shellEntry{
					label: "Archive", glyph: iconArchive, tint: 0x8e8e93, count: counts.Archive, counts: true,
					active: inVault(filter.Category == state.FilterArchive),
					press:  func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterArchive}) },
				})
				shellRow(c, m, shellEntry{
					label: "Trash", glyph: iconTrash, tint: 0x8e8e93, count: counts.Trash, counts: true,
					active: inVault(filter.Category == state.FilterTrash),
					press:  func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterTrash}) },
				})
				shellRow(c, m, shellEntry{
					label: "Settings", glyph: iconSettings, tint: 0x7c7c84,
					active: route == RouteSettings, press: goRoute(RouteSettings),
				})
			})
		})
		shellSyncFooter(c, m)
	})
}

func shellCollections(c *ui.Context, m *AppModel, cols []state.Collection, filter state.SearchFilter, route MainRoute, counts VaultCounts) {
	p := pal(c)
	rows := func(orgID string) {
		for _, col := range cols {
			if orgID != "" && col.OrganizationID != orgID {
				continue
			}
			id := col.ID
			ui.Box(c.Key(id)).Children(func() {
				shellRow(c, m, shellEntry{
					label: col.Name, glyph: iconLibrary, count: counts.ByCollection[id], counts: true,
					active: route == RouteVault && filter.CollectionID == id,
					press:  func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll, CollectionID: id}) },
				})
			})
		}
	}
	if orgs := m.Organizations.Get(); len(orgs) > 1 {
		for _, org := range orgs {
			ui.Text(c, org.Name).FontSize(10.5).FontWeight(500).TextColor(p.Fg3).SingleLine().Padding(6, 0, 2, 8)
			rows(org.ID)
		}
		return
	}
	rows("")
}

func shellHeader(c *ui.Context, title string) {
	ui.Row(c).Height(22).Margin(14, 0, 2, 0).Padding(0, 4, 0, 8).Children(func() {
		ui.Text(c, title).FontSize(11).FontWeight(600).TextColor(pal(c).Fg3).Grow(1)
	})
}

func shellCollapsibleHeader(c *ui.Context, title string, collapsed bool, count int, toggle func(), trailing func()) {
	p := pal(c)
	ui.Row(c).Height(22).Margin(14, 0, 2, 0).Padding(0, 4, 0, 0).Children(func() {
		b := ui.ButtonBase(c).Label(title).Expanded(!collapsed).Grow(1).FillHeight().Justify(ui.Start).Gap(4).Padding(0, 0, 0, 8)
		b.OnClick(toggle).Children(func() {
			ui.Text(c, title).FontSize(11).FontWeight(600).TextColor(p.Fg3)
			glyph := iconChevronDown
			if collapsed {
				glyph = iconChevronRight
			}
			icon(c, glyph, 11, p.Fg3)
			if collapsed {
				ui.Text(c, fmt.Sprint(count)).FontSize(11).TextColor(p.Fg3).FontFeatures("tnum")
			}
		})
		if trailing != nil {
			trailing()
		}
	})
}

// shellRowBox is a sidebar row: a click chooses it.
func shellRowBox(c *ui.Context, name string, active bool, pad float32) ui.Element {
	p := pal(c)
	r := ui.ButtonBase(c).Label(name).Height(28).Gap(8).Padding(0, pad, 0, 8).Radius(6).FocusRingOffset(-2)
	switch {
	case active:
		r.Background(p.Sel)
	case r.Hovered():
		r.Background(p.Fill.Alpha(0.6))
	}
	return r
}

func shellRow(c *ui.Context, m *AppModel, e shellEntry) {
	p := pal(c)
	r := shellRowBox(c, e.label, e.active, 8)
	if e.folderDrop != nil {
		shellFolderDropTarget(c, m, r, *e.folderDrop)
	}
	r.OnClick(e.press).Children(func() {
		if e.tint != 0 {
			iconTile(c, e.glyph, e.tint)
		} else {
			ui.Box(c).Width(20).AlignItems(ui.Center).Children(func() { icon(c, e.glyph, 15, p.Accent) })
		}
		t := ui.Text(c, e.label).FontSize(13).TextColor(p.Fg).SingleLine().Grow(1)
		if e.active {
			t.FontWeight(500)
		}
		switch {
		case e.counts && e.badge:
			if e.count > 0 {
				ui.Box(c).Height(17).MinWidth(17).Padding(0, 6).Radius(999).Center().Background(p.WarnSoft).Children(func() {
					ui.Text(c, fmt.Sprint(e.count)).FontSize(11).FontWeight(600).TextColor(p.Warn).FontFeatures("tnum")
				})
			}
		case e.counts:
			ui.Text(c, fmt.Sprint(e.count)).FontSize(12).TextColor(p.Fg3).FontFeatures("tnum")
		}
	})
}

func shellFolderMenu(mn *ui.Menu, m *AppModel, f state.Folder, offline bool) {
	if mn.Item("Rename Folder…").Disabled(offline).Chosen() {
		m.OpenRenameFolderModal(f)
	}
	mn.Separator()
	if mn.Item("Delete Folder").Disabled(offline).Chosen() {
		m.DeleteFolder(m.Scope, f)
	}
}

func shellFolderRow(c *ui.Context, m *AppModel, f state.Folder, active bool, count int, offline bool) {
	p := pal(c)
	row := shellRowBox(c, f.Name, active, 4)
	row.OnClick(func() {
		m.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll, FolderID: f.ID})
	})
	row.ContextMenu(func(mn *ui.Menu) { shellFolderMenu(mn, m, f, offline) })
	shellFolderDropTarget(c, m, row, f.ID)
	row.Children(func() {
		ui.Box(c).Width(20).AlignItems(ui.Center).Children(func() { icon(c, iconFolder, 15, p.Accent) })
		t := ui.Text(c, f.Name).FontSize(13).TextColor(p.Fg).SingleLine().Grow(1)
		if active {
			t.FontWeight(500)
			ui.MenuButton(c, "", func(mn *ui.Menu) { shellFolderMenu(mn, m, f, offline) }).
				Label("Folder actions").Size(20, 20).Padding(0).Radius(5).Background(ui.Transparent).Border(0, ui.Transparent).
				NoShadow().Children(func() { icon(c, iconEllipsis, 14, p.Fg2) })
			return
		}
		ui.Text(c, fmt.Sprint(count)).FontSize(12).TextColor(p.Fg3).FontFeatures("tnum").Padding(0, 4, 0, 0)
	})
}

// shellFolderDropTarget makes row take items dragged from the list into
// the folder folderID, "" for No Folder, outlining it while they are over.
func shellFolderDropTarget(c *ui.Context, m *AppModel, row ui.Element, folderID string) {
	p := pal(c)
	if _, over := ui.DragOver[draggedItems](row); over {
		row.Background(p.AccentSoft).Border(1.5, p.Accent)
	}
	if ids, ok := ui.Drop[draggedItems](row); ok {
		m.MoveToFolder(ids, folderID)
	}
}

func shellSyncFooter(c *ui.Context, m *AppModel) {
	p := pal(c)
	email := m.Prefs.Get().Email
	row := ui.ButtonBase(c).Label("Accounts").Tooltip("Switch account").Shrink(0).Gap(10).Padding(12, 14).
		AlignItems(ui.Center).BorderWidth(1, 0, 0, 0).BorderColor(p.Line)
	if row.Hovered() || row.Pressed() {
		row.Background(p.Fill)
	}
	row.Menu(func(mn *ui.Menu) { accountMenu(mn, m) }).Children(func() {
		avatar(c, email, 28)
		ui.Column(c).Grow(1).Gap(1).MinWidth(0).Children(func() {
			ui.Text(c, email).FontSize(12).FontWeight(500).TextColor(p.Fg).SingleLine()
			ui.Row(c).Gap(6).Children(func() {
				dot := p.Success
				status := "Synced"
				switch m.SyncState.Get() {
				case SyncInProgress:
					dot, status = p.Accent, "Syncing…"
				case SyncPending:
					dot, status = p.Accent, "Sync pending"
				case SyncOffline:
					dot, status = p.Warn, "Offline · cached vault"
				case SyncAuthExpired:
					dot, status = p.Warn, "Session expired"
				default:
					if ts := m.LastSync.Get(); !ts.IsZero() {
						status = "Synced " + formatRelativeTime(ts)
						c.After(30e9) // keep "2m ago" current
					}
				}
				ui.Box(c).Size(6, 6).Radius(3).Background(dot)
				ui.Text(c, status).FontSize(11).TextColor(p.Fg3).SingleLine().Grow(1)
			})
		})
		icon(c, iconChevronDown, 13, p.Fg3)
	})
}

// shellRowMenu builds the context menu of the item id in the list.
func shellRowMenu(mn *ui.Menu, m *AppModel, id string) {
	cx := m.Scope
	m.SelectCipher(cx, id)
	ci := m.ActiveCipher.Get()
	if ci == nil || ci.ID != id {
		return
	}
	offline := m.SyncState.Get() == SyncOffline
	if ci.Login != nil {
		if mn.Item("Copy Username").Disabled(ci.Login.Username == "").Chosen() {
			m.CopyPlainValue("Username", ci.Login.Username)
		}
		if mn.Item("Copy Password").Disabled(ci.Login.Password == "" || m.PasswordHidden(ci)).Chosen() {
			m.GateReprompt(cx, ci, "copy password", func() { m.CopySecretValue("Password", ci.Login.Password) })
		}
		if strings.TrimSpace(ci.Login.TOTP) != "" && mn.Item("Copy Verification Code").Chosen() {
			m.GateReprompt(cx, ci, "copy TOTP code", func() {
				if code := m.TOTPCode.Get(); code != "" {
					m.CopySecretValue("TOTP code", code)
				}
			})
		}
		mn.Separator()
	}
	if ci.SSHKey != nil {
		if mn.Item("Copy Public Key").Disabled(ci.SSHKey.PublicKey == "").Chosen() {
			m.CopyPlainValue("Public key", ci.SSHKey.PublicKey)
		}
		mn.Separator()
	}
	readOnly := m.CipherReadOnly(ci)
	if ci.DeletedDate != nil {
		if mn.Item("Restore").Disabled(offline || readOnly).Chosen() {
			m.RestoreActive()
		}
		if mn.Item("Delete Permanently…").Disabled(offline || readOnly).Chosen() {
			m.HardDeleteActive(cx)
		}
		return
	}
	fav := "Add to Favorites"
	if ci.Favorite {
		fav = "Remove from Favorites"
	}
	if mn.Item("Edit").Disabled(offline || readOnly || m.PasswordHidden(ci)).Chosen() {
		m.StartEditCipher(cx)
	}
	if mn.Item("Clone").Disabled(!m.CanClone(ci)).Chosen() {
		m.CloneActive(cx)
	}
	if mn.Item(fav).Disabled(offline || readOnly || !m.CanFavorite(ci)).Chosen() {
		m.ToggleFavorite()
	}
	mn.Separator()
	if ci.ArchivedDate != nil {
		if mn.Item("Unarchive").Disabled(!m.CanUnarchiveItem(ci)).Chosen() {
			m.ArchiveActive(cx, false)
		}
	} else if mn.Item("Archive").Disabled(!m.CanArchiveItem(ci)).Chosen() {
		m.ArchiveActive(cx, true)
	}
	if mn.Item("Move to Trash").Disabled(offline || readOnly).Chosen() {
		m.SoftDeleteActive()
	}
}

// draggedItems are the IDs of the items dragged out of the list.
type draggedItems []string

// shellMultiSelected returns the items chosen in the list when there are
// several, in list order; nil for one or none.
func shellMultiSelected(m *AppModel) []string {
	if shellSelection.Len() < 2 {
		return nil
	}
	var ids []string
	for _, it := range m.FilteredItems.Items() {
		if shellSelection.Has(it.ID) {
			ids = append(ids, it.ID)
		}
	}
	if len(ids) < 2 {
		return nil
	}
	return ids
}

// shellSyncSelection makes the list's choice follow the model's item when
// that changed elsewhere (keys, navigation, a new item) or the list chose
// one the model refused, as an editor with unsaved changes does.
func shellSyncSelection(m *AppModel, items []state.CipherSummary) {
	selected := m.SelectedID.Get()
	external := selected != shellListSelected
	if !external && shellSelection.Len() > 1 && !m.EditMode.Get() {
		return
	}
	if !external && (shellSelection.Len() == 0 && selected == "" || shellSelection.Len() == 1 && shellSelection.Has(selected)) {
		return
	}
	shellListSelected = selected
	shellSelection.Clear()
	shellSelRow = -1
	for i, it := range items {
		if it.ID == selected {
			shellSelection.Add(selected)
			shellList.Choose(i)
			if external {
				shellList.ScrollIntoView(i)
			}
			break
		}
	}
}

// clearListSelection leaves the list with nothing chosen, as after an action
// on several items.
func clearListSelection() {
	shellSelection.Clear()
	shellSelRow = -1
	shellListSelected = ""
}

// shellMultiMenu is the context menu of several items chosen in the list.
func shellMultiMenu(mn *ui.Menu, m *AppModel, ids []string) {
	cx := m.Scope
	b := m.bulkSelection(ids)
	off := !m.bulkWritable()
	if b.inTrash {
		if mn.Item("Restore").Disabled(off || len(b.restorable) == 0).Chosen() {
			m.RestoreItems(ids)
		}
		if mn.Item("Delete Permanently…").Disabled(off || len(b.deletable) == 0).Chosen() {
			m.DeleteItemsPermanently(cx, ids)
		}
		return
	}
	mn.Submenu("Move to Folder", func(sub *ui.Menu) { shellFolderChoices(sub, m, ids, off || len(b.movable) == 0) })
	if len(b.unarchivable) > 0 && mn.Item("Unarchive").Disabled(off).Chosen() {
		m.ArchiveItems(cx, ids, false)
	}
	if len(b.unarchivable) < len(b.all) && mn.Item("Archive").Disabled(off || len(b.archivable) == 0).Chosen() {
		m.ArchiveItems(cx, ids, true)
	}
	mn.Separator()
	if mn.Item("Move to Trash…").Disabled(off || len(b.trashable) == 0).Chosen() {
		m.TrashItems(cx, ids)
	}
}

// shellFolderChoices lists No Folder and every folder to move ids into.
func shellFolderChoices(mn *ui.Menu, m *AppModel, ids []string, disabled bool) {
	if mn.Item("No Folder").Disabled(disabled).Chosen() {
		m.MoveToFolder(ids, "")
	}
	if folders := m.Folders.Get(); len(folders) > 0 {
		mn.Separator()
		for _, f := range folders {
			if mn.Item(f.Name).Disabled(disabled).Chosen() {
				m.MoveToFolder(ids, f.ID)
			}
		}
	}
}

func shellListPane(c *ui.Context, m *AppModel) {
	p := pal(c)
	cx := m.Scope
	items := m.FilteredItems.Items()
	shellList.Key = func(i int) any { return items[i].ID }
	shellList.Label = func(i int) string { return items[i].Name }
	shellList.Selection = &shellSelection
	shellList.Selected = &shellSelRow
	shellList.DragRows = func(rows []int) any {
		if m.SyncState.Get() == SyncOffline {
			return nil
		}
		ids := make(draggedItems, 0, len(rows))
		for _, r := range rows {
			if items[r].Deleted {
				return nil
			}
			ids = append(ids, items[r].ID)
		}
		return ids
	}
	shellSyncSelection(m, items)

	ui.Column(c).Width(m.ListW.Get()).Shrink(0).Background(p.List).Children(func() {
		shellSearchScope(c, m)
		shellTrashBar(c, m)
		list := ui.List(c.Key("vault-item-list"), &shellList, len(items)).Grow(1).Basis(0).Gap(2).Padding(8, 8).Children(func() {
			if len(items) == 0 {
				shellListEmpty(c, m)
			}
		})
		list.Rows(func(r ui.ListRow) {
			c := r.Context
			it := items[r.Index]
			sel := r.Selected()
			row := ui.Row(c).Height(52).Gap(10).Padding(0, 10).Radius(8)
			if !sel && r.Hovered() {
				row.Background(p.Fill.Alpha(0.6))
			}
			row.ContextMenu(func(mn *ui.Menu) {
				if ids := shellMultiSelected(m); len(ids) > 1 && shellSelection.Has(it.ID) {
					shellMultiMenu(mn, m, ids)
					return
				}
				shellRowMenu(mn, m, it.ID)
			})
			row.Children(func() {
				siteEmblem(c, m, it.URIs, it.Name, it.Type, it.Subtitle, 32)
				ui.Column(c).Grow(1).MinWidth(0).Gap(2).Children(func() {
					name, sub := p.Fg, p.Fg2
					if sel {
						name, sub = p.White, p.White.Alpha(0.8)
					}
					ui.Text(c, it.Name).FontSize(13).FontWeight(600).TextColor(name).SingleLine()
					subtitle := it.Subtitle
					if subtitle == "" {
						subtitle = CipherTypeLabel(it.Type)
					}
					ui.Text(c, subtitle).FontSize(12).TextColor(sub).SingleLine()
				})
				ui.Row(c).Gap(6).Children(func() {
					tint := func(normal ui.Color) ui.Color {
						if sel {
							return p.White.Alpha(0.9)
						}
						return normal
					}
					if it.Reprompt == 1 {
						icon(c, iconLockKeyhole, 12, tint(p.Fg3))
					}
					if it.HasPasskey {
						icon(c, iconKeyRound, 12, tint(p.Fg3)).Label("Has a passkey")
					}
					if it.HasTOTP {
						icon(c, iconTimer, 12.5, tint(p.Fg3))
					}
					if it.Favorite {
						icon(c, filledStar, 11.5, tint(p.Star))
					}
				})
			})
		})
		if list.Changed() {
			id := ""
			if shellSelRow >= 0 && shellSelRow < len(items) && shellSelection.Has(items[shellSelRow].ID) {
				id = items[shellSelRow].ID
			} else {
				for k := range shellSelection.All() {
					id = k
					break
				}
			}
			shellListSelected = id
			m.SelectCipher(cx, id)
		}
	})
}

// shellTrashBar offers Empty Trash while Trash holds items the user may
// delete.
func shellTrashBar(c *ui.Context, m *AppModel) {
	m.AllCounts.Get()
	if m.SidebarFilter.Get().Category != state.FilterTrash || m.TrashDeletable() <= 0 {
		return
	}
	p := pal(c)
	ui.Row(c).Gap(8).Margin(10, 12, 0, 12).Padding(0, 4, 0, 10).Height(30).Radius(8).Background(p.Fill).Children(func() {
		ui.Text(c, "Items in Trash can be restored.").FontSize(12).TextColor(p.Fg2).Grow(1).SingleLine()
		busy := m.TrashBusy.Get()
		shellSmallButton(c, "Empty Trash", false, busy || m.SyncState.Get() == SyncOffline, busy).OnClick(func() { m.EmptyTrash(m.Scope) })
	})
}

// shellSmallButton is a compact button, ghost or in the accent color.
func shellSmallButton(c *ui.Context, text string, primary, disabled, busy bool) ui.Element {
	p := pal(c)
	var b ui.Element
	if primary {
		b = ui.PrimaryButton(c, "")
	} else {
		b = ui.ButtonBase(c).Label(text).Radius(6)
		switch {
		case b.Pressed():
			b.Background(p.FillStrong)
		case b.Hovered():
			b.Background(p.Fill)
		}
	}
	b.Height(24).Padding(0, 8).Disabled(disabled).Children(func() {
		if busy {
			ui.Spinner(c).Size(11, 11)
		}
		t := ui.Text(c, text).FontSize(12).FontWeight(500).SingleLine()
		if !primary {
			t.TextColor(p.Accent)
			if disabled {
				t.TextColor(p.Fg3)
			}
		}
	})
	return b
}

// shellSearchScope shows where a query typed in a section searches, with
// one click to widen it to every item or narrow it back.
func shellSearchScope(c *ui.Context, m *AppModel) {
	if !m.SearchScoped() {
		return
	}
	p := pal(c)
	ui.Row(c).Gap(8).Margin(10, 12, 0, 12).Padding(0, 4, 0, 10).Height(30).Radius(8).Background(p.Fill).Children(func() {
		icon(c, iconSearch, 12, p.Fg3)
		where := "In " + m.sectionTitle()
		if m.SearchIsGlobal() {
			where = "In All Items"
		}
		ui.Text(c, where).FontSize(12).TextColor(p.Fg2).SingleLine().Grow(1)
		if m.SearchIsGlobal() {
			shellSmallButton(c, "Only "+m.sectionTitle(), false, false, false).OnClick(func() { m.SetSearchAll(false) })
			return
		}
		shellSmallButton(c, "Search All Items", m.FilteredItems.Len() == 0, false, false).OnClick(func() { m.SetSearchAll(true) })
	})
}

func shellListEmpty(c *ui.Context, m *AppModel) {
	p := pal(c)
	q := m.SearchQuery.Get()
	trash := m.SidebarFilter.Get().Category == state.FilterTrash
	glyph, title, desc := iconKeyRound, "No Items", "Choose New Item to add your first entry."
	switch {
	case q != "":
		glyph, title = iconSearch, "No Results"
		desc = fmt.Sprintf("Nothing matches “%s”.", q)
		if m.SearchScoped() && !m.SearchIsGlobal() {
			desc = fmt.Sprintf("Nothing in %s matches “%s”.", m.sectionTitle(), q)
		}
	case trash:
		glyph, title, desc = iconTrash, "Trash Is Empty", "Items you delete appear here."
	}
	ui.Column(c).FillWidth().AlignItems(ui.Center).Padding(64, 32).Gap(8).Children(func() {
		ui.Box(c).Size(44, 44).Radius(22).Center().Background(p.Fill).Margin(0, 0, 4, 0).Children(func() {
			icon(c, glyph, 20, p.Fg3)
		})
		ui.Text(c, title).FontSize(13).FontWeight(600).TextColor(p.Fg)
		ui.Text(c, desc).FontSize(12).TextColor(p.Fg2).TextAlign(ui.Center)
		if m.SearchScoped() && !m.SearchIsGlobal() {
			ui.PrimaryButton(c, "").Margin(8, 0, 0, 0).OnClick(func() { m.SetSearchAll(true) }).Children(func() {
				ui.Icon(c, iconSearch).Size(13, 13)
				ui.Text(c, "Search All Items").SingleLine()
			})
		}
	})
}
