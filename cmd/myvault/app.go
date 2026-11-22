package main

import (
	"context"
	_ "embed"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	vaultapp "github.com/oneryx/myvault/cmd/myvault/app"
	"github.com/oneryx/myvault/cmd/myvault/core"
	"github.com/oneryx/myvault/internal/vaultcore/state"
	"github.com/oneryx/myvault/internal/vaultcore/store"
)

// trayTemplatePNG is the app icon vault door as a template image,
// drawn in the menu bar colors.
//
//go:embed assets/TrayTemplate.png
var trayTemplatePNG []byte

// trayColorPNG is the app icon for the Windows notification area and Linux
// trays, which draw icons as they are.
//
//go:embed assets/TrayIcon.png
var trayColorPNG []byte

type DesktopShell struct {
	scope     *core.Scope
	dataDir   string
	clipboard *ClipboardAdapter
	favicons  *vaultapp.FaviconStore
	sshAgent  *sshAgentHost
	service   *state.Service
	model     *vaultapp.AppModel

	mainWin  *mygo.Window
	tray     *mygo.Tray
	trayMenu struct {
		sync, lock *mygo.MenuItem
	}

	rtMu      sync.Mutex
	rtRunning bool
}

// newScope makes the root scope, wired to the main thread and the platform.
func newScope() *core.Scope {
	host := &core.Host{
		Post:                  newPoster().post,
		SetClipboard:          mygo.Clipboard.WriteText,
		BiometricAvailability: biometricAvailability,
		AuthenticateBiometric: authenticateBiometric,
		PickFiles:             pickFiles,
	}
	return core.NewScope(host)
}

func NewDesktopShell() *DesktopShell {
	scope := newScope()
	dataDir := ensureDataDir()
	core.SetStorageDir(dataDir)
	secrets := NewBiometricSecretStore(SecretStoreAdapter{}, newHardwareKeychain())

	shell := &DesktopShell{
		scope:     scope,
		dataDir:   dataDir,
		clipboard: NewClipboardAdapter(),
		sshAgent:  newSSHAgentHost(runtime.GOOS, dataDir),
	}
	if cacheDir, err := mygo.App.Path(mygo.PathCache); err == nil {
		shell.favicons = vaultapp.NewFaviconStore(vaultapp.FaviconStoreConfig{CacheDir: filepath.Join(cacheDir, "icons")})
	}

	tempPrefs := core.NewPersisted(scope, vaultapp.DefaultPrefsKey, vaultapp.DefaultUserPrefs(), core.PersistOptions{Version: 1})
	initialPrefs := vaultapp.EnsureDeviceID(tempPrefs)

	meta := DiscoverAccountSnapshot(dataDir, initialPrefs.AccountID)
	accountID := initialPrefs.AccountID
	if meta != nil {
		accountID = meta.AccountID
	}

	svc, err := state.NewService(state.ServiceConfig{
		Store:      store.NewFileStore(dataDir),
		Secrets:    secrets,
		AccountID:  accountID,
		DeviceID:   initialPrefs.DeviceID,
		DeviceName: "MyVault Desktop",
		DeviceType: deviceTypeForOS(),
		OnStatusChange: func(st state.LockStatus) {
			if st != state.StatusUnlocked {
				shell.sshAgent.Clear()
				if m := shell.model; m != nil {
					m.RevokePending()
				}
			}
			scope.Post(func() {
				if shell.model == nil {
					return
				}
				if st != state.StatusUnlocked {
					shell.model.ServiceLeftUnlocked(st)
					return
				}
				// A sleep or Back to Unlock may have locked the session
				// again before this callback ran.
				if shell.service.Status() != state.StatusUnlocked {
					return
				}
				shell.model.LockState.Set(st)
				shell.startRealtimeAsync()
			})
		},
		OnVaultUpdated: func() {
			scope.Post(func() {
				if shell.model != nil && shell.model.LockState.Get() == state.StatusUnlocked {
					shell.model.RefreshVaultData()
				}
			})
		},
	})
	if err != nil {
		panic(err)
	}
	shell.service = svc

	hooks := shell.platformHooks(secrets)
	hooks.BiometricHardwareBound = secrets.HardwareBound
	hooks.DiscoverSnapshot = func(preferred string) *vaultapp.AccountSnapshotMeta {
		return DiscoverAccountSnapshot(dataDir, preferred)
	}
	hooks.VerifyMasterPassword = func(accountID string, password []byte) error {
		return VerifyMasterPasswordOffline(dataDir, accountID, password)
	}

	shell.model = vaultapp.NewAppModel(scope, svc, hooks)
	if meta != nil {
		shell.model.SyncAccountMetaFromSnapshot()
	}
	shell.finishSetup()
	return shell
}

func (s *DesktopShell) platformHooks(secrets store.SecretStore) vaultapp.PlatformHooks {
	hooks := vaultapp.PlatformHooks{
		Secrets:    secrets,
		CopySecret: s.clipboard.CopySecret,
		CopyPlain:  s.clipboard.CopyPlain,
		SetLaunchAtLogin: func(on bool) {
			_ = mygo.App.SetOpenAtLogin(on)
		},
		SetDockVisible: func(on bool) {
			if runtime.GOOS != "darwin" {
				return
			}
			policy := mygo.ActivationPolicyRegular
			if !on {
				policy = mygo.ActivationPolicyAccessory
			}
			mygo.App.SetActivationPolicy(policy)
		},
		SetTrayVisible:     s.SetTrayVisible,
		SetAppearance:      setAppearance,
		SleepLockSupported: true,
		Favicons:           s.favicons,
		ChooseSavePath:     s.chooseSavePath,
		Updates:            appUpdates(s.invalidate),
	}
	if s.sshAgent != nil {
		hooks.SSHAgent = s.sshAgent
	}
	return hooks
}

func (s *DesktopShell) chooseSavePath(name string, done func(path string, ok bool, err error)) {
	go func() {
		dir, _ := mygo.App.Path(mygo.PathDownloads)
		path, err := mygo.Dialog.Save(mygo.SaveDialogOptions{
			Parent:            s.mainWin,
			Title:             "Save Attachment",
			DefaultPath:       filepath.Join(dir, name),
			ButtonLabel:       "Save",
			CreateDirectories: true,
		})
		done(path, err == nil && path != "", err)
	}()
}

func pickFiles(opts core.PickFilesOptions) ([]core.File, error) {
	var filters []mygo.FileFilter
	if len(opts.Types) > 0 {
		var exts []string
		for _, t := range opts.Types {
			exts = append(exts, t[1:])
		}
		filters = []mygo.FileFilter{{Name: "Files", Extensions: exts}}
	}
	paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{
		Title:       opts.Title,
		ButtonLabel: opts.Button,
		Filters:     filters,
	})
	if err != nil {
		return nil, err
	}
	var files []core.File
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		files = append(files, core.File{Name: filepath.Base(p), Path: p, Size: info.Size()})
	}
	return files, nil
}

// activeShell is the running shell, for debugging tools.
var activeShell *DesktopShell

func (s *DesktopShell) finishSetup() {
	activeShell = s
	core.SetInvalidate(s.invalidate)
	mygo.App.SetMenu(applicationMenu())

	p := s.model.Prefs.Get()
	if runtime.GOOS == "darwin" && p.HideDockIcon && p.ShowTrayIcon {
		mygo.App.SetActivationPolicy(mygo.ActivationPolicyAccessory)
	}
	s.SetTrayVisible(p.ShowTrayIcon)
	setAppearance(p.Appearance)
	s.scope.Effect(s.updateTrayMenu)

	// The app stays running with the tray icon, and on macOS, as Mac apps
	// do, until the user quits.
	mygo.App.OnWindowAllClosed(func() {
		if runtime.GOOS != "darwin" && !s.model.Prefs.Get().ShowTrayIcon {
			mygo.App.Quit()
		}
	})
	mygo.App.OnActivate(func(hasVisibleWindows bool) {
		if !hasVisibleWindows {
			s.OpenMainWindow()
		}
	})

	lock := func() { s.scope.Post(func() { s.model.LockOnSystemEvent() }) }
	mygo.Power.OnSuspend(lock)
	mygo.Power.OnLockScreen(lock)

	mygo.App.OnQuit(func() {
		s.clipboard.ClearOnQuit()
		s.scope.Dispose()
	})

	if !mygo.App.WasOpenedAtLogin() || !p.ShowTrayIcon {
		s.OpenMainWindow()
	}
}

func (s *DesktopShell) invalidate() {
	if w := s.mainWin; w != nil {
		w.Invalidate()
	}
}

func (s *DesktopShell) startRealtimeAsync() {
	if s.service == nil {
		return
	}
	s.rtMu.Lock()
	if s.rtRunning {
		s.rtMu.Unlock()
		return
	}
	s.rtRunning = true
	s.rtMu.Unlock()

	go func() {
		_ = s.service.StartRealtime(context.Background())
		s.rtMu.Lock()
		s.rtRunning = false
		s.rtMu.Unlock()
	}()
}

func (s *DesktopShell) OpenMainWindow() {
	if s.mainWin != nil {
		s.mainWin.Show()
		s.mainWin.Focus()
		return
	}
	win := mygo.NewWindow(mygo.WindowOptions{
		Title:         "MyVault",
		Width:         vaultapp.MainWindowWidth,
		Height:        vaultapp.MainWindowHeight,
		MinWidth:      vaultapp.MainWindowMinWidth,
		MinHeight:     vaultapp.MainWindowMinHeight,
		StateKey:      "main",
		TitleBarStyle: mygo.TitleBarHidden,
		Content:       ui.View(func(c *ui.Context) { vaultapp.MainWindowView(c, s.model) }),
	})
	s.mainWin = win
	visible := func(on bool) { s.scope.Post(func() { s.model.SetMainWindowVisible(on) }) }
	win.OnShow(func() { visible(true) })
	win.OnRestore(func() { visible(true) })
	win.OnHide(func() { visible(false) })
	win.OnMinimize(func() { visible(false) })
	win.OnClose(func(e *mygo.CloseEvent) {
		if s.model.EditMode.Get() && s.model.EditDirty.Get() {
			e.PreventDefault()
			s.model.GuardDirty(s.scope, func() { win.Destroy() })
		}
	})
	win.OnClosed(func() {
		if s.mainWin == win {
			s.mainWin = nil
		}
		s.model.SetMainWindowVisible(false)
	})
	s.model.SetMainWindowVisible(true)
}

func (s *DesktopShell) SetTrayVisible(on bool) {
	if on == (s.tray != nil) {
		return
	}
	if !on {
		s.tray.Destroy()
		s.tray = nil
		return
	}
	icon, template := trayColorPNG, false
	if runtime.GOOS == "darwin" {
		icon, template = trayTemplatePNG, true
	}
	s.trayMenu.sync = &mygo.MenuItem{Label: "Sync Now", Click: func(*mygo.MenuItem, *mygo.Window) { s.model.SyncNow(false) }}
	s.trayMenu.lock = &mygo.MenuItem{Label: "Lock Now", Click: func(*mygo.MenuItem, *mygo.Window) { s.model.Lock() }}
	menu := mygo.NewMenu([]*mygo.MenuItem{
		{Label: "Open MyVault", Click: func(*mygo.MenuItem, *mygo.Window) { s.OpenMainWindow() }},
		mygo.Separator(),
		s.trayMenu.sync,
		s.trayMenu.lock,
		mygo.Separator(),
		{Label: "Quit MyVault", Click: func(*mygo.MenuItem, *mygo.Window) { mygo.App.Quit() }},
	})
	tray, err := mygo.NewTray(mygo.TrayOptions{
		Icon:           icon,
		IconIsTemplate: template,
		ToolTip:        "MyVault",
		Menu:           menu,
	})
	if err != nil {
		return
	}
	s.tray = tray
	s.updateTrayMenu()
}

// updateTrayMenu enables the tray's items for the vault's state.
func (s *DesktopShell) updateTrayMenu() {
	if s.tray == nil || s.model == nil {
		return
	}
	unlocked := s.model.LockState.Get() == state.StatusUnlocked
	offline := s.model.SyncState.Get() == vaultapp.SyncOffline
	s.trayMenu.sync.SetEnabled(unlocked && !offline)
	s.trayMenu.lock.SetVisible(unlocked)
}

// poster runs functions on the main thread in the order they were posted,
// without blocking the caller.
type poster struct {
	mu      sync.Mutex
	cond    *sync.Cond
	pending []func()
}

func newPoster() *poster {
	p := &poster{}
	p.cond = sync.NewCond(&p.mu)
	go p.loop()
	return p
}

func (p *poster) post(fn func()) {
	p.mu.Lock()
	p.pending = append(p.pending, fn)
	p.mu.Unlock()
	p.cond.Signal()
}

func (p *poster) loop() {
	for {
		p.mu.Lock()
		for len(p.pending) == 0 {
			p.cond.Wait()
		}
		batch := p.pending
		p.pending = nil
		p.mu.Unlock()
		mygo.RunOnMain(func() {
			for _, fn := range batch {
				fn()
			}
		})
	}
}

// setAppearance shows the app "light" or "dark", or as the system for "".
func setAppearance(a string) {
	switch a {
	case "light":
		mygo.Theme.SetSource(mygo.ThemeLight)
	case "dark":
		mygo.Theme.SetSource(mygo.ThemeDark)
	default:
		mygo.Theme.SetSource(mygo.ThemeSystem)
	}
}
