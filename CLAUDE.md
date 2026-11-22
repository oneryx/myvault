# MyVault

Desktop client for Vaultwarden / Bitwarden-compatible servers, Go + [mygo](https://github.com/egoist/mygo) native UI
(drawn on the GPU, no webview, no CGO). Module `github.com/oneryx/myvault`.

## Commands

```sh
task demo        # run on the in-memory sample vault (go run ./cmd/myvault --demo)
task             # run against a real server
task test        # gofmt -l . && go vet ./... && go test ./...
task build       # go tool mygo build → dist/ (config in mygo.json)
```

mygo docs live in the module cache: `$(go list -m -f '{{.Dir}}' github.com/egoist/mygo)/docs` (`docs/ui/*.md` for
widgets). Read them before guessing an API.

## Layout

- `internal/vaultcore/` — UI-free core: crypto, api, realtime (SignalR), store, state (lock/unlock, search), export,
  health, totp, gen, sshagent. Must never import mygo or any GUI package.
- `cmd/myvault/core/` — small reactive layer: `Signal`, `Memo`, `Effect`, `Batch`, `Persisted`, and `Scope` (Post,
  alerts, biometrics, file picking via a `Host` the shell provides). Every signal write calls the invalidate hook
  (redraws the window).
- `cmd/myvault/app/` — `AppModel` (model.go: all state in signals; login, unlock, sync, edit, reprompt, backup,
  import, nav) and the views. Views are plain functions `func X(c *ui.Context, m *AppModel)` rebuilt every frame:
  `mainview.go` (root, shortcuts, dialogs, alerts, toasts), `auth.go` (login/lock/2FA), `shell.go` (toolbar, sidebar,
  list, routes), `detail.go`, `editor.go`, `settings.go`, `generator.go`, `health.go`, `import.go`.
- `cmd/myvault/` — shell: `app.go` (window, tray, menu, hooks, main-thread poster), `adapters.go` (mygo.Secrets,
  concealed auto-clearing clipboard), `biometric_darwin.go` (Touch ID via purego LAContext), `biokeychain*.go`
  (hardware-bound keychain item), `sshagent_host.go`, `demo/` (sample vault).

## Conventions

- Model methods run on the main thread. Blocking work goes in a goroutine and publishes with `m.Scope.Post(...)`.
  Secret actions capture `m.LockGeneration()` and check `m.StillUnlocked(gen)` before acting.
- Views read signals with `.Get()` and write back through model methods or `bindString`/local copies compared after
  the widget (mygo widgets bind `*T`). Give stateful inputs stable `c.Key(...)`. Model calls needing a scope get
  `m.Scope`.
- Colors come from `pal(c)` (style.go), never hard-coded per view; icons are `icon*` vars in `icons_lucide.go`
  (generated from Lucide — add new ones the same way). Shared view helpers are in `style.go`.
- Confirmations use `m.Scope.ShowAlert` (rendered by `alertDialog`); toasts use `m.ShowToast`.
- Tests: views via `ui.NewTester` and the harness in `app/harness_test.go`; use `t.TempDir()` for storage
  (`core.SetStorageDir`), never the real user data dir or keychain.
- `shot_debug.go` (`-tags shot`): `MYVAULT_SHOT=out.png MYVAULT_SHOT_DO=light,select:c-github` captures the window
  for visual checks.
