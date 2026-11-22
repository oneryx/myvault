# MyVault Architecture

## Goal

A fast, low-memory, zero-CGO desktop client for self-hosted Vaultwarden (Bitwarden-compatible) servers on macOS,
Linux and Windows, with Touch ID unlock on macOS, built on a UI-agnostic Go core (`internal/vaultcore`) and a
[MyGo](https://github.com/egoist/mygo) native UI drawn on the GPU.

## Design

### 1. Layers

`internal/vaultcore` has **zero imports** of `mygo` or any GUI package:

```text
+-------------------------------------------------------------------+
|  cmd/myvault  (desktop shell)                                     |
|  - main window, tray icon, app menu, Touch ID (LocalAuthentication|
|    via purego), hardware-bound keychain item, ssh-agent socket     |
|  - adapters: mygo.Secrets, mygo.Clipboard (concealed, auto-clear), |
|    mygo.Dialog, mygo.Power (lock on sleep and screen lock)        |
+-------------------------------------------------------------------+
|  cmd/myvault/app  (model and views)                               |
|  - AppModel: every screen's state in signals; login, unlock,      |
|    sync, editing, reprompt, backup, import, health, navigation    |
|  - views: functions of the model that mygo's ui package builds    |
|    every frame (login, lock, sidebar, list, detail, editor, ...)  |
+-------------------------------------------------------------------+
|  cmd/myvault/core  (reactive state)                               |
|  - Signal, Memo, Effect, Batch, Persisted; each write asks the    |
|    window for a new frame. Alerts, file picking and biometrics    |
|    reach the platform through a Host the shell provides.         |
+-------------------------------+-----------------------------------+
                                | Go interfaces & domain structs
                                v
+-------------------------------------------------------------------+
|  internal/vaultcore  (pure Go, zero CGO, zero UI dependencies)    |
|  - crypto/   : KDF (PBKDF2, Argon2id), HKDF, AES-256-CBC-HMAC,    |
|                RSA-OAEP, EncString parser/encoder, zeroize        |
|  - api/      : prelogin, OAuth2 token + refresh, /api/sync,       |
|                cipher/folder/attachment CRUD, revision date       |
|  - realtime/ : SignalR/MessagePack WebSocket (/notifications/hub) |
|  - store/    : atomic encrypted JSON snapshot                     |
|  - state/    : lock/unlock state machine, in-memory decrypted     |
|                vault, search, memory wipe on lock                 |
|  - export/   : encrypted backup and reviewed import               |
|  - health/, totp/, gen/, sshagent/                                |
+-------------------------------------------------------------------+
```

Model methods run on the main thread. Work that blocks (network, key derivation, disk) runs in goroutines that
publish their results with `Scope.Post`, which runs a function on the main thread in one batch; effects then run and
the window draws a new frame. Every pending secret action records the lock generation it started under and is
dropped if the vault locked meanwhile.

### 2. Cryptography and Key Hierarchy (`internal/vaultcore/crypto`)

Follows the Bitwarden/Vaultwarden cryptographic specification (see [`vaultcore-spec.md`](vaultcore-spec.md) for full details and verified test vectors):

1. **Prelogin**: `POST /identity/accounts/prelogin` returns KDF type (`0` = PBKDF2-SHA256, `1` = Argon2id) and parameters.
2. **Master Key Derivation**:
   - Email is normalized (`strings.ToLower(strings.TrimSpace(email))`).
   - `PBKDF2`: `PBKDF2-HMAC-SHA256(password, email, iterations, 32)`.
   - `Argon2id`: `Argon2id(password, SHA256(email), time=iterations, memory=kdfMemory*1024 KiB, threads=kdfParallelism, keyLen=32)`.
   - **Memory reclamation**: After Argon2id completes and sensitive temporary buffers are zeroed, call `debug.FreeOSMemory()` so the working set is returned to the OS promptly.
3. **Master Password Hash (for login only)**:
   - `Base64(PBKDF2-HMAC-SHA256(masterKey, password, 1, 32))` sent to `/identity/connect/token`.
4. **Stretched Master Key**:
   - `encKey = HKDF-Expand(SHA256, masterKey, "enc", 32)` (no HKDF-Extract)
   - `macKey = HKDF-Expand(SHA256, masterKey, "mac", 32)`
5. **Protected Symmetric User Key**:
   - Server returns `Key` (EncString) in token/sync response; decrypting yields the 64-byte **User Key** (`userEncKey` 32B + `userMacKey` 32B).
   - **Invariant**: Never store the raw master password on disk or in Keychain. Only the decrypted User Key (and OAuth refresh token) is stored in Keychain when Touch ID unlock is enabled.
6. **CipherString (`EncString`) & Per-Cipher Key**:
   - Standard Type 2 (`AesCbc256_HmacSha256_B64`): verify HMAC-SHA256 (`MAC(iv || ct, macKey)`) in constant time before AES-256-CBC decryption.
   - If a cipher has a non-empty `cipher.key`, unwrap that 64-byte per-cipher symmetric key first and use it to decrypt the cipher's fields.
   - **Organizations**: `profile.privateKey` (Type 2, PKCS#8) is decrypted with the User Key, then each enabled `organization.key` (RSA-OAEP Types 3–6, SHA-256 or SHA-1) is unwrapped into a 64-byte org key held only in memory. Org ciphers and collection names decrypt with that key (per-cipher keys are wrapped with it), and edits re-encrypt with it while keeping `organizationId` and `collectionIds`.
7. **Memory Hygiene**:
   - Overwrite sensitive `[]byte` key material on lock, logout, sleep, and session timeout.

### 3. Touch ID Unlock

1. **Enrollment** (opt-in in Settings after a master-password unlock): `LAContext` (policy
   `DeviceOwnerAuthenticationWithBiometrics`) confirms the user, then the 64-byte user key is saved under
   `userkey:<accountID>`.
2. **Unlock**: Touch ID, then the key is read off the main thread, the encrypted snapshot is loaded and decrypted, and
   the state becomes unlocked. Cancelling or failing falls back to the master password.
3. **Hardware-bound key** (`cmd/myvault/biokeychain*.go`): `BiometricSecretStore` first tries the Data Protection
   Keychain with a `SecAccessControl` of `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` +
   `kSecAccessControlBiometryCurrentSet`. macOS then shows its own Touch ID prompt when the key is read, and the app
   skips `LAContext`. Builds without the `keychain-access-groups` entitlement get `errSecMissingEntitlement` (`-34018`)
   and keep the key in the login Keychain, gated by `LAContext`. Settings shows which protection is active.

### 4. Lock Triggers

- Manual lock (`Cmd+L` / tray), idle timeout (default 15 minutes), and system sleep or screen lock (on by default).
- On lock: the user key, org keys and decrypted items are zeroed, timers stop, and drafts, dialogs and revealed
  secrets are cleared.

### 5. Storage, Sync, and Real-Time Updates

1. **Local Storage (Zero SQLite, Zero Plaintext on Disk)**:
   - **Encrypted Vault Snapshot**: `<user data dir>/vault_<accountID>.enc.json` — stores the raw encrypted `/api/sync` response payload plus local metadata (`lastSyncAt`, `revisionDate`, `serverURL`, `email`, `kdfParams`). Written atomically via temp file + `fsync` + `os.Rename` with `0600` permissions.
   - **Secrets (`mygo.Secrets`: Keychain, Secret Service or Credential Manager)**: OAuth `refresh_token` and (if Touch ID enabled) `user_key`.
   - **Preferences**: non-sensitive settings in `<user data dir>/myvault.prefs.json` (`core.NewPersisted`).
   - **Favicon Cache**: icons from `<server>/icons/<domain>/icon.png`, stored in `<cache dir>/icons/<domain>.png` plus a 256-entry memory LRU and a negative cache; fetched by 4 bounded workers. The "Show website icons" toggle disables all requests, and "Clear Icon Cache" removes them.
   - **Accounts**: every account signed in on this device keeps its own snapshot, secrets, favicon cache and Touch ID
     setting. One is current at a time: switching (sidebar footer or lock screen menu) locks the open vault and shows
     the other account's lock screen. Add Account signs in to another without removing any; Log Out removes only the
     current account and opens another one, locked, if any remain.
2. **Sync Flow**:
   - On unlock: immediately decrypt local `vault_<accountID>.enc.json` so the UI is usable offline in `< 50 ms`.
   - In background: call `GET /api/accounts/revision-date`; only fetch full `GET /api/sync` if the server revision date is newer (or on manual sync `Cmd+R`).
   - Transparent access-token refresh via `POST /identity/connect/token` (`grant_type=refresh_token`).
3. **Real-Time Push (`internal/vaultcore/realtime`)**:
   - Connects to `wss://<host>/notifications/hub?access_token=<token>` using SignalR handshake + varint-framed MessagePack (matching Vaultwarden `src/api/notifications.rs`).
   - Handles cipher/folder/vault sync triggers and `LogOut` pushes with exponential backoff reconnect.

### 6. Desktop

- **Main window**: resizable three panes (sidebar, item list, detail or editor) with persisted widths; the toolbar
  sits under the window controls (hidden title bar). The window's size and position are restored (`StateKey`).
- **Tray icon**: on by default; closing the main window keeps the app running. Menu-bar-only mode hides the Dock icon
  (`ActivationPolicyAccessory`).
- **Clipboard**: copied secrets are marked confidential and cleared after the configured delay, or as the app quits,
  if the clipboard still holds them.
- **CPU and memory**: the 1 s TOTP ticker runs only while a login with a code is shown, the idle lock is a single
  timer, and frames are drawn only when the model changes.

## Project Layout

```text
myvault/
├── cmd/myvault/
│   ├── main.go, app.go        # app start, shell: window, tray, menu, hooks
│   ├── adapters.go            # secrets, clipboard, snapshot discovery
│   ├── biometric_*.go         # Touch ID (LocalAuthentication via purego)
│   ├── biokeychain*.go        # hardware-bound keychain item
│   ├── sshagent_host.go       # local ssh-agent socket
│   ├── core/                  # signals, effects, persisted settings
│   ├── app/                   # AppModel and the views
│   └── demo/                  # in-memory sample vault (--demo)
├── internal/vaultcore/        # the UI-free core
└── mygo.json                  # app name, identifier, icon for `mygo build`
```

## Related Documents

- [`vaultcore` Interface, Protocol, and Test Vector Specification](vaultcore-spec.md)
- [Official Bitwarden Desktop Client and Vaultwarden Protocol](research/official-client-and-protocol.md)
