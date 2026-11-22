# `vaultcore` Interface, Protocol, and Test Vector Specification

## Goal

Provide an implementation-ready, UI-agnostic Go specification for `internal/vaultcore` so that core development and full unit/integration testing can proceed cleanly and independently of any GUI layer.

## Non-goals

- UI layout and widgets (owned by `cmd/myvault`, see [Architecture](architecture.md)).
- Phase 2 features: 2FA login flows, Organizations/Collections (RSA-OAEP org key unwrap), Attachments, Bitwarden Send, and multi-account state multiplexing. Interfaces remain forward-compatible with these without complicating Phase 1.

## Requirements and Constraints

- **Zero CGO (`CGO_ENABLED=0`)**: All packages under `internal/vaultcore` must compile with standard Go + pure-Go dependencies (`golang.org/x/crypto` for Argon2id/PBKDF2/HKDF, a pure-Go WebSocket library such as `github.com/coder/websocket`, and a pure-Go MessagePack codec such as `github.com/vmihailenco/msgpack/v5`).
- **Zero GUI imports**: `internal/vaultcore/...` must never import `github.com/egoist/mygo/...` or any other GUI package.
- **Zero plaintext on disk**: Local snapshot persistence stores only server-encrypted JSON payloads; decrypted data lives strictly in memory and is zeroed on lock.
- **Lossless unknown-field preservation**: Vaultwarden supports cipher types 1–8 (`Login`, `SecureNote`, `Card`, `Identity`, `SshKey`, `BankAccount`, `DriversLicense`, `Passport`) and fields such as `archivedDate`, `encryptedFor`, `encryptedByKeyId`, and `key` (per-cipher key). Unrecognized fields and non-MVP cipher types must be preserved unmodified on read/sync and never corrupted.

## Design

### 1. Package Map & Concrete Go Interfaces

#### 1.1 `internal/vaultcore/crypto`

```go
package crypto

type KDFType int

const (
	KDFPBKDF2   KDFType = 0
	KDFArgon2id KDFType = 1
)

type KDFConfig struct {
	Type        KDFType `json:"kdf"`
	Iterations  uint32  `json:"kdfIterations"`
	MemoryMB    uint32  `json:"kdfMemory,omitempty"`      // Argon2id only; MiB (multiply by 1024 for KiB)
	Parallelism uint32  `json:"kdfParallelism,omitempty"` // Argon2id only
}

type EncType int

const (
	EncAesCbc256B64            EncType = 0 // Legacy; rejected for cipher fields, optional for legacy UserKey unwrap
	EncAesCbc256HmacSha256B64  EncType = 2 // Standard symmetric format: "2.<b64(iv)>|<b64(ct)>|<b64(mac)>"
	EncRsa2048OaepSha256B64    EncType = 3 // Phase 2: Org key unwrap
	EncRsa2048OaepSha1B64      EncType = 4 // Phase 2: Org key unwrap
)

// SymmetricKey holds a 64-byte Encrypt-then-MAC key (32B AES-256 enc + 32B HMAC-SHA256 mac).
// Call Zero() on lock/logout.
type SymmetricKey struct {
	Enc [32]byte
	Mac [32]byte
}

func (k *SymmetricKey) Zero()
func (k *SymmetricKey) Bytes() [64]byte
func SymmetricKeyFromBytes(raw []byte) (*SymmetricKey, error) // requires len == 64

type EncString struct {
	Type EncType
	IV   []byte
	CT   []byte
	MAC  []byte
}

// KDF & Master Key derivation
func NormalizeEmail(email string) string // strings.ToLower(strings.TrimSpace(email))
func ValidateKDF(cfg KDFConfig) error    // PBKDF2 >= 5000; Argon2id iter >= 2, memory >= 16 MiB, parallelism >= 1
func DeriveMasterKey(password []byte, email string, cfg KDFConfig) ([32]byte, error)
func HashMasterPasswordForServer(masterKey [32]byte, password []byte) string // Base64(PBKDF2-SHA256(masterKey, password, 1, 32))
func StretchMasterKey(masterKey [32]byte) (*SymmetricKey, error)             // HKDF-Expand(SHA256, PRK=masterKey, "enc"|"mac", 32) — NO Extract!

// User Key unwrap (supports Type 2; optionally Type 0 for legacy vaults using raw masterKey)
func DecryptUserKey(protectedKey string, masterKey [32]byte) (*SymmetricKey, error)

// EncString parse / encrypt / decrypt (Type 2 only for cipher fields)
func ParseEncString(s string) (*EncString, error)
func (e *EncString) String() string
func EncryptBytes(plaintext []byte, key *SymmetricKey) (*EncString, error)          // Type 2, CSPRNG 16B IV, PKCS#7, HMAC(iv||ct)
func EncryptBytesWithIV(plaintext, iv []byte, key *SymmetricKey) (*EncString, error) // Deterministic helper for unit tests
func EncryptString(plaintext string, key *SymmetricKey) (string, error)
func DecryptBytes(enc *EncString, key *SymmetricKey) ([]byte, error)                // Verifies HMAC in constant time BEFORE AES decrypt
func DecryptString(encStr string, key *SymmetricKey) (string, error)

// Memory hygiene
func ZeroBytes(b []byte)
```

**Critical cryptographic rules (verified against `bitwarden/sdk-internal` @ `c5c08aebe883`)**:
1. **Email normalization**: Always `strings.ToLower(strings.TrimSpace(email))` before using as KDF salt.
2. **Argon2id salt**: `SHA-256(normalizedEmail)` (32 bytes), not the raw email string. Memory passed to `argon2.IDKey` is `cfg.MemoryMB * 1024` (KiB).
3. **Argon2id memory release**: After `DeriveMasterKey` completes for Argon2id, callers should zero temporary slices and invoke `runtime/debug.FreeOSMemory()` so the 32–64 MiB working buffer is returned to the OS promptly.
4. **HKDF-Expand only**: `StretchMasterKey` uses `masterKey` directly as `PRK` in RFC 5869 `HKDF-Expand` (`crypto/hkdf.Expand(sha256.New, masterKey[:], "enc", 32)` and `"mac"`). Do **not** run `HKDF-Extract`.
5. **Encrypt-then-MAC order**: Compute `HMAC-SHA256(key.Mac[:], iv || ct)` over the raw binary concatenation `iv || ct` (not Base64 text). On decrypt, compare with `hmac.Equal` **before** decrypting AES-CBC or checking PKCS#7 padding to prevent padding-oracle leaks.
6. **Type 0 handling**: Reject `EncAesCbc256B64` (Type 0) for cipher fields (matching Bitwarden's `encrypt.service.implementation.ts`). Allow Type 0 **only** inside `DecryptUserKey` using raw `masterKey` (no stretch) for legacy accounts created before Bitwarden migrated to Type 2 protected keys.
7. **Per-cipher key (`cipher.key`)**: If a cipher's `Key` field is non-empty, decrypt `cipher.Key` using `userKey` first to obtain a 64-byte `cipherKey`, and use `cipherKey` for all fields of that cipher. If `cipher.Key` is empty, use `userKey` directly.

---

#### 1.2 `internal/vaultcore/api`

```go
package api

type Client struct { /* baseURL, httpClient, deviceID, deviceName, deviceType, userAgent */ }

type ClientConfig struct {
	ServerURL  string       // Normalized, no trailing slash (e.g. "https://vault.example.com")
	DeviceID   string       // Stable UUIDv4 persisted in non-secret app config
	DeviceName string       // e.g. "macos" or "linux"
	DeviceType int          // Bitwarden DeviceType enum: 7 = macOS Desktop, 8 = Linux Desktop, 6 = Windows Desktop
	HTTPClient *http.Client // Optional; defaults to sane timeouts + system TLS/proxy
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Key          string `json:"Key"`        // Protected User Key (EncString)
	PrivateKey   string `json:"PrivateKey"` // Protected RSA Private Key (Phase 2)
	KDF          int    `json:"Kdf"`
	KDFIters     int    `json:"KdfIterations"`
	KDFMemory    *int   `json:"KdfMemory"`
	KDFParallel  *int   `json:"KdfParallelism"`
}

// Vaultwarden / Bitwarden HTTP methods
func (c *Client) Prelogin(ctx context.Context, email string) (crypto.KDFConfig, error)
func (c *Client) LoginPassword(ctx context.Context, email, masterPasswordHash string) (*TokenResponse, error)
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error)
func (c *Client) RevisionDate(ctx context.Context, accessToken string) (time.Time, error)
func (c *Client) Sync(ctx context.Context, accessToken string) (*SyncResponse, []byte, error) // returns parsed + raw JSON bytes for atomic snapshot

// Cipher CRUD (all transmit encrypted CipherPayload)
func (c *Client) CreateCipher(ctx context.Context, accessToken string, payload *CipherPayload) (*EncryptedCipher, error)
func (c *Client) UpdateCipher(ctx context.Context, accessToken, cipherID string, payload *CipherPayload) (*EncryptedCipher, error)
func (c *Client) SoftDeleteCipher(ctx context.Context, accessToken, cipherID string) error
func (c *Client) RestoreCipher(ctx context.Context, accessToken, cipherID string) (*EncryptedCipher, error)
func (c *Client) HardDeleteCipher(ctx context.Context, accessToken, cipherID string) error

// Folder CRUD
func (c *Client) CreateFolder(ctx context.Context, accessToken, encryptedName string) (*EncryptedFolder, error)
func (c *Client) UpdateFolder(ctx context.Context, accessToken, folderID, encryptedName string) (*EncryptedFolder, error)
func (c *Client) DeleteFolder(ctx context.Context, accessToken, folderID string) error
```

**Exact Vaultwarden Endpoint Contract (verified against `dani-garcia/vaultwarden` @ `baff1cabae39`)**:

| Operation | Method & Path | Content-Type / Headers | Notes |
| --- | --- | --- | --- |
| Prelogin | `POST /identity/accounts/prelogin` | `application/json` | Body: `{"email": "..."}` -> `{kdf, kdfIterations, kdfMemory, kdfParallelism}` |
| Password login | `POST /identity/connect/token` | `application/x-www-form-urlencoded`; `Auth-Email: <base64url(email)>` | Form: `grant_type=password`, `username`, `password` (MasterPasswordHash), `scope=api offline_access`, `client_id=desktop`, `deviceIdentifier`, `deviceName`, `deviceType` |
| Token refresh | `POST /identity/connect/token` | `application/x-www-form-urlencoded` | Form: `grant_type=refresh_token`, `refresh_token`, `client_id=desktop` |
| Revision date | `GET /api/accounts/revision-date` | `Authorization: Bearer <token>` | Returns Unix ms timestamp (int64) or ISO timestamp; cheap staleness check |
| Full sync | `GET /api/sync?excludeDomains=true` | `Authorization: Bearer <token>` | Returns `profile`, `folders`, `ciphers`, `sends`, `policies`; raw bytes cached directly on disk |
| Create cipher | `POST /api/ciphers` | `application/json`, Bearer | Returns created `EncryptedCipher` |
| Update cipher | `PUT /api/ciphers/{id}` | `application/json`, Bearer | Include `lastKnownRevisionDate` for optimistic concurrency |
| Soft delete | `PUT /api/ciphers/{id}/delete` | Bearer | Moves cipher to Trash (`deletedDate` set) |
| Restore | `PUT /api/ciphers/{id}/restore` | Bearer | Restores cipher from Trash |
| Hard delete | `DELETE /api/ciphers/{id}` | Bearer | Permanently deletes cipher |
| Folder CRUD | `POST /api/folders`, `PUT /api/folders/{id}`, `DELETE /api/folders/{id}` | `application/json`, Bearer | Body: `{"name": "<EncString>"}` |

**Typed API errors**:
- `ErrUnauthorized` (HTTP 401 -> trigger token refresh once; if refresh fails, lock & require re-login)
- `ErrTwoFactorRequired` (HTTP 400 with `TwoFactorProviders` in body -> clear user-facing error noting 2FA login is Phase 2)
- `ErrRevisionConflict` (stale `lastKnownRevisionDate` -> re-sync before retrying write)
- `ErrNetworkOffline` (allow seamless offline read access from local snapshot)

---

#### 1.3 Cipher & Folder Schema — Encrypted vs. Plaintext Field Matrix

| Struct / Field | Wire JSON Key | Encrypted? | Notes |
| --- | --- | --- | --- |
| `Cipher.ID` | `id` | No | UUID |
| `Cipher.Type` | `type` | No | `1`=Login, `2`=SecureNote, `3`=Card, `4`=Identity, `5`=SshKey, `6`=BankAccount, `7`=DriversLicense, `8`=Passport |
| `Cipher.FolderID` | `folderId` | No | Nullable UUID |
| `Cipher.OrganizationID` | `organizationId` | No | Nullable UUID (MVP displays read-only or skips org ciphers until Phase 2) |
| `Cipher.Favorite` | `favorite` | No | `bool` |
| `Cipher.Reprompt` | `reprompt` | No | `0`=None, `1`=Password (re-prompt master password/Touch ID before reveal/copy) |
| `Cipher.Key` | `key` | **Yes (UserKey)** | Optional per-cipher 64B `SymmetricKey`; when present, decrypts all fields below |
| `Cipher.Name` | `name` | **Yes** | Display title |
| `Cipher.Notes` | `notes` | **Yes** | Nullable |
| `Cipher.RevisionDate` / `CreationDate` / `DeletedDate` / `ArchivedDate` | `revisionDate`, etc. | No | ISO 8601 timestamps |
| `Login.Username` / `Password` / `TOTP` | `login.username`, `password`, `totp` | **Yes** | Nullable strings |
| `Login.URIs[].URI` | `login.uris[].uri` | **Yes** | URL/hostname |
| `Login.URIs[].Match` | `login.uris[].match` | No | Nullable int (URI match detection enum) |
| `Login.PasswordRevisionDate` | `login.passwordRevisionDate` | No | Nullable ISO timestamp |
| `SecureNote.Type` | `secureNote.type` | No | `0`=Generic |
| `Card.*` | `card.cardholderName`, `brand`, `number`, `expMonth`, `expYear`, `code` | **Yes** | All 6 string fields encrypted |
| `Identity.*` | `identity.title`, `firstName`, `middleName`, `lastName`, `address1..3`, `city`, `state`, `postalCode`, `country`, `company`, `email`, `phone`, `ssn`, `username`, `passportNumber`, `licenseNumber` | **Yes** | All string fields encrypted |
| `Fields[].Name` / `Value` | `fields[].name`, `value` | **Yes** | Custom fields |
| `Fields[].Type` / `LinkedID` | `fields[].type`, `linkedId` | No | `0`=Text, `1`=Hidden, `2`=Boolean, `3`=Linked |
| `PasswordHistory[].Password` | `passwordHistory[].password` | **Yes** | Historical passwords |
| `PasswordHistory[].LastUsedDate` | `passwordHistory[].lastUsedDate` | No | ISO timestamp |
| `Folder.Name` | `name` | **Yes (UserKey)** | Always encrypted with User Key (folders have no per-folder key) |

---

#### 1.4 `internal/vaultcore/realtime` (SignalR MessagePack WebSocket)

Verified against `dani-garcia/vaultwarden/src/api/notifications.rs` (`baff1cabae39`):

1. **URL**: `wss://<host>/notifications/hub?access_token=<jwt>` (or `ws://` for local HTTP dev).
2. **Handshake**:
   - Client sends text frame: `{"protocol":"messagepack","version":1}\x1e` (note trailing `0x1e` ASCII record separator).
   - Server replies with `{}\x1e` (or error JSON + `0x1e`).
3. **Binary Message Framing**:
   - Every subsequent WebSocket binary frame contains one or more SignalR messages, each prefixed with an **unsigned LEB128 varint** byte length followed by that many bytes of MessagePack payload.
4. **Message Types** (top-level MessagePack array):
   - `[6]` -> **Ping** (server sends every 15s; client replies with varint-prefixed `[6]` or WebSocket Pong to keep connection alive).
   - `[1, headersMap, invocationId, "ReceiveMessage", [argMap]]` -> **Invocation**:
     - `argMap["ContextId"]`: acting device UUID or nil (skip redundant full sync if equal to our own `DeviceID` where appropriate).
     - `argMap["Type"]`: integer `UpdateType`:
       - `0` = `SyncCipherUpdate`
       - `1` = `SyncCipherCreate`
       - `2` = `SyncLoginDelete` (also covers cipher delete)
       - `3` = `SyncFolderDelete`
       - `4` = `SyncCiphers`
       - `5` = `SyncVault`
       - `6` = `SyncOrgKeys`
       - `7` = `SyncFolderCreate`
       - `8` = `SyncFolderUpdate`
       - `10` = `SyncSettings`
       - `11` = `LogOut` (immediately lock vault, wipe tokens/keys, notify UI)
       - `12..14` = Send events (ignored in MVP)
     - `argMap["Payload"]`: map containing `Id`, `UserId`, `RevisionDate`, etc.
5. **Interface**:
   ```go
   package realtime

   type Event struct {
       Type      UpdateType
       ContextID string
       ItemID    string // Cipher or Folder ID when present
   }

   type Client interface {
       Run(ctx context.Context, accessToken func() (string, error), onEvent func(Event)) error
   }
   ```
   - Exponential backoff (`1s -> 2s -> 4s ... max 60s` with jitter) on disconnects.
   - MVP handler strategy: on any `Sync*` event (0–8), debounce 300 ms and trigger a lightweight background sync; on `LogOut` (11), immediately lock and clear session.

---

#### 1.5 `internal/vaultcore/store`, `state`, `totp`, `gen`

```go
// store
type Snapshot struct {
	SchemaVersion int              `json:"schemaVersion"` // 1
	AccountID     string           `json:"accountId"`
	ServerURL     string           `json:"serverUrl"`
	Email         string           `json:"email"`
	KDF           crypto.KDFConfig `json:"kdf"`
	ProtectedKey  string           `json:"protectedKey"` // Server's encrypted User Key
	RevisionDate  time.Time        `json:"revisionDate"`
	LastSyncAt    time.Time        `json:"lastSyncAt"`
	RawSyncJSON   json.RawMessage  `json:"rawSyncJson"` // Raw /api/sync response (100% encrypted fields)
}

type Store interface {
	LoadSnapshot(accountID string) (*Snapshot, error)
	SaveSnapshot(snap *Snapshot) error // atomic temp file -> fsync -> 0600 -> rename
	DeleteSnapshot(accountID string) error
}

// External platform adapters injected by cmd/myvault
type SecretStore interface {
	Get(account string) (string, bool, error)
	Set(account, value string) error
	Delete(account string) error
}

// state
type LockStatus int
const (
	StatusLoggedOut LockStatus = iota
	StatusLocked
	StatusUnlocked
)

type VaultService interface {
	Status() LockStatus
	Login(ctx context.Context, serverURL, email string, masterPassword []byte) error
	UnlockWithPassword(ctx context.Context, masterPassword []byte) error
	UnlockWithUserKey(ctx context.Context, userKey *crypto.SymmetricKey) error // Used after Touch ID
	EnableBiometricUnlock(secrets SecretStore) error
	DisableBiometricUnlock(secrets SecretStore) error
	Lock() // Zeroes UserKey & all decrypted ciphers/folders immediately
	Logout(ctx context.Context, secrets SecretStore) error

	SyncNow(ctx context.Context) error
	Search(query string, filter SearchFilter) []CipherSummary // < 1ms in-memory fuzzy/substring match
	GetCipher(id string) (*Cipher, error)
	SaveCipher(ctx context.Context, c *Cipher) (*Cipher, error)
	SoftDeleteCipher(ctx context.Context, id string) error
	RestoreCipher(ctx context.Context, id string) error
	HardDeleteCipher(ctx context.Context, id string) error
	Folders() []Folder
	SaveFolder(ctx context.Context, f *Folder) (*Folder, error)
	DeleteFolder(ctx context.Context, id string) error
}

// totp
type TOTPConfig struct {
	Secret    []byte // Decoded Base32 secret
	Algorithm string // "SHA1" (default), "SHA256", "SHA512"
	Digits    int    // 6 (default) or 8
	Period    int    // 30 (default)
	Steam     bool   // steam:// prefix support (5-char Steam Guard alphabet, common in Bitwarden)
}

func ParseTOTP(raw string) (*TOTPConfig, error) // Accepts otpauth://totp/..., steam://..., or bare Base32 (spaces/lowercase tolerated)
func Generate(cfg *TOTPConfig, now time.Time) (code string, remainingSec int, period int, err error)

// gen
type PasswordOptions struct {
	Length         int
	Uppercase      bool
	Lowercase      bool
	Numbers        bool
	Special        bool
	MinNumbers     int
	MinSpecial     int
	AvoidAmbiguous bool
}
func GeneratePassword(opts PasswordOptions) (string, error)

type PassphraseOptions struct {
	NumWords   int
	Separator  string
	Capitalize bool
	IncludeNum bool
}
func GeneratePassphrase(opts PassphraseOptions) (string, error)
```

---

---

### 3. Verified Cryptographic & Protocol Test Vector Suite

Every `vaultcore` implementation must pass these exact unit tests before touching a live Vaultwarden server. All Bitwarden vectors below are verbatim from `bitwarden/sdk-internal` (`c5c08aebe883`, accessed 2026-11-20) and independently cross-checked.

#### Vector 1: KDF Parameter Minimums (`crypto.ValidateKDF`)
Must reject with error:
- PBKDF2 `iterations = 4999` (minimum `5000`)
- Argon2id `iterations = 1, memory = 16, parallelism = 1` (minimum `iterations >= 2`)
- Argon2id `iterations = 2, memory = 15, parallelism = 1` (minimum `memory >= 16 MiB`)
- Argon2id `iterations = 1, memory = 15, parallelism = 1`

#### Vector 2: PBKDF2-SHA256 Master Key Derivation
- Password: `"67t9b5g67$%Dh89n"`
- Salt (normalized email): `"test_key"`
- KDF: `PBKDF2`, `iterations = 10000`
- Expected 32-byte `MasterKey` (hex):
  `1f4f68e29647b15ac250acd1118184518aa745a7fe95021b27c5402a16c3564b`

#### Vector 3: Argon2id Master Key Derivation
- Password: `"67t9b5g67$%Dh89n"`
- Salt (normalized email, internally hashed with SHA-256 before Argon2id): `"test_key"`
- KDF: `Argon2id`, `iterations = 4`, `memory = 32` (MiB = `32768` KiB), `parallelism = 2`
- Expected 32-byte `MasterKey` (hex):
  `cff0e1b1a213a34c626ab3afe00911f01493ed2ff6968db83ee183f23335e1f2`

#### Vector 4: HKDF-Expand Key Stretching (No Extract!)
- Input `MasterKey` (from Vector 2):
  `1f4f68e29647b15ac250acd1118184518aa745a7fe95021b27c5402a16c3564b`
- `HKDF-Expand(SHA256, PRK=MasterKey, info="enc", 32)` (hex):
  `6f1fb22dee9825728fd77c5387adc3178e8678f93d84a3b671c5bdccbc15ed60`
- `HKDF-Expand(SHA256, PRK=MasterKey, info="mac", 32)` (hex):
  `dd7fceea651bca265634221c4e1cb910303d7fa6d1f7c257e81a3055c1f9b39b`

#### Vector 5: Master Password Auth Hash (PBKDF2 + Email Normalization)
- Password: `"asdfasdf"`
- Salts (all 3 must produce identical output after normalization):
  `"test@bitwarden.com"`, `"TEST@bitwarden.com"`, `" test@bitwarden.com"`
- KDF: `PBKDF2`, `iterations = 100000`
- Expected `MasterPasswordHash` (Base64):
  `wmyadRMyBZOH7P/a/ucTCbSghKgdzDpPqUnu/DAVtSw=`

#### Vector 6: Master Password Auth Hash (Argon2id)
- Password: `"asdfasdf"`
- Salt: `"test_salt"`
- KDF: `Argon2id`, `iterations = 4`, `memory = 32`, `parallelism = 2`
- Expected `MasterPasswordHash` (Base64):
  `PR6UjYmjmppTYcdyTiNbAhPJuQQOmynKbdEl1oyi/iQ=`

#### Vector 7: Type 2 Symmetric Encrypt/Decrypt (`AesCbc256_HmacSha256_B64`)
- Key (64 bytes): `enc = [0..31]`, `mac = [32..63]` (`000102...3f`)
- IV (16 bytes, hex): `d8da2400c4ba965531936ea8b9e32aac`
- Plaintext: `"Bitwarden SDK test vector"`
- Expected EncString:
  `2.2NokAMS6llUxk26oueMqrA==|6k0QD71SJLy2WEBDkV4esiTrgkP/z7eoSedSesGLGYE=|PE4sb0jpAwZW+tnyPuW43eeWvSxjvdw3xMJlPGbDlYI=`
- **Negative tamper tests (mandatory)**:
  - Flip 1 bit in `IV` -> must return `ErrInvalidMAC` (never decrypt).
  - Flip 1 bit in `CT` -> must return `ErrInvalidMAC`.
  - Flip 1 bit in `MAC` -> must return `ErrInvalidMAC`.
  - Pass Type 0 string to `DecryptString` -> must return `ErrUnsupportedEncType`.

#### Vector 8: Legacy Type 0 User Key Unwrap (`DecryptUserKey` compatibility)
- Password: `"asdfasdfasdf"`, Salt: `"legacy@bitwarden.com"`, KDF: `PBKDF2`, `iterations = 600000`
- Protected `Key`:
  `0.8UClLa8IPE1iZT7chy5wzQ==|6PVfHnVk5S3XqEtQemnM5yb4JodxmPkkWzmDRdfyHtjORmvxqlLX40tBJZ+CKxQWmS8tpEB5w39rbgHg/gqs0haGdZG4cPbywsgGzxZ7uNI=`
- Expected 64-byte `UserKey`:
  - `Enc` (hex): `0c5f97cb2504ec4389615a3a067ff21cd1a87d1d7618d52c75ca027384a57d94`
  - `Mac` (hex): `bad7ea8918a9e31dda39b4ed495bbd33fd1a1134e204864bc2d0b28580e08ca7`

#### Vector 9: TOTP (RFC 6238 + Bitwarden Formats)
- RFC 6238 SHA-1 (8 digits, period 30s, ASCII secret `"12345678901234567890"` = Base32 `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`):
  - `t = 59` -> `"94287082"`
  - `t = 1111111109` -> `"07081804"`
  - `t = 1234567890` -> `"89005924"`
  - `t = 2000000000` -> `"69279037"`
- Bitwarden input parser cases:
  - Bare Base32 with spaces/lowercase: `"jbsw y3dp ehpk 3pxp"` -> 6 digits, 30s, SHA1.
  - Standard URI: `"otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=6&period=30"`.
  - Missing padding `=` in Base32 secret -> accepted cleanly.

#### Vector 10: SignalR MessagePack Framing (`realtime`)
- Handshake outgoing: `{"protocol":"messagepack","version":1}\x1e`
- Ping frame: `[0x02, 0x91, 0x06]` (varint length `2`, 1-element msgpack array `[6]`).
- `ReceiveMessage` invocation frame: decode `[1, {}, nil, "ReceiveMessage", [{"ContextId": "dev-1", "Type": 0, "Payload": {"Id": "cipher-1"}}]]` -> emits `Event{Type: SyncCipherUpdate, ContextID: "dev-1", ItemID: "cipher-1"}`.
- Multiple varint-prefixed messages concatenated inside a single WebSocket binary frame -> must parse all messages in order.

## Acceptance Criteria

- [ ] All 10 test vector suites pass under `CGO_ENABLED=0 go test ./internal/vaultcore/...`.
- [ ] `go list -deps ./internal/vaultcore/...` contains zero GUI packages.
- [ ] End-to-end integration test against a local Vaultwarden Docker container passes login, sync, cipher CRUD (including a cipher with a per-cipher `key`), folder CRUD, soft-delete/restore, and real-time SignalR push update.
- [ ] Copied secrets are marked confidential (`mygo.ClipboardOptions{Concealed: true}`) and cleared after the configured delay if the clipboard still holds them.

## Risks

- **Bitwarden v2 blob cipher format (`cipher.data`)**: Vaultwarden `CipherData` includes an optional sealed `data` blob for future v2 accounts; MVP supports standard v1 field-encrypted ciphers and must fail gracefully with a clear message if an unsupported v2 blob cipher is encountered.
- **Per-cipher key rotation / creation**: Modern official clients may create ciphers with a per-cipher `key`. MyVault MVP decrypts `cipher.key` when reading and preserves `cipher.key` when updating an existing cipher (re-encrypting fields with that same `cipherKey`).

## Related Documents

- [Architecture & MVP Design](architecture.md)
- [Official Bitwarden Desktop Client and Vaultwarden Protocol](research/official-client-and-protocol.md)
