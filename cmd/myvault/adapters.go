package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/transfer"
	vaultapp "github.com/oneryx/myvault/cmd/myvault/app"
	"github.com/oneryx/myvault/internal/vaultcore/crypto"
	"github.com/oneryx/myvault/internal/vaultcore/store"
)

// secretService is the keychain service of every secret. It is the bundle
// identifier in mygo.json, set here so `go run` builds, which have no
// bundle, share the installed app's secrets.
const secretService = "io.github.oneryx.myvault"

// SecretStoreAdapter keeps secrets in the system's credential store.
type SecretStoreAdapter struct{}

func (SecretStoreAdapter) Get(account string) (string, bool, error) {
	v, err := mygo.Secrets.Service(secretService).Get(account)
	if errors.Is(err, mygo.ErrSecretNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return string(v), true, nil
}

func (SecretStoreAdapter) Set(account, value string) error {
	return mygo.Secrets.Service(secretService).Set(account, []byte(value))
}

func (SecretStoreAdapter) Delete(account string) error {
	return mygo.Secrets.Service(secretService).Delete(account)
}

// ClipboardAdapter copies secrets marked as confidential, and clears them
// after a while, or as the app quits, if the clipboard still holds them.
type ClipboardAdapter struct {
	mu    sync.Mutex
	timer *time.Timer
	owned string
}

func NewClipboardAdapter() *ClipboardAdapter { return &ClipboardAdapter{} }

func (c *ClipboardAdapter) CopySecret(secret string, clearAfter time.Duration) (bool, error) {
	err := mygo.Clipboard.Write(transfer.TextData(secret), mygo.ClipboardOptions{Concealed: true})
	if err != nil {
		return false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.owned = secret
	if clearAfter > 0 {
		c.timer = time.AfterFunc(clearAfter, func() { c.clear(secret) })
	}
	return true, nil
}

func (c *ClipboardAdapter) CopyPlain(text string) {
	mygo.Clipboard.WriteText(text)
}

// clear empties the clipboard if it still holds secret.
func (c *ClipboardAdapter) clear(secret string) {
	c.mu.Lock()
	owned := c.owned == secret
	if owned {
		c.owned = ""
	}
	c.mu.Unlock()
	if owned && mygo.Clipboard.ReadText() == secret {
		mygo.Clipboard.Clear()
	}
}

// ClearOnQuit clears a secret still waiting to be cleared.
func (c *ClipboardAdapter) ClearOnQuit() {
	c.mu.Lock()
	owned := c.owned
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.mu.Unlock()
	if owned != "" {
		c.clear(owned)
	}
}

func DiscoverAccountSnapshot(dataDir, preferredAccountID string) *vaultapp.AccountSnapshotMeta {
	fs := store.NewFileStore(dataDir)
	if preferredAccountID != "" {
		if snap, err := fs.LoadSnapshot(preferredAccountID); err == nil {
			return snapshotToMeta(snap)
		}
	}

	ids, _ := fs.ListAccounts()
	var latest *store.Snapshot
	var latestSync time.Time
	for _, id := range ids {
		snap, err := fs.LoadSnapshot(id)
		if err != nil {
			continue
		}
		if latest == nil || snap.LastSyncAt.After(latestSync) {
			latest, latestSync = snap, snap.LastSyncAt
		}
	}
	if latest == nil {
		return nil
	}
	return snapshotToMeta(latest)
}

func VerifyMasterPasswordOffline(dataDir, accountID string, password []byte) error {
	if accountID == "" {
		return errors.New("no active account")
	}
	snap, err := store.NewFileStore(dataDir).LoadSnapshot(accountID)
	if err != nil {
		return err
	}
	masterKey, err := crypto.DeriveMasterKey(password, snap.Email, snap.KDF)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(masterKey[:])

	userKey, err := crypto.DecryptUserKey(snap.ProtectedKey, masterKey)
	if err != nil {
		return err
	}
	userKey.Zero()
	return nil
}

func snapshotToMeta(snap *store.Snapshot) *vaultapp.AccountSnapshotMeta {
	return &vaultapp.AccountSnapshotMeta{
		AccountID:  snap.AccountID,
		ServerURL:  snap.ServerURL,
		Email:      snap.Email,
		KDFSummary: formatKDFSummary(snap.KDF),
		LastSyncAt: snap.LastSyncAt,
	}
}

func formatKDFSummary(kdf crypto.KDFConfig) string {
	switch kdf.Type {
	case crypto.KDFArgon2id:
		return fmt.Sprintf("Argon2id (%d iter, %d MiB, %d threads)", kdf.Iterations, kdf.MemoryMB, kdf.Parallelism)
	default:
		return fmt.Sprintf("PBKDF2-SHA256 (%d iterations)", kdf.Iterations)
	}
}

func ensureDataDir() string {
	dir, _ := mygo.App.Path(mygo.PathUserData)
	if dir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			dir = filepath.Join(home, ".myvault")
		} else {
			dir = os.TempDir()
		}
	}
	_ = os.MkdirAll(dir, 0o700)
	return dir
}

func deviceTypeForOS() int {
	switch runtime.GOOS {
	case "darwin":
		return 7 // macOS Desktop
	case "linux":
		return 8 // Linux Desktop
	default:
		return 6 // Windows Desktop
	}
}
