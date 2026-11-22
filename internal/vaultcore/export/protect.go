package export

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/oneryx/myvault/internal/vaultcore/crypto"
)

var (
	ErrWrongPassword      = errors.New("export: the backup password is incorrect")
	ErrAccountRestricted  = errors.New("export: this backup is encrypted with its account key; export it again with a password")
	ErrNotBitwardenExport = errors.New("export: not a Bitwarden JSON export")
)

// MaxFileSize bounds the export files read.
const MaxFileSize = 64 << 20

// DefaultKDF is the KDF Bitwarden clients use for new password-protected
// exports: PBKDF2-SHA256 with 600,000 iterations.
var DefaultKDF = crypto.KDFConfig{Type: crypto.KDFPBKDF2, Iterations: 600_000}

// protectedFile is the Bitwarden password-protected encrypted JSON export.
// The key is the export password stretched like a master key, salted with
// salt as is; encKeyValidation_DO_NOT_EDIT is a random value encrypted with
// it, which tells a wrong password from a damaged file.
type protectedFile struct {
	Encrypted         bool    `json:"encrypted"`
	PasswordProtected bool    `json:"passwordProtected"`
	Salt              string  `json:"salt"`
	KDFType           int     `json:"kdfType"`
	KDFIterations     uint32  `json:"kdfIterations"`
	KDFMemory         *uint32 `json:"kdfMemory"`
	KDFParallelism    *uint32 `json:"kdfParallelism"`
	EncKeyValidation  string  `json:"encKeyValidation_DO_NOT_EDIT"`
	Data              string  `json:"data"`
}

func deriveKey(password []byte, salt string, cfg crypto.KDFConfig) (*crypto.SymmetricKey, error) {
	master, err := crypto.DeriveKeyFromPassword(password, salt, cfg)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(master[:])
	return crypto.StretchMasterKey(master)
}

// EncryptWithPassword returns v as a password-protected Bitwarden export.
// ErrBackupTooLarge means the encrypted backup would exceed MaxFileSize,
// which Read refuses, so it is not written.
var ErrBackupTooLarge = fmt.Errorf("export: the encrypted backup would be larger than %d MiB, which MyVault cannot import back", MaxFileSize>>20)

func EncryptWithPassword(v *Vault, password []byte, cfg crypto.KDFConfig) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("export: a backup password is required")
	}
	var saltBytes [16]byte
	if _, err := rand.Read(saltBytes[:]); err != nil {
		return nil, err
	}
	salt := base64.StdEncoding.EncodeToString(saltBytes[:])
	key, err := deriveKey(password, salt, cfg)
	if err != nil {
		return nil, err
	}
	defer key.Zero()

	plain := *v
	plain.Encrypted = false
	plaintext, err := json.Marshal(plain)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(plaintext)
	data, err := crypto.EncryptBytes(plaintext, key)
	if err != nil {
		return nil, err
	}
	validation, err := crypto.EncryptString(randomGUID(), key)
	if err != nil {
		return nil, err
	}
	f := protectedFile{
		Encrypted: true, PasswordProtected: true, Salt: salt,
		KDFType: int(cfg.Type), KDFIterations: cfg.Iterations,
		EncKeyValidation: validation, Data: data.String(),
	}
	if cfg.Type == crypto.KDFArgon2id {
		mem, par := cfg.MemoryMB, cfg.Parallelism
		f.KDFMemory, f.KDFParallelism = &mem, &par
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err == nil && len(out) > MaxFileSize {
		crypto.ZeroBytes(out)
		return nil, ErrBackupTooLarge
	}
	return out, err
}

// NeedsPassword reports whether data is a password-protected export.
func NeedsPassword(data []byte) (bool, error) {
	var head struct {
		Encrypted         bool `json:"encrypted"`
		PasswordProtected bool `json:"passwordProtected"`
		Items             json.RawMessage
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return false, ErrNotBitwardenExport
	}
	switch {
	case head.Encrypted && head.PasswordProtected:
		return true, nil
	case head.Encrypted:
		return false, ErrAccountRestricted
	case head.Items == nil:
		return false, ErrNotBitwardenExport
	}
	return false, nil
}

// Read parses a plain export, or decrypts a password-protected one with
// password.
func Read(data []byte, password []byte) (*Vault, error) {
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("export: file larger than %d MiB", MaxFileSize>>20)
	}
	protected, err := NeedsPassword(data)
	if err != nil {
		return nil, err
	}
	if !protected {
		var v Vault
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, ErrNotBitwardenExport
		}
		return &v, nil
	}

	var f protectedFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, ErrNotBitwardenExport
	}
	cfg := crypto.KDFConfig{Type: crypto.KDFType(f.KDFType), Iterations: f.KDFIterations}
	if f.KDFMemory != nil {
		cfg.MemoryMB = *f.KDFMemory
	}
	if f.KDFParallelism != nil {
		cfg.Parallelism = *f.KDFParallelism
	}
	key, err := deriveKey(password, f.Salt, cfg)
	if err != nil {
		return nil, err
	}
	defer key.Zero()
	if _, err := crypto.DecryptString(f.EncKeyValidation, key); err != nil {
		return nil, ErrWrongPassword
	}
	enc, err := crypto.ParseEncString(f.Data)
	if err != nil {
		return nil, ErrNotBitwardenExport
	}
	plaintext, err := crypto.DecryptBytes(enc, key)
	if err != nil {
		return nil, ErrWrongPassword
	}
	defer crypto.ZeroBytes(plaintext)
	var v Vault
	if err := json.Unmarshal(plaintext, &v); err != nil {
		return nil, ErrNotBitwardenExport
	}
	return &v, nil
}

func randomGUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
