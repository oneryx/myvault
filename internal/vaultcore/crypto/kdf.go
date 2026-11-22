package crypto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"runtime/debug"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

type KDFType int

const (
	KDFPBKDF2   KDFType = 0
	KDFArgon2id KDFType = 1
)

type KDFConfig struct {
	Type        KDFType `json:"kdf"`
	Iterations  uint32  `json:"kdfIterations"`
	MemoryMB    uint32  `json:"kdfMemory,omitempty"`
	Parallelism uint32  `json:"kdfParallelism,omitempty"`
}

const (
	minPBKDF2Iterations  uint32 = 5000
	maxPBKDF2Iterations  uint32 = 2_000_000
	minArgon2Iterations  uint32 = 2
	maxArgon2Iterations  uint32 = 20
	minArgon2MemoryMB    uint32 = 16
	maxArgon2MemoryMB    uint32 = 1024
	minArgon2Parallelism uint32 = 1
	maxArgon2Parallelism uint32 = 16
)

func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func ValidateKDF(cfg KDFConfig) error {
	switch cfg.Type {
	case KDFPBKDF2:
		if cfg.Iterations < minPBKDF2Iterations || cfg.Iterations > maxPBKDF2Iterations {
			return fmt.Errorf("%w: PBKDF2 iterations %d out of range", ErrInvalidKDF, cfg.Iterations)
		}
		return nil
	case KDFArgon2id:
		if cfg.Iterations < minArgon2Iterations || cfg.Iterations > maxArgon2Iterations {
			return fmt.Errorf("%w: Argon2id iterations %d out of range", ErrInvalidKDF, cfg.Iterations)
		}
		if cfg.MemoryMB < minArgon2MemoryMB || cfg.MemoryMB > maxArgon2MemoryMB {
			return fmt.Errorf("%w: Argon2id memory %d MiB out of range", ErrInvalidKDF, cfg.MemoryMB)
		}
		if cfg.Parallelism < minArgon2Parallelism || cfg.Parallelism > maxArgon2Parallelism {
			return fmt.Errorf("%w: Argon2id parallelism %d out of range", ErrInvalidKDF, cfg.Parallelism)
		}
		return nil
	default:
		return fmt.Errorf("%w: unknown KDF type %d", ErrInvalidKDF, cfg.Type)
	}
}

func DeriveMasterKey(password []byte, email string, cfg KDFConfig) ([32]byte, error) {
	return DeriveKeyFromPassword(password, NormalizeEmail(email), cfg)
}

// DeriveKeyFromPassword is the Bitwarden password KDF with salt used as is,
// as for the master key (salted with the normalized email) and for
// password-protected exports (salted with a random string).
func DeriveKeyFromPassword(password []byte, salt string, cfg KDFConfig) ([32]byte, error) {
	var masterKey [32]byte
	if err := ValidateKDF(cfg); err != nil {
		return masterKey, err
	}

	switch cfg.Type {
	case KDFPBKDF2:
		raw := pbkdf2.Key(password, []byte(salt), int(cfg.Iterations), 32, sha256.New)
		copy(masterKey[:], raw)
		ZeroBytes(raw)
		return masterKey, nil
	case KDFArgon2id:
		saltHash := sha256.Sum256([]byte(salt))
		raw := argon2.IDKey(password, saltHash[:], cfg.Iterations, cfg.MemoryMB*1024, uint8(cfg.Parallelism), 32)
		copy(masterKey[:], raw)
		ZeroBytes(raw)
		ZeroBytes(saltHash[:])
		// Reclaim the transient 32-64 MiB Argon2id working set promptly.
		debug.FreeOSMemory()
		return masterKey, nil
	default:
		return masterKey, ErrInvalidKDF
	}
}

func HashMasterPasswordForServer(masterKey [32]byte, password []byte) string {
	derived := pbkdf2.Key(masterKey[:], password, 1, 32, sha256.New)
	defer ZeroBytes(derived)
	return base64.StdEncoding.EncodeToString(derived)
}

func StretchMasterKey(masterKey [32]byte) (*SymmetricKey, error) {
	// Bitwarden stretches masterKey via HKDF-Expand directly (no HKDF-Extract).
	enc, err := hkdf.Expand(sha256.New, masterKey[:], "enc", 32)
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(enc)

	mac, err := hkdf.Expand(sha256.New, masterKey[:], "mac", 32)
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(mac)

	k := &SymmetricKey{}
	copy(k.Enc[:], enc)
	copy(k.Mac[:], mac)
	return k, nil
}
