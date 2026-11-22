package crypto

import (
	"crypto/aes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

type EncType int

const (
	EncAesCbc256B64           EncType = 0
	EncAesCbc256HmacSha256B64 EncType = 2
	EncRsa2048OaepSha256B64   EncType = 3
	EncRsa2048OaepSha1B64     EncType = 4

	EncRsa2048OaepSha256HmacSha256B64 EncType = 5
	EncRsa2048OaepSha1HmacSha256B64   EncType = 6
)

type EncString struct {
	Type EncType
	IV   []byte
	CT   []byte
	MAC  []byte
}

func ParseEncString(s string) (*EncString, error) {
	typeStr, body, ok := strings.Cut(s, ".")
	if !ok || typeStr == "" || body == "" {
		return nil, ErrInvalidEncString
	}

	typeNum, err := strconv.Atoi(typeStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid type prefix", ErrInvalidEncString)
	}
	encType := EncType(typeNum)

	switch encType {
	case EncAesCbc256B64:
		parts := strings.Split(body, "|")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, ErrInvalidEncString
		}
		iv, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil || len(iv) != aes.BlockSize {
			return nil, ErrInvalidEncString
		}
		ct, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil || len(ct) == 0 {
			return nil, ErrInvalidEncString
		}
		return &EncString{Type: encType, IV: iv, CT: ct}, nil

	case EncAesCbc256HmacSha256B64:
		parts := strings.Split(body, "|")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			return nil, ErrInvalidEncString
		}
		iv, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil || len(iv) != aes.BlockSize {
			return nil, ErrInvalidEncString
		}
		ct, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil || len(ct) == 0 {
			return nil, ErrInvalidEncString
		}
		mac, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil || len(mac) != sha256.Size {
			return nil, ErrInvalidEncString
		}
		return &EncString{Type: encType, IV: iv, CT: ct, MAC: mac}, nil

	case EncRsa2048OaepSha256B64, EncRsa2048OaepSha1B64:
		if strings.Contains(body, "|") {
			return nil, ErrInvalidEncString
		}
		ct, err := base64.StdEncoding.DecodeString(body)
		if err != nil || len(ct) == 0 {
			return nil, ErrInvalidEncString
		}
		return &EncString{Type: encType, CT: ct}, nil

	case EncRsa2048OaepSha256HmacSha256B64, EncRsa2048OaepSha1HmacSha256B64:
		parts := strings.Split(body, "|")
		if len(parts) > 2 || parts[0] == "" {
			return nil, ErrInvalidEncString
		}
		ct, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil || len(ct) == 0 {
			return nil, ErrInvalidEncString
		}
		out := &EncString{Type: encType, CT: ct}
		if len(parts) == 2 {
			if out.MAC, err = base64.StdEncoding.DecodeString(parts[1]); err != nil {
				return nil, ErrInvalidEncString
			}
		}
		return out, nil

	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedEncType, encType)
	}
}

func (e *EncString) String() string {
	if e == nil {
		return ""
	}
	switch e.Type {
	case EncAesCbc256B64:
		return strconv.Itoa(int(e.Type)) + "." +
			base64.StdEncoding.EncodeToString(e.IV) + "|" +
			base64.StdEncoding.EncodeToString(e.CT)
	case EncAesCbc256HmacSha256B64:
		return strconv.Itoa(int(e.Type)) + "." +
			base64.StdEncoding.EncodeToString(e.IV) + "|" +
			base64.StdEncoding.EncodeToString(e.CT) + "|" +
			base64.StdEncoding.EncodeToString(e.MAC)
	case EncRsa2048OaepSha256B64, EncRsa2048OaepSha1B64:
		return strconv.Itoa(int(e.Type)) + "." +
			base64.StdEncoding.EncodeToString(e.CT)
	case EncRsa2048OaepSha256HmacSha256B64, EncRsa2048OaepSha1HmacSha256B64:
		out := strconv.Itoa(int(e.Type)) + "." + base64.StdEncoding.EncodeToString(e.CT)
		if len(e.MAC) > 0 {
			out += "|" + base64.StdEncoding.EncodeToString(e.MAC)
		}
		return out
	default:
		return ""
	}
}

// EncStringKind classifies a string that may be an EncString.
type EncStringKind int

const (
	// NotEncString is plain text.
	NotEncString EncStringKind = iota
	// IsEncString is an EncString of a known type with its exact structure.
	IsEncString
	// MaybeEncString has a type MyVault does not know and a body that could
	// be ciphertext; it cannot be told apart from plain text safely.
	MaybeEncString
)

// encAesCbc128HmacSha256B64 is the retired type 1 (iv|ct|mac), which
// MyVault never decrypts but must still recognize.
const encAesCbc128HmacSha256B64 EncType = 1

// ClassifyEncString tells whether s is an EncString. For every type
// ParseEncString knows, s is an EncString exactly when ParseEncString
// accepts it; type 1 uses the same structure as type 2. Any other numeric
// type with a base64 body is MaybeEncString.
func ClassifyEncString(s string) EncStringKind {
	typeStr, body, ok := strings.Cut(s, ".")
	if !ok || typeStr == "" || len(typeStr) > 3 {
		return NotEncString
	}
	for _, r := range typeStr {
		if r < '0' || r > '9' {
			return NotEncString
		}
	}
	t, _ := strconv.Atoi(typeStr)
	switch EncType(t) {
	case EncAesCbc256B64, EncAesCbc256HmacSha256B64, EncRsa2048OaepSha256B64, EncRsa2048OaepSha1B64,
		EncRsa2048OaepSha256HmacSha256B64, EncRsa2048OaepSha1HmacSha256B64:
		if _, err := ParseEncString(s); err == nil {
			return IsEncString
		}
		return NotEncString
	case encAesCbc128HmacSha256B64:
		if _, err := ParseEncString("2." + body); err == nil {
			return IsEncString
		}
		return NotEncString
	}
	parts := strings.Split(body, "|")
	for _, p := range parts {
		if b, err := base64.StdEncoding.DecodeString(p); err != nil || len(b) == 0 {
			return NotEncString
		}
	}
	return MaybeEncString
}
