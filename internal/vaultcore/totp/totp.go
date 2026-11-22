package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultAlgorithm = "SHA1"
	defaultDigits    = 6
	defaultPeriod    = 30
	steamDigits      = 5
	steamAlphabet    = "23456789BCDFGHJKMNPQRTVWXY"
)

var (
	ErrInvalidTOTP      = errors.New("totp: invalid TOTP input")
	ErrInvalidSecret    = errors.New("totp: invalid Base32 secret")
	ErrUnsupportedParam = errors.New("totp: unsupported TOTP parameter")
)

type TOTPConfig struct {
	Secret    []byte
	Algorithm string
	Digits    int
	Period    int
	Steam     bool
}

func ParseTOTP(raw string) (*TOTPConfig, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, ErrInvalidTOTP
	}

	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(lower, "steam://"):
		secret, err := decodeBase32Secret(s[len("steam://"):])
		if err != nil {
			return nil, err
		}
		return &TOTPConfig{
			Secret:    secret,
			Algorithm: defaultAlgorithm,
			Digits:    steamDigits,
			Period:    defaultPeriod,
			Steam:     true,
		}, nil

	case strings.HasPrefix(lower, "otpauth://"):
		return parseOTPAuthURI(s)

	default:
		secret, err := decodeBase32Secret(s)
		if err != nil {
			return nil, err
		}
		return &TOTPConfig{
			Secret:    secret,
			Algorithm: defaultAlgorithm,
			Digits:    defaultDigits,
			Period:    defaultPeriod,
		}, nil
	}
}

func parseOTPAuthURI(raw string) (*TOTPConfig, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTOTP, err)
	}
	if !strings.EqualFold(u.Host, "totp") {
		return nil, fmt.Errorf("%w: unsupported otpauth type %q", ErrUnsupportedParam, u.Host)
	}

	q := u.Query()
	secret, err := decodeBase32Secret(q.Get("secret"))
	if err != nil {
		return nil, err
	}

	cfg := &TOTPConfig{
		Secret:    secret,
		Algorithm: defaultAlgorithm,
		Digits:    defaultDigits,
		Period:    defaultPeriod,
	}

	if alg := strings.ToUpper(strings.TrimSpace(q.Get("algorithm"))); alg != "" {
		if _, ok := hashFunc(alg); !ok {
			return nil, fmt.Errorf("%w: algorithm %q", ErrUnsupportedParam, alg)
		}
		cfg.Algorithm = alg
	}

	if strings.EqualFold(strings.TrimSpace(q.Get("encoder")), "steam") {
		cfg.Steam = true
		cfg.Digits = steamDigits
	}

	if d := strings.TrimSpace(q.Get("digits")); d != "" {
		digits, err := strconv.Atoi(d)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid digits %q", ErrInvalidTOTP, d)
		}
		if cfg.Steam {
			if digits != steamDigits {
				return nil, fmt.Errorf("%w: steam digits %d", ErrUnsupportedParam, digits)
			}
		} else if digits != 6 && digits != 8 {
			return nil, fmt.Errorf("%w: digits %d", ErrUnsupportedParam, digits)
		}
		cfg.Digits = digits
	}

	if p := strings.TrimSpace(q.Get("period")); p != "" {
		period, err := strconv.Atoi(p)
		if err != nil || period <= 0 {
			return nil, fmt.Errorf("%w: invalid period %q", ErrInvalidTOTP, p)
		}
		cfg.Period = period
	}

	return cfg, nil
}

func Generate(cfg *TOTPConfig, now time.Time) (string, int, int, error) {
	if cfg == nil || len(cfg.Secret) == 0 {
		return "", 0, 0, ErrInvalidSecret
	}

	period := cfg.Period
	if period == 0 {
		period = defaultPeriod
	}
	if period < 0 {
		return "", 0, 0, fmt.Errorf("%w: period %d", ErrUnsupportedParam, period)
	}

	alg := strings.ToUpper(strings.TrimSpace(cfg.Algorithm))
	if alg == "" {
		alg = defaultAlgorithm
	}
	hFn, ok := hashFunc(alg)
	if !ok {
		return "", 0, 0, fmt.Errorf("%w: algorithm %q", ErrUnsupportedParam, alg)
	}

	unix := now.Unix()
	if unix < 0 {
		return "", 0, 0, fmt.Errorf("%w: negative timestamp", ErrInvalidTOTP)
	}

	counter := uint64(unix / int64(period))
	remaining := period - int(unix%int64(period))

	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)

	mac := hmac.New(hFn, cfg.Secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	truncated := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])

	if cfg.Steam {
		var out [steamDigits]byte
		v := truncated
		alphaLen := uint32(len(steamAlphabet))
		for i := range out {
			out[i] = steamAlphabet[v%alphaLen]
			v /= alphaLen
		}
		return string(out[:]), remaining, period, nil
	}

	digits := cfg.Digits
	if digits == 0 {
		digits = defaultDigits
	}
	var mod uint32
	switch digits {
	case 6:
		mod = 1_000_000
	case 8:
		mod = 100_000_000
	default:
		return "", 0, 0, fmt.Errorf("%w: digits %d", ErrUnsupportedParam, digits)
	}

	return fmt.Sprintf("%0*d", digits, truncated%mod), remaining, period, nil
}

func decodeBase32Secret(raw string) ([]byte, error) {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r', '-', '=':
			return -1
		default:
			return r
		}
	}, strings.ToUpper(raw))
	if cleaned == "" {
		return nil, ErrInvalidSecret
	}

	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(cleaned)
	if err != nil || len(secret) == 0 {
		return nil, ErrInvalidSecret
	}
	return secret, nil
}

func hashFunc(alg string) (func() hash.Hash, bool) {
	switch alg {
	case "SHA1":
		return sha1.New, true
	case "SHA256":
		return sha256.New, true
	case "SHA512":
		return sha512.New, true
	default:
		return nil, false
	}
}
