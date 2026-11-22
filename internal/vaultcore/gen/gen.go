package gen

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
)

const (
	uppercaseAll   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	uppercaseClear = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	lowercaseAll   = "abcdefghijklmnopqrstuvwxyz"
	lowercaseClear = "abcdefghijkmnpqrstuvwxyz"
	numbersAll     = "0123456789"
	numbersClear   = "23456789"
	specialChars   = "!@#$%^&*"
)

var ErrInvalidOptions = errors.New("gen: invalid generator options")

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

type PassphraseOptions struct {
	NumWords   int
	Separator  string
	Capitalize bool
	IncludeNum bool
}

type charRequirement struct {
	charset string
	min     int
}

func GeneratePassword(opts PasswordOptions) (string, error) {
	if opts.Length <= 0 || opts.MinNumbers < 0 || opts.MinSpecial < 0 {
		return "", ErrInvalidOptions
	}
	if opts.MinNumbers > 0 && !opts.Numbers {
		return "", fmt.Errorf("%w: MinNumbers requires Numbers", ErrInvalidOptions)
	}
	if opts.MinSpecial > 0 && !opts.Special {
		return "", fmt.Errorf("%w: MinSpecial requires Special", ErrInvalidOptions)
	}

	var reqs []charRequirement
	var pool strings.Builder

	if opts.Uppercase {
		cs := uppercaseAll
		if opts.AvoidAmbiguous {
			cs = uppercaseClear
		}
		reqs = append(reqs, charRequirement{charset: cs, min: 1})
		pool.WriteString(cs)
	}
	if opts.Lowercase {
		cs := lowercaseAll
		if opts.AvoidAmbiguous {
			cs = lowercaseClear
		}
		reqs = append(reqs, charRequirement{charset: cs, min: 1})
		pool.WriteString(cs)
	}
	if opts.Numbers {
		cs := numbersAll
		if opts.AvoidAmbiguous {
			cs = numbersClear
		}
		minCount := opts.MinNumbers
		if minCount == 0 {
			minCount = 1
		}
		reqs = append(reqs, charRequirement{charset: cs, min: minCount})
		pool.WriteString(cs)
	}
	if opts.Special {
		minCount := opts.MinSpecial
		if minCount == 0 {
			minCount = 1
		}
		reqs = append(reqs, charRequirement{charset: specialChars, min: minCount})
		pool.WriteString(specialChars)
	}

	if len(reqs) == 0 {
		return "", fmt.Errorf("%w: at least one character class must be enabled", ErrInvalidOptions)
	}

	totalMin := 0
	for _, r := range reqs {
		totalMin += r.min
	}
	if totalMin > opts.Length {
		return "", fmt.Errorf("%w: minimum character requirements (%d) exceed length (%d)", ErrInvalidOptions, totalMin, opts.Length)
	}

	out := make([]byte, 0, opts.Length)
	for _, r := range reqs {
		for range r.min {
			ch, err := randomChar(r.charset)
			if err != nil {
				return "", err
			}
			out = append(out, ch)
		}
	}

	allChars := pool.String()
	for len(out) < opts.Length {
		ch, err := randomChar(allChars)
		if err != nil {
			return "", err
		}
		out = append(out, ch)
	}

	if err := shuffleBytes(out); err != nil {
		return "", err
	}
	return string(out), nil
}

// PassphraseBits is the entropy of a passphrase GeneratePassphrase makes
// with opts: each word drawn from the word list, plus, with IncludeNum, a
// digit and the word it is added to. Capitalizing adds none.
func PassphraseBits(opts PassphraseOptions) float64 {
	if opts.NumWords <= 0 {
		return 0
	}
	bits := float64(opts.NumWords) * math.Log2(float64(len(passphraseWords)))
	if opts.IncludeNum {
		bits += math.Log2(10) + math.Log2(float64(opts.NumWords))
	}
	return bits
}

func GeneratePassphrase(opts PassphraseOptions) (string, error) {
	if opts.NumWords <= 0 {
		return "", fmt.Errorf("%w: NumWords must be positive", ErrInvalidOptions)
	}

	words := make([]string, opts.NumWords)
	for i := range words {
		idx, err := randomInt(len(passphraseWords))
		if err != nil {
			return "", err
		}
		w := passphraseWords[idx]
		if opts.Capitalize {
			w = strings.ToUpper(w[:1]) + w[1:]
		}
		words[i] = w
	}

	if opts.IncludeNum {
		target, err := randomInt(opts.NumWords)
		if err != nil {
			return "", err
		}
		digit, err := randomInt(10)
		if err != nil {
			return "", err
		}
		words[target] += string(byte('0' + digit))
	}

	return strings.Join(words, opts.Separator), nil
}

func randomInt(max int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

func randomChar(charset string) (byte, error) {
	idx, err := randomInt(len(charset))
	if err != nil {
		return 0, err
	}
	return charset[idx], nil
}

func shuffleBytes(b []byte) error {
	for i := len(b) - 1; i > 0; i-- {
		j, err := randomInt(i + 1)
		if err != nil {
			return err
		}
		b[i], b[j] = b[j], b[i]
	}
	return nil
}
