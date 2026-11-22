package gen

import (
	"errors"
	"math"
	"strings"
	"testing"
	"unicode"
)

func TestGeneratePassword_Constraints(t *testing.T) {
	opts := PasswordOptions{
		Length:         24,
		Uppercase:      true,
		Lowercase:      true,
		Numbers:        true,
		Special:        true,
		MinNumbers:     4,
		MinSpecial:     3,
		AvoidAmbiguous: true,
	}

	const ambiguous = "IOlo01"
	for range 20 {
		pw, err := GeneratePassword(opts)
		if err != nil {
			t.Fatalf("GeneratePassword failed: %v", err)
		}
		if len(pw) != opts.Length {
			t.Fatalf("len = %d, want %d", len(pw), opts.Length)
		}

		var upper, lower, num, spec int
		for _, r := range pw {
			if strings.ContainsRune(ambiguous, r) {
				t.Fatalf("password %q contains ambiguous char %q", pw, r)
			}
			switch {
			case strings.ContainsRune(uppercaseClear, r):
				upper++
			case strings.ContainsRune(lowercaseClear, r):
				lower++
			case strings.ContainsRune(numbersClear, r):
				num++
			case strings.ContainsRune(specialChars, r):
				spec++
			default:
				t.Fatalf("unexpected char %q in %q", r, pw)
			}
		}
		if upper < 1 || lower < 1 || num < opts.MinNumbers || spec < opts.MinSpecial {
			t.Fatalf("password %q violated class counts (upper=%d lower=%d num=%d spec=%d)", pw, upper, lower, num, spec)
		}
	}
}

func TestGeneratePassword_RejectsInvalidOptions(t *testing.T) {
	cases := []PasswordOptions{
		{Length: 0, Lowercase: true},
		{Length: 12},
		{Length: 8, Lowercase: true, MinNumbers: 1},
		{Length: 5, Uppercase: true, Lowercase: true, Numbers: true, Special: true, MinNumbers: 3, MinSpecial: 2},
	}
	for _, opts := range cases {
		if _, err := GeneratePassword(opts); !errors.Is(err, ErrInvalidOptions) {
			t.Errorf("GeneratePassword(%+v) = %v, want ErrInvalidOptions", opts, err)
		}
	}
}

func TestGeneratePassphrase(t *testing.T) {
	phrase, err := GeneratePassphrase(PassphraseOptions{
		NumWords:   5,
		Separator:  "-",
		Capitalize: true,
		IncludeNum: true,
	})
	if err != nil {
		t.Fatalf("GeneratePassphrase failed: %v", err)
	}

	parts := strings.Split(phrase, "-")
	if len(parts) != 5 {
		t.Fatalf("got %d words (%q), want 5", len(parts), phrase)
	}

	digits := 0
	for _, w := range parts {
		if len(w) == 0 || !unicode.IsUpper(rune(w[0])) {
			t.Errorf("word %q is not capitalized", w)
		}
		if w[len(w)-1] >= '0' && w[len(w)-1] <= '9' {
			digits++
		}
	}
	if digits != 1 {
		t.Errorf("expected exactly 1 word with trailing digit in %q, got %d", phrase, digits)
	}

	if _, err := GeneratePassphrase(PassphraseOptions{NumWords: 0}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("NumWords=0 got %v, want ErrInvalidOptions", err)
	}
}

func TestGenerateEd25519SSHKey(t *testing.T) {
	k, err := GenerateEd25519SSHKey("me@host")
	if err != nil {
		t.Fatalf("GenerateEd25519SSHKey: %v", err)
	}
	if !strings.HasPrefix(k.PrivateKey, "-----BEGIN OPENSSH PRIVATE KEY-----") ||
		!strings.HasPrefix(k.PublicKey, "ssh-ed25519 ") || !strings.HasSuffix(k.PublicKey, " me@host") ||
		!strings.HasPrefix(k.KeyFingerprint, "SHA256:") {
		t.Fatalf("unexpected key: %+v", k)
	}
	got, err := InspectSSHPrivateKey(k.PrivateKey, "me@host")
	if err != nil || got != k {
		t.Fatalf("InspectSSHPrivateKey = (%+v, %v), want %+v", got, err, k)
	}
}

func TestPassphraseWordsAreTheEFFLargeList(t *testing.T) {
	if len(passphraseWords) != 7776 {
		t.Fatalf("word list has %d words, want 7776", len(passphraseWords))
	}
	seen := map[string]bool{}
	for _, w := range passphraseWords {
		if seen[w] {
			t.Fatalf("duplicate word %q", w)
		}
		seen[w] = true
	}
	if passphraseWords[0] != "abacus" || passphraseWords[7775] != "zoom" {
		t.Fatalf("list starts %q and ends %q", passphraseWords[0], passphraseWords[7775])
	}
}

func TestPassphraseBits(t *testing.T) {
	four := PassphraseBits(PassphraseOptions{NumWords: 4})
	if math.Abs(four-4*math.Log2(7776)) > 1e-9 {
		t.Fatalf("4 words = %.2f bits", four)
	}
	withNum := PassphraseBits(PassphraseOptions{NumWords: 4, IncludeNum: true, Capitalize: true})
	if math.Abs(withNum-(four+math.Log2(10)+2)) > 1e-9 {
		t.Fatalf("4 words with a digit = %.2f bits", withNum)
	}
}
