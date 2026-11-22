package app

import (
	"hash/fnv"
	"strings"
	"unicode"

	"github.com/oneryx/myvault/internal/vaultcore/api"
)

type emblemPalette struct{ top, bottom uint32 }

var emblemPalettes = []emblemPalette{
	{0x4f8bff, 0x1f5fd6},
	{0x7a7cff, 0x4b44d6},
	{0xa77bff, 0x7440dd},
	{0xf26daa, 0xc93a7c},
	{0xff7a6b, 0xd9433a},
	{0xffa24d, 0xe0711b},
	{0x35c98a, 0x16955c},
	{0x2cc4c4, 0x128b9a},
	{0x6b8aa8, 0x3f5873},
}

var brandPalettes = map[string]emblemPalette{
	"github":     {0x3a4048, 0x171b21},
	"aws":        {0xffad33, 0xec7a00},
	"amazon":     {0xffad33, 0xec7a00},
	"cloudflare": {0xffa047, 0xf06d14},
	"stripe":     {0x8a82ff, 0x5a4fe8},
	"apple":      {0x7a7a80, 0x2c2c30},
	"google":     {0x5c9aff, 0x2a6ee8},
	"netflix":    {0xf2434d, 0xb8121d},
	"figma":      {0xb07cff, 0x7a3fe6},
	"linear":     {0x7b86f0, 0x4e59c9},
	"dropbox":    {0x4b8dff, 0x0b5be0},
	"visa":       {0x2f5fd0, 0x14307f},
	"amex":       {0x3aa6dd, 0x1771a8},
	"mastercard": {0xff8a3d, 0xe0471f},
}

func paletteFor(name string, t api.CipherType, brand string) emblemPalette {
	key := strings.ToLower(name + " " + brand)
	for b, p := range brandPalettes {
		if strings.Contains(key, b) {
			return p
		}
	}
	switch t {
	case api.CipherTypeCard:
		return emblemPalette{0x35c98a, 0x16955c}
	case api.CipherTypeIdentity:
		return emblemPalette{0xa77bff, 0x7440dd}
	case api.CipherTypeSecureNote:
		return emblemPalette{0xffc145, 0xe69400}
	case api.CipherTypeSSHKey:
		return emblemPalette{0x7d8a9c, 0x4a5568}
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.ToLower(name)))
	return emblemPalettes[h.Sum32()%uint32(len(emblemPalettes))]
}

func monogram(name string) string {
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return strings.ToUpper(string(r))
		}
	}
	return "•"
}

func maskedDots(n int) string {
	if n < 8 {
		n = 8
	}
	if n > 14 {
		n = 14
	}
	return strings.Repeat("•", n)
}

func initials(email string) string {
	local := strings.SplitN(email, "@", 2)[0]
	parts := strings.FieldsFunc(local, func(r rune) bool { return r == '.' || r == '_' || r == '-' || r == '+' })
	out := ""
	for _, p := range parts {
		if p != "" {
			out += strings.ToUpper(string([]rune(p)[0]))
		}
		if len(out) == 2 {
			break
		}
	}
	if out == "" {
		return "?"
	}
	return out
}
