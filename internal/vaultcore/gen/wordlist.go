package gen

import (
	_ "embed"
	"strings"
)

// eff_large_wordlist.txt is the EFF large wordlist (https://www.eff.org/dice)
// by the Electronic Frontier Foundation, CC BY 3.0, with its dice numbers
// removed: 7,776 words, one per line.
//
//go:embed eff_large_wordlist.txt
var effLargeWordlist string

var passphraseWords = strings.Fields(effLargeWordlist)
