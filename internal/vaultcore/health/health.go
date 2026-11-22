// Package health analyzes the decrypted vault locally for password and card
// hygiene issues. It performs no network calls.
package health

import (
	"cmp"
	"fmt"
	"math"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/state"
	"github.com/oneryx/myvault/internal/vaultcore/uri"
)

const (
	MinPasswordLength = 10
	ExpiringWindow    = 60 * 24 * time.Hour
)

// Issue points at one flagged item. It never carries secret values.
type Issue struct {
	CipherID string
	Type     api.CipherType
	Name     string
	Subtitle string
	Detail   string
}

type ReusedGroup struct {
	Count int
	Items []Issue
}

// DuplicateGroup is logins for the same site, by registrable domain, with
// the same username, compared without case; an empty username is one too.
type DuplicateGroup struct {
	Site     string
	Username string
	Items    []Issue
}

type CardIssue struct {
	Issue
	Expired bool
}

type Report struct {
	Reused    []ReusedGroup
	Weak      []Issue
	Cards     []CardIssue
	Unsecured []Issue
	// Duplicates counts in TotalIssues by group.
	Duplicates []DuplicateGroup
}

func (r Report) ReusedItems() int {
	n := 0
	for _, g := range r.Reused {
		n += len(g.Items)
	}
	return n
}

func (r Report) TotalIssues() int {
	return r.ReusedItems() + len(r.Weak) + len(r.Cards) + len(r.Unsecured) + len(r.Duplicates)
}

// Analyze inspects active items. Items in Trash are skipped, and logins whose
// password is hidden by an organization are left out of password checks.
func Analyze(ciphers []*state.Cipher, now time.Time) Report {
	var r Report
	byPassword := map[string][]*state.Cipher{}
	type siteUser struct{ site, user string }
	bySiteUser := map[siteUser][]*state.Cipher{}
	for _, c := range ciphers {
		if c == nil || c.DeletedDate != nil {
			continue
		}
		switch {
		case c.Login != nil && c.Type == api.CipherTypeLogin:
			user := strings.ToLower(strings.TrimSpace(c.Login.Username))
			seen := map[string]bool{}
			for _, u := range c.Login.URIs {
				if site := uri.Domain(u.URI); site != "" && !seen[site] {
					seen[site] = true
					k := siteUser{site, user}
					bySiteUser[k] = append(bySiteUser[k], c)
				}
			}
			if insecure, ok := insecureURI(c.Login.URIs); ok {
				r.Unsecured = append(r.Unsecured, issue(c, insecure))
			}
			if c.HidePassword || c.Login.Password == "" {
				continue
			}
			byPassword[c.Login.Password] = append(byPassword[c.Login.Password], c)
			if reason := WeakReason(c.Login.Password); reason != "" {
				r.Weak = append(r.Weak, issue(c, reason))
			}
		case c.Card != nil && c.Type == api.CipherTypeCard:
			if ci, ok := cardIssue(c, now); ok {
				r.Cards = append(r.Cards, ci)
			}
		}
	}
	for _, group := range byPassword {
		if len(group) < 2 {
			continue
		}
		g := ReusedGroup{Count: len(group)}
		for _, c := range group {
			g.Items = append(g.Items, issue(c, fmt.Sprintf("Used in %d items", len(group))))
		}
		sortIssues(g.Items)
		r.Reused = append(r.Reused, g)
	}
	for k, group := range bySiteUser {
		if len(group) < 2 {
			continue
		}
		g := DuplicateGroup{Site: k.site}
		for _, c := range group {
			g.Items = append(g.Items, issue(c, ""))
		}
		sortIssues(g.Items)
		// The username as the first item, in list order, spells it.
		g.Username = g.Items[0].Subtitle
		r.Duplicates = append(r.Duplicates, g)
	}
	slices.SortFunc(r.Duplicates, func(a, b DuplicateGroup) int {
		return cmp.Or(strings.Compare(a.Site, b.Site), strings.Compare(strings.ToLower(a.Username), strings.ToLower(b.Username)))
	})
	slices.SortFunc(r.Reused, func(a, b ReusedGroup) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		return compareIssue(a.Items[0], b.Items[0])
	})
	sortIssues(r.Weak)
	sortIssues(r.Unsecured)
	slices.SortFunc(r.Cards, func(a, b CardIssue) int {
		if a.Expired != b.Expired {
			if a.Expired {
				return -1
			}
			return 1
		}
		return compareIssue(a.Issue, b.Issue)
	})
	return r
}

func issue(c *state.Cipher, detail string) Issue {
	sub := ""
	switch {
	case c.Login != nil:
		sub = c.Login.Username
	case c.Card != nil:
		sub = c.Card.Brand
		if sub == "" {
			sub = c.Card.CardholderName
		}
	}
	return Issue{CipherID: c.ID, Type: c.Type, Name: c.Name, Subtitle: sub, Detail: detail}
}

func compareIssue(a, b Issue) int {
	return cmp.Or(strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)), strings.Compare(a.CipherID, b.CipherID))
}

func sortIssues(items []Issue) { slices.SortFunc(items, compareIssue) }

var commonPasswords = map[string]bool{
	"password": true, "passw0rd": true, "qwerty": true, "qwertyuiop": true, "asdfgh": true, "asdfghjkl": true,
	"zxcvbnm": true, "letmein": true, "welcome": true, "admin": true, "administrator": true, "login": true,
	"iloveyou": true, "monkey": true, "dragon": true, "football": true, "baseball": true, "master": true,
	"sunshine": true, "princess": true, "shadow": true, "superman": true, "trustno": true, "starwars": true,
	"secret": true, "changeme": true, "default": true, "abc": true, "test": true, "guest": true, "root": true,
	"summer": true, "winter": true, "spring": true, "autumn": true, "hello": true, "freedom": true,
}

// WeakReason returns why password is weak, or "" when it looks strong.
func WeakReason(password string) string {
	runes := []rune(password)
	if isCommon(password) {
		return "Common password"
	}
	if len(runes) < MinPasswordLength {
		return fmt.Sprintf("Shorter than %d characters", MinPasswordLength)
	}
	if patternRun(runes)*2 >= len(runes) {
		return "Mostly a sequence or repeated characters"
	}
	bits := entropyBits(runes)
	if classes(runes) == 1 && bits < 66 {
		return "Uses only one type of character"
	}
	if bits < 50 {
		return "Easy to guess"
	}
	return ""
}

var leet = strings.NewReplacer("@", "a", "4", "a", "0", "o", "1", "i", "3", "e", "$", "s", "5", "s", "7", "t")

func isCommon(password string) bool {
	p := strings.ToLower(password)
	for _, candidate := range []string{p, leet.Replace(p)} {
		if commonPasswords[candidate] {
			return true
		}
		base := strings.TrimFunc(candidate, func(r rune) bool { return !unicode.IsLetter(r) })
		if base != "" && commonPasswords[base] {
			return true
		}
	}
	return false
}

func patternRun(runes []rune) int {
	best, run, dir := 1, 1, 0
	if len(runes) == 0 {
		return 0
	}
	for i := 1; i < len(runes); i++ {
		d := int(runes[i]) - int(runes[i-1])
		if d >= -1 && d <= 1 && (run == 1 || d == dir) {
			dir = d
			run++
		} else if d >= -1 && d <= 1 {
			dir, run = d, 2
		} else {
			run = 1
		}
		best = max(best, run)
	}
	return best
}

func classes(runes []rune) int {
	var lower, upper, digit, other bool
	for _, r := range runes {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	n := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			n++
		}
	}
	return n
}

func entropyBits(runes []rune) float64 {
	var lower, upper, digit, other bool
	distinct := map[rune]bool{}
	for _, r := range runes {
		distinct[r] = true
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	pool := 0
	if lower {
		pool += 26
	}
	if upper {
		pool += 26
	}
	if digit {
		pool += 10
	}
	if other {
		pool += 33
	}
	effective := min(float64(len(runes)), float64(len(distinct))*1.5)
	return effective * math.Log2(float64(max(pool, 1)))
}

func cardIssue(c *state.Cipher, now time.Time) (CardIssue, bool) {
	year, err := strconv.Atoi(strings.TrimSpace(c.Card.ExpYear))
	if err != nil || year <= 0 {
		return CardIssue{}, false
	}
	if year < 100 {
		year += 2000
	}
	month := 12
	if m := strings.TrimSpace(c.Card.ExpMonth); m != "" {
		if month, err = strconv.Atoi(m); err != nil || month < 1 || month > 12 {
			return CardIssue{}, false
		}
	}
	end := time.Date(year, time.Month(month)+1, 1, 0, 0, 0, 0, now.Location())
	label := fmt.Sprintf("%02d/%d", month, year)
	switch {
	case !now.Before(end):
		return CardIssue{Issue: issue(c, "Expired "+label), Expired: true}, true
	case end.Sub(now) <= ExpiringWindow:
		return CardIssue{Issue: issue(c, "Expires "+label)}, true
	}
	return CardIssue{}, false
}

func insecureURI(uris []state.LoginURI) (string, bool) {
	for _, u := range uris {
		raw := strings.TrimSpace(u.URI)
		if !strings.HasPrefix(strings.ToLower(raw), "http://") {
			continue
		}
		parsed, err := url.Parse(raw)
		if err != nil || isLocalHost(parsed.Hostname()) {
			continue
		}
		return raw, true
	}
	return "", false
}

func isLocalHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
