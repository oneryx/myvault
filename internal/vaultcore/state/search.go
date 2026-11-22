package state

import (
	"slices"
	"strings"
)

type scoredSummary struct {
	summary CipherSummary
	score   int
}

// searchCiphers lists the ciphers filter selects that match query. hidden
// reports an item whose passwords the user may not see, which search treats
// as the detail view does: nothing it hides can be found.
func searchCiphers(ciphers map[string]*Cipher, query string, filter SearchFilter, hidden func(*Cipher) bool) []CipherSummary {
	q := strings.ToLower(strings.TrimSpace(query))
	var matches []scoredSummary

	for _, c := range ciphers {
		if !matchesFilter(c, filter) {
			continue
		}
		summary := summarizeCipher(c)
		if q == "" {
			matches = append(matches, scoredSummary{summary: summary, score: 0})
			continue
		}
		if score, ok := scoreCipher(c, summary, q, hidden(c)); ok {
			matches = append(matches, scoredSummary{summary: summary, score: score})
		}
	}

	slices.SortFunc(matches, func(a, b scoredSummary) int {
		if a.score != b.score {
			return b.score - a.score
		}
		return strings.Compare(strings.ToLower(a.summary.Name), strings.ToLower(b.summary.Name))
	})

	out := make([]CipherSummary, len(matches))
	for i, m := range matches {
		out[i] = m.summary
	}
	return out
}

func matchesFilter(c *Cipher, filter SearchFilter) bool {
	isDeleted := c.DeletedDate != nil
	if filter.Category == FilterTrash {
		return isDeleted
	}
	if isDeleted {
		return false
	}
	isArchived := c.ArchivedDate != nil
	if filter.Category == FilterArchive {
		return isArchived
	}
	if isArchived {
		return false
	}

	if filter.Type != nil && c.Type != *filter.Type {
		return false
	}
	if filter.OrganizationID != "" && (c.OrganizationID == nil || *c.OrganizationID != filter.OrganizationID) {
		return false
	}
	if filter.CollectionID != "" && !slices.Contains(c.CollectionIDs, filter.CollectionID) {
		return false
	}
	if filter.FolderID != "" {
		return c.FolderID != nil && *c.FolderID == filter.FolderID
	}

	switch filter.Category {
	case FilterFavorites:
		return c.Favorite
	case FilterNoFolder:
		return c.FolderID == nil || *c.FolderID == ""
	default:
		return true
	}
}

// fieldHidden is the custom field type whose value an item that hides
// passwords does not show.
const fieldHidden = 1

// scoreCipher matches q against an item's name, subtitle, websites, notes,
// custom fields, card, identity and SSH key fingerprint. An item whose
// passwords the user may not view does not match the values of its hidden
// fields. Passwords, TOTP secrets, SSH private keys and passkeys are never
// searched.
func scoreCipher(c *Cipher, summary CipherSummary, q string, hidesPasswords bool) (int, bool) {
	best := 0
	matched := false

	check := func(field string, weight int) {
		if field == "" {
			return
		}
		s := matchScore(strings.ToLower(field), q)
		if s > 0 {
			total := s * weight
			if !matched || total > best {
				best = total
				matched = true
			}
		}
	}

	check(summary.Name, 10)
	check(summary.Subtitle, 6)
	if c.Login != nil {
		for _, u := range c.Login.URIs {
			check(u.URI, 5)
		}
	}
	check(c.Notes, 2)
	for _, f := range c.Fields {
		check(f.Name, 3)
		if f.Type != fieldHidden || !hidesPasswords {
			check(f.Value, 3)
		}
	}
	if k := c.Card; k != nil {
		for _, v := range []string{k.Brand, k.CardholderName, k.Number, k.Code} {
			check(v, 4)
		}
	}
	if k := c.SSHKey; k != nil {
		check(k.KeyFingerprint, 4)
	}
	if i := c.Identity; i != nil {
		check(strings.Join(strings.Fields(i.FirstName+" "+i.MiddleName+" "+i.LastName), " "), 5)
		for _, v := range []string{i.Title, i.Address1, i.Address2, i.Address3, i.City, i.State, i.PostalCode, i.Country,
			i.Company, i.Email, i.Phone, i.SSN, i.Username, i.PassportNumber, i.LicenseNumber} {
			check(v, 4)
		}
	}

	return best, matched
}

func matchScore(haystack, needle string) int {
	if haystack == needle {
		return 100
	}
	if strings.HasPrefix(haystack, needle) {
		return 80
	}
	if strings.Contains(haystack, needle) {
		return 60
	}
	if isSubsequence(haystack, needle) {
		return 30
	}
	return 0
}

func isSubsequence(haystack, needle string) bool {
	hi := 0
	for ni := 0; ni < len(needle); ni++ {
		idx := strings.IndexByte(haystack[hi:], needle[ni])
		if idx < 0 {
			return false
		}
		hi += idx + 1
	}
	return true
}
