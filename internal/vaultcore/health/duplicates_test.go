package health

import (
	"slices"
	"testing"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

func userLogin(id, user string, uris ...string) *state.Cipher {
	c := login(id, "", uris...)
	c.Login.Username = user
	return c
}

// Logins group by registrable domain and username, compared without case;
// an empty username is a value too, and Trash is left out.
func TestDuplicateLogins(t *testing.T) {
	deleted := time.Now()
	archived := time.Now()
	trashed := userLogin("trashed", "alex", "https://github.com")
	trashed.DeletedDate = &deleted
	inArchive := userLogin("archived", "alex", "https://github.com/settings")
	inArchive.ArchivedDate = &archived
	r := Analyze([]*state.Cipher{
		userLogin("gh", "alex", "https://github.com/login"),
		userLogin("gist", "Alex", "https://gist.github.com"),
		inArchive,
		trashed,
		userLogin("gh-work", "alex-corp", "https://github.com"),
		userLogin("bbc1", "", "https://www.bbc.co.uk"),
		userLogin("bbc2", "", "bbc.co.uk/sounds"),
		userLogin("other-uk", "", "https://news.co.uk"),
		userLogin("no-site", "alex"),
		{ID: "note", Type: api.CipherTypeSecureNote, Name: "note"},
	}, time.Now())
	type group struct {
		site, user string
		ids        []string
	}
	var got []group
	for _, g := range r.Duplicates {
		got = append(got, group{g.Site, g.Username, ids(g.Items)})
	}
	want := []group{
		{"bbc.co.uk", "", []string{"bbc1", "bbc2"}},
		{"github.com", "alex", []string{"archived", "gh", "gist"}},
	}
	if !slices.EqualFunc(got, want, func(a, b group) bool {
		return a.site == b.site && a.user == b.user && slices.Equal(a.ids, b.ids)
	}) {
		t.Fatalf("duplicates = %+v, want %+v", got, want)
	}
	if r.TotalIssues() < len(want) {
		t.Fatalf("TotalIssues %d does not count the groups", r.TotalIssues())
	}
}
