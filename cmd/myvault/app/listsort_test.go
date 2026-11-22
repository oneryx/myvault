package app

import (
	"slices"
	"testing"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/state"
)

func ids(items []state.CipherSummary) []string {
	var out []string
	for _, it := range items {
		out = append(out, it.ID)
	}
	return out
}

func TestSortItems(t *testing.T) {
	at := func(day int) *time.Time {
		d := time.Date(2026, 1, day, 0, 0, 0, 0, time.UTC)
		return &d
	}
	// The default order is what search returns, kept as is.
	items := func() []state.CipherSummary {
		return []state.CipherSummary{
			{ID: "a", Name: "alpha", RevisionDate: at(2)},
			{ID: "b", Name: "Bravo", RevisionDate: at(9)},
			{ID: "c", Name: "charlie", RevisionDate: at(2)},
			{ID: "d", Name: "Delta"},
		}
	}
	for s, want := range map[ListSort][]string{
		SortDefault:        {"a", "b", "c", "d"},
		SortNameDesc:       {"d", "c", "b", "a"},
		SortModifiedNewest: {"b", "a", "c", "d"},
		SortModifiedOldest: {"d", "a", "c", "b"},
	} {
		if got := ids(SortItems(items(), s)); !slices.Equal(got, want) {
			t.Errorf("%q: %v, want %v", s, got, want)
		}
	}
}

// The chosen order applies to the list at once and is remembered.
func TestListSortIsRememberedAndApplied(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	var before, after []string
	app.Post(func() {
		before = ids(m.FilteredItems.Items())
		m.SetListSort(SortNameDesc)
		after = ids(m.FilteredItems.Items())
	})
	app.Settle()
	if m.Prefs.Get().ListSort != SortNameDesc {
		t.Fatalf("pref = %q", m.Prefs.Get().ListSort)
	}
	if len(after) < 2 || slices.Equal(before, after) {
		t.Fatalf("list order %v did not change from %v", after, before)
	}
}
