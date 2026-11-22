package state

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/crypto"
)

func ids(s []CipherSummary) []string {
	var out []string
	for _, c := range s {
		out = append(out, c.ID)
	}
	return out
}

func TestService_ArchiveHidesItemsEverywhereButArchive(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	ctx := context.Background()
	if !svc.CanArchive() {
		t.Fatal("a premium account cannot archive")
	}
	c, _ := svc.GetCipher("c-1")
	if !c.Favorite {
		c.Favorite = true
		if _, err := svc.SaveCipher(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.ArchiveCipher(ctx, "c-1"); err != nil {
		t.Fatal(err)
	}
	env.mu.Lock()
	calls := slices.Clone(env.archiveCalls)
	env.mu.Unlock()
	if len(calls) != 1 || calls[0] != "PUT /api/ciphers/c-1/archive body=" {
		t.Fatalf("archive requests = %q", calls)
	}

	for name, f := range map[string]SearchFilter{
		"all items": {Category: FilterAll},
		"favorites": {Category: FilterFavorites},
		"folder":    {FolderID: "f-work"},
		"logins":    {Type: ptrType(api.CipherTypeLogin)},
	} {
		if slices.Contains(ids(svc.Search("", f)), "c-1") || slices.Contains(ids(svc.Search("GitHub", f)), "c-1") {
			t.Fatalf("an archived item shows in %s", name)
		}
	}
	got := svc.Search("", SearchFilter{Category: FilterArchive})
	if len(got) != 1 || got[0].ID != "c-1" || !got[0].Archived {
		t.Fatalf("Archive = %+v", got)
	}
	if found := ids(svc.Search("GitHub", SearchFilter{Category: FilterArchive})); !slices.Contains(found, "c-1") {
		t.Fatal("search in Archive misses the archived item")
	}

	// Editing an archived item keeps it archived: the update carries its
	// archive date, which the server would otherwise clear.
	c, _ = svc.GetCipher("c-1")
	c.Name = "GitHub (archived, renamed)"
	if _, err := svc.SaveCipher(ctx, c); err != nil {
		t.Fatal(err)
	}
	var sent map[string]json.RawMessage
	env.mu.Lock()
	_ = json.Unmarshal(env.lastBody, &sent)
	env.mu.Unlock()
	if string(sent["archivedDate"]) == "null" || len(sent["archivedDate"]) == 0 {
		t.Fatalf("an edit of an archived item sent archivedDate %s", sent["archivedDate"])
	}
	if c, _ := svc.GetCipher("c-1"); c.ArchivedDate == nil {
		t.Fatal("editing unarchived the item")
	}

	if err := svc.UnarchiveCipher(ctx, "c-1"); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(ids(svc.Search("", SearchFilter{Category: FilterAll})), "c-1") || len(svc.Search("", SearchFilter{Category: FilterArchive})) != 0 {
		t.Fatal("unarchive did not bring the item back")
	}
}

func ptrType(t api.CipherType) *api.CipherType { return &t }

func TestService_ArchiveSurvivesLockAndUnlockOffline(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	if err := svc.ArchiveCipher(context.Background(), "c-1"); err != nil {
		t.Fatal(err)
	}
	relockOffline(t, svc, env)
	if got := ids(svc.Search("", SearchFilter{Category: FilterArchive})); !slices.Equal(got, []string{"c-1"}) {
		t.Fatalf("Archive after unlock = %v", got)
	}
}

func TestService_ArchiveRules(t *testing.T) {
	env := newVaultTestEnv(t)
	no := false
	rev := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	name, _ := crypto.EncryptString("Shared read-only", env.userKey)
	env.ciphers["c-ro"] = api.EncryptedCipher{ID: "c-ro", Type: api.CipherTypeSecureNote, Name: name, Edit: &no, RevisionDate: &rev, SecureNote: &api.EncryptedSecureNote{}}
	svc := loggedInTestService(t, env)
	ctx := context.Background()

	// Like a favorite, the archive is per user: read-only items qualify.
	if err := svc.ArchiveCipher(ctx, "c-ro"); err != nil {
		t.Fatalf("archiving a read-only item = %v", err)
	}
	if err := svc.ArchiveCipher(ctx, "c-trash"); !errors.Is(err, ErrCipherInTrash) {
		t.Fatalf("archiving an item in Trash = %v", err)
	}
	if err := svc.ArchiveCipher(ctx, "missing"); !errors.Is(err, ErrCipherNotFound) {
		t.Fatalf("archiving a missing item = %v", err)
	}
}

func TestService_ArchiveNeedsPremiumButUnarchiveDoesNot(t *testing.T) {
	env := newVaultTestEnv(t)
	env.noPremium = true
	archived := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	c := env.ciphers["c-1"]
	c.ArchivedDate = &archived
	env.ciphers["c-1"] = c
	svc := loggedInTestService(t, env)
	if svc.CanArchive() {
		t.Fatal("an account without premium can archive")
	}
	if err := svc.ArchiveCipher(context.Background(), "c-trash-x"); !errors.Is(err, ErrCipherNotFound) {
		t.Fatalf("archive of a missing item = %v", err)
	}
	if err := svc.UnarchiveCipher(context.Background(), "c-1"); err != nil {
		t.Fatalf("unarchive without premium = %v, want allowed", err)
	}
	if err := svc.ArchiveCipher(context.Background(), "c-1"); !errors.Is(err, ErrPremiumRequired) {
		t.Fatalf("archive without premium = %v, want ErrPremiumRequired", err)
	}
}

func TestService_ArchiveOnAnOlderServerIsReported(t *testing.T) {
	env := newVaultTestEnv(t)
	env.oldServer = true
	svc := loggedInTestService(t, env)
	if err := svc.ArchiveCipher(context.Background(), "c-1"); !errors.Is(err, ErrArchiveUnsupported) {
		t.Fatalf("archive on an older server = %v, want ErrArchiveUnsupported", err)
	}
	if c, _ := svc.GetCipher("c-1"); c.ArchivedDate != nil {
		t.Fatal("the item looks archived after the server refused")
	}
}

func TestService_ArchiveResponseNeverRestoresARemovedItem(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	env.mu.Lock()
	// While the archive request is in flight, access to the item is
	// revoked and a sync removes it.
	env.onArchive = func() {
		env.mu.Lock()
		env.onArchive = nil
		delete(env.ciphers, "c-1")
		env.mu.Unlock()
		if err := svc.forceSync(context.Background()); err != nil {
			t.Errorf("sync: %v", err)
		}
	}
	env.mu.Unlock()

	// The server still answers with the item, which the user can no
	// longer see.
	if err := svc.ArchiveCipher(context.Background(), "c-1"); err != nil {
		t.Fatalf("archive = %v", err)
	}
	if _, err := svc.GetCipher("c-1"); err == nil {
		t.Fatal("a late archive response put back an item the sync removed")
	}
	relockOffline(t, svc, env)
	if _, err := svc.GetCipher("c-1"); err == nil {
		t.Fatal("the removed item is back in the snapshot")
	}
}

func TestService_SavingAStaleDraftKeepsTheServersArchiveState(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	draft, _ := svc.GetCipher("c-1")

	// Another device archives the item; the open draft still says it is not.
	when := time.Date(2026, 11, 21, 8, 0, 0, 0, time.UTC)
	env.mu.Lock()
	c := env.ciphers["c-1"]
	c.ArchivedDate = &when
	env.ciphers["c-1"] = c
	env.mu.Unlock()

	draft.Name = "Renamed in an old draft"
	if _, err := svc.SaveCipher(context.Background(), draft); err != nil {
		t.Fatal(err)
	}
	var sent struct {
		ArchivedDate          *time.Time `json:"archivedDate"`
		LastKnownRevisionDate *time.Time `json:"lastKnownRevisionDate"`
	}
	env.mu.Lock()
	_ = json.Unmarshal(env.lastBody, &sent)
	env.mu.Unlock()
	if sent.ArchivedDate == nil || !sent.ArchivedDate.Equal(when) {
		t.Fatalf("the save sent archivedDate %v, want the server's %v", sent.ArchivedDate, when)
	}
	if sent.LastKnownRevisionDate == nil || draft.RevisionDate == nil || !sent.LastKnownRevisionDate.Equal(*draft.RevisionDate) {
		t.Fatal("the save did not keep the draft's revision for conflict detection")
	}
}

func TestService_PremiumRulesOnEveryWritePath(t *testing.T) {
	env := newVaultTestEnv(t)
	env.noPremium = true
	when := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	c := env.ciphers["c-1"]
	c.ArchivedDate = &when
	env.ciphers["c-1"] = c
	svc := loggedInTestService(t, env)
	ctx := context.Background()

	// An import cannot create an archived item without premium.
	if _, err := svc.SaveCipher(ctx, &Cipher{Type: api.CipherTypeSecureNote, Name: "From backup", ArchivedDate: &when, SecureNote: &SecureNote{}}); err != nil {
		t.Fatal(err)
	}
	if got, _ := svc.GetCipher("c-created"); got == nil || got.ArchivedDate != nil {
		t.Fatalf("created %+v, want it in the vault, not the Archive", got)
	}

	// An archived item can still be edited, but not have its favorite changed.
	cur, _ := svc.GetCipher("c-1")
	cur.Name = "Edited after premium ended"
	if _, err := svc.SaveCipher(ctx, cur); err != nil {
		t.Fatalf("an ordinary edit of an archived item = %v", err)
	}
	if got, _ := svc.GetCipher("c-1"); got.ArchivedDate == nil {
		t.Fatal("the edit unarchived the item")
	}
	cur, _ = svc.GetCipher("c-1")
	cur.Favorite = !cur.Favorite
	if _, err := svc.SaveCipher(ctx, cur); !errors.Is(err, ErrPremiumRequired) {
		t.Fatalf("changing the favorite of an archived item without premium = %v", err)
	}
}

func TestService_Ambiguous404IsResolvedBySync(t *testing.T) {
	env := newVaultTestEnv(t)
	env.archiveApplyThen404 = true
	svc := loggedInTestService(t, env)
	if err := svc.ArchiveCipher(context.Background(), "c-1"); err != nil {
		t.Fatalf("archive the server applied but answered 404 = %v", err)
	}
	if c, _ := svc.GetCipher("c-1"); c.ArchivedDate == nil {
		t.Fatal("the archive the server applied is not shown")
	}
}

func TestService_ArchiveCopiesItsFlagsUnderTheLock(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	ctx := context.Background()
	done := make(chan error, 2)
	go func() { done <- svc.SoftDeleteCipher(ctx, "c-1") }()
	go func() { done <- svc.ArchiveCipher(ctx, "c-1") }()
	for range 2 {
		if err := <-done; err != nil && !errors.Is(err, ErrCipherInTrash) {
			t.Fatalf("concurrent op: %v", err)
		}
	}
	if c, _ := svc.GetCipher("c-1"); c.DeletedDate == nil {
		t.Fatal("the item is not in Trash")
	}
}

func TestService_404FromAServerWithArchiveIsNotBlamedOnItsVersion(t *testing.T) {
	env := newVaultTestEnv(t)
	env.oldServer = true
	c := env.ciphers["c-1"]
	c.Extra = map[string]json.RawMessage{"archivedDate": json.RawMessage("null")}
	env.ciphers["c-1"] = c
	svc := loggedInTestService(t, env)
	if err := svc.ArchiveCipher(context.Background(), "c-1"); !errors.Is(err, ErrArchiveNotConfirmed) {
		t.Fatalf("a 404 from a server that reports archivedDate = %v, want ErrArchiveNotConfirmed", err)
	}
}

func TestService_SaveAlwaysTakesTheServersArchiveDate(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	draft, _ := svc.GetCipher("c-1")
	when := time.Date(2026, 11, 21, 8, 0, 0, 0, time.UTC)
	env.mu.Lock()
	c := env.ciphers["c-1"]
	c.ArchivedDate = &when
	env.ciphers["c-1"] = c
	env.mu.Unlock()

	// The item is gone from this device but still on the server.
	svc.mu.Lock()
	delete(svc.ciphers, "c-1")
	svc.mu.Unlock()
	if _, err := svc.SaveCipher(context.Background(), draft); err != nil {
		t.Fatal(err)
	}
	var sent struct {
		ArchivedDate *time.Time `json:"archivedDate"`
	}
	env.mu.Lock()
	_ = json.Unmarshal(env.lastBody, &sent)
	env.lastBody = nil
	// Now the server has lost it too.
	delete(env.ciphers, "c-1")
	env.mu.Unlock()
	if sent.ArchivedDate == nil || !sent.ArchivedDate.Equal(when) {
		t.Fatalf("a save of an item missing locally sent archivedDate %v, want the server's", sent.ArchivedDate)
	}
	if _, err := svc.SaveCipher(context.Background(), draft); !errors.Is(err, ErrCipherNotFound) {
		t.Fatalf("a save of an item the server no longer has = %v, want ErrCipherNotFound", err)
	}
	env.mu.Lock()
	defer env.mu.Unlock()
	if env.lastBody != nil {
		t.Fatal("a stale archive date was sent for an item the server no longer has")
	}
}

func TestService_FavoriteGuardUsesTheServersArchiveState(t *testing.T) {
	env := newVaultTestEnv(t)
	env.noPremium = true
	svc := loggedInTestService(t, env)
	draft, _ := svc.GetCipher("c-1")

	// Archived on another device; this device still shows it unarchived.
	when := time.Date(2026, 11, 21, 8, 0, 0, 0, time.UTC)
	env.mu.Lock()
	c := env.ciphers["c-1"]
	c.ArchivedDate = &when
	env.ciphers["c-1"] = c
	env.mu.Unlock()

	draft.Favorite = !draft.Favorite
	if _, err := svc.SaveCipher(context.Background(), draft); !errors.Is(err, ErrPremiumRequired) {
		t.Fatalf("changing the favorite of an item the server has archived = %v, want ErrPremiumRequired", err)
	}
}

func TestService_ArchiveEvidenceFromSingleResponsesAndNone(t *testing.T) {
	// Sync sends no archivedDate, so the server looks like it lacks
	// Archive, until an item response reports archivedDate.
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	svc.mu.RLock()
	absentAfterSync := svc.archiveAbsent
	svc.mu.RUnlock()
	if !absentAfterSync {
		t.Fatal("a sync without archivedDate should count as evidence of no Archive")
	}
	setReported := func(on bool) {
		env.mu.Lock()
		c := env.ciphers["c-1"]
		c.Extra = nil
		if on {
			c.Extra = map[string]json.RawMessage{"archivedDate": json.RawMessage("null")}
		}
		env.ciphers["c-1"] = c
		env.mu.Unlock()
	}
	setReported(true)
	cur, _ := svc.GetCipher("c-1")
	if _, err := svc.SaveCipher(context.Background(), cur); err != nil {
		t.Fatal(err)
	}
	setReported(false)
	env.mu.Lock()
	env.oldServer = true
	env.mu.Unlock()
	if err := svc.ArchiveCipher(context.Background(), "c-1"); !errors.Is(err, ErrArchiveNotConfirmed) {
		t.Fatalf("a 404 after an item response reported archivedDate = %v, want ErrArchiveNotConfirmed", err)
	}

	// No evidence either way: the vault the server sends is empty.
	env2 := newVaultTestEnv(t)
	env2.oldServer = true
	svc2 := loggedInTestService(t, env2)
	env2.mu.Lock()
	for id := range env2.ciphers {
		delete(env2.ciphers, id)
	}
	env2.mu.Unlock()
	if err := svc2.forceSync(context.Background()); err != nil {
		t.Fatal(err)
	}
	svc2.mu.Lock()
	svc2.ciphers["c-x"] = &Cipher{ID: "c-x", Type: api.CipherTypeSecureNote, Name: "x", SecureNote: &SecureNote{}}
	svc2.mu.Unlock()
	if err := svc2.ArchiveCipher(context.Background(), "c-x"); !errors.Is(err, ErrArchiveNotConfirmed) {
		t.Fatalf("a 404 with no evidence either way = %v, want ErrArchiveNotConfirmed", err)
	}
}
