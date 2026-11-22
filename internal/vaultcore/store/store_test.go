package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/crypto"
)

func TestFileStore_RoundTripPermissionsAndOverwrite(t *testing.T) {
	dir := t.TempDir()
	var s Store = NewFileStore(dir)

	rev := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	snap := &Snapshot{
		SchemaVersion: CurrentSchemaVersion,
		AccountID:     "acct-123",
		ServerURL:     "https://vault.example.com",
		Email:         "alice@example.com",
		KDF:           crypto.KDFConfig{Type: crypto.KDFArgon2id, Iterations: 3, MemoryMB: 64, Parallelism: 4},
		ProtectedKey:  "2.iv|ct|mac",
		RevisionDate:  rev,
		LastSyncAt:    rev.Add(time.Minute),
		RawSyncJSON:   json.RawMessage(`{"ciphers":[{"id":"c1","name":"2.a|b|c"}]}`),
	}

	if err := s.SaveSnapshot(snap); err != nil {
		t.Fatalf("SaveSnapshot failed: %v", err)
	}

	target := filepath.Join(dir, "vault_acct-123.enc.json")
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat snapshot failed: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("file perm = %04o, want 0600", perm)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 file in store dir (no leftover temp files), got %d", len(entries))
	}

	loaded, err := s.LoadSnapshot("acct-123")
	if err != nil {
		t.Fatalf("LoadSnapshot failed: %v", err)
	}
	if loaded.AccountID != snap.AccountID || loaded.Email != snap.Email || loaded.ProtectedKey != snap.ProtectedKey {
		t.Fatalf("loaded metadata mismatch: %+v", loaded)
	}
	if loaded.KDF != snap.KDF || !loaded.RevisionDate.Equal(snap.RevisionDate) {
		t.Fatalf("loaded KDF/revision mismatch: %+v", loaded)
	}
	if !bytes.Equal(loaded.RawSyncJSON, snap.RawSyncJSON) {
		t.Fatalf("RawSyncJSON = %s, want %s", loaded.RawSyncJSON, snap.RawSyncJSON)
	}

	snap.ProtectedKey = "2.iv2|ct2|mac2"
	if err := s.SaveSnapshot(snap); err != nil {
		t.Fatalf("overwrite SaveSnapshot failed: %v", err)
	}
	overwritten, err := s.LoadSnapshot("acct-123")
	if err != nil || overwritten.ProtectedKey != "2.iv2|ct2|mac2" {
		t.Fatalf("overwrite load = (%+v, %v)", overwritten, err)
	}
}

func TestFileStore_MissingDeleteAndInvalidAccountID(t *testing.T) {
	s := NewFileStore(t.TempDir())

	if _, err := s.LoadSnapshot("missing"); !errors.Is(err, ErrSnapshotNotFound) {
		t.Fatalf("LoadSnapshot(missing) = %v, want ErrSnapshotNotFound", err)
	}

	if err := s.DeleteSnapshot("missing"); err != nil {
		t.Fatalf("DeleteSnapshot(missing) should be idempotent, got %v", err)
	}

	snap := &Snapshot{AccountID: "acct-del", RawSyncJSON: json.RawMessage(`{}`)}
	if err := s.SaveSnapshot(snap); err != nil {
		t.Fatalf("SaveSnapshot failed: %v", err)
	}
	if err := s.DeleteSnapshot("acct-del"); err != nil {
		t.Fatalf("DeleteSnapshot failed: %v", err)
	}
	if _, err := s.LoadSnapshot("acct-del"); !errors.Is(err, ErrSnapshotNotFound) {
		t.Fatalf("after delete got %v, want ErrSnapshotNotFound", err)
	}

	for _, badID := range []string{"", "../escape", "a/b", `a\b`} {
		if _, err := s.LoadSnapshot(badID); !errors.Is(err, ErrInvalidAccountID) {
			t.Errorf("LoadSnapshot(%q) = %v, want ErrInvalidAccountID", badID, err)
		}
	}
}

func TestFileStore_ListAccounts(t *testing.T) {
	dir := t.TempDir()
	s := NewFileStore(dir)
	if ids, err := NewFileStore(filepath.Join(dir, "missing")).ListAccounts(); err != nil || len(ids) != 0 {
		t.Fatalf("ListAccounts of a missing dir = (%v, %v)", ids, err)
	}
	for _, id := range []string{"acct-a", "acct-b"} {
		if err := s.SaveSnapshot(&Snapshot{AccountID: id, RawSyncJSON: json.RawMessage(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "myvault.prefs.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	ids, err := s.ListAccounts()
	if err != nil || len(ids) != 2 || ids[0] != "acct-a" || ids[1] != "acct-b" {
		t.Fatalf("ListAccounts = (%v, %v)", ids, err)
	}
}
