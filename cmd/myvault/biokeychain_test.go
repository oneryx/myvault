package main

import (
	"errors"
	"sync"
	"testing"

	vaultapp "github.com/oneryx/myvault/cmd/myvault/app"
)

type memSecrets struct {
	mu        sync.Mutex
	m         map[string]string
	deleteErr error
}

func (s *memSecrets) Get(k string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	return v, ok, nil
}

func (s *memSecrets) Set(k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = v
	return nil
}

func (s *memSecrets) Delete(k string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleteErr != nil {
		return s.deleteErr
	}
	delete(s.m, k)
	return nil
}

type fakeHardware struct {
	items     map[string][]byte
	addErr    error
	copyErr   error
	deleteErr error
	prompts   int
}

func (f *fakeHardware) Add(account string, secret []byte) error {
	if f.addErr != nil {
		return f.addErr
	}
	f.items[account] = append([]byte(nil), secret...)
	return nil
}

func (f *fakeHardware) Copy(account, _ string) ([]byte, error) {
	if f.addErr != nil {
		return nil, f.addErr
	}
	if f.copyErr != nil {
		return nil, f.copyErr
	}
	v, ok := f.items[account]
	if !ok {
		return nil, errItemNotFound
	}
	f.prompts++
	return v, nil
}

func (f *fakeHardware) Exists(account string) (bool, error) {
	if f.addErr != nil {
		return false, nil
	}
	_, ok := f.items[account]
	return ok, nil
}

func (f *fakeHardware) Delete(account string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	if f.addErr != nil {
		return f.addErr
	}
	if _, ok := f.items[account]; !ok {
		return errItemNotFound
	}
	delete(f.items, account)
	return nil
}

func TestBiometricSecretStoreFallsBackWithoutEntitlement(t *testing.T) {
	fallback := &memSecrets{m: map[string]string{}}
	hw := &fakeHardware{items: map[string][]byte{}, addErr: errMissingEntitlement}
	s := NewBiometricSecretStore(fallback, hw)

	if err := s.Set("userkey:acct", "wrapped"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if v, ok, _ := fallback.Get("userkey:acct"); !ok || v != "wrapped" {
		t.Fatal("key not stored in the fallback keychain")
	}
	if s.HardwareBound("acct") {
		t.Fatal("HardwareBound with a missing entitlement")
	}
	if v, ok, err := s.Get("userkey:acct"); err != nil || !ok || v != "wrapped" {
		t.Fatalf("Get = (%q, %v, %v)", v, ok, err)
	}
	if err := s.Delete("userkey:acct"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok, _ := s.Get("userkey:acct"); ok {
		t.Fatal("key survived Delete")
	}
}

func TestBiometricSecretStoreUsesHardwareKeychain(t *testing.T) {
	fallback := &memSecrets{m: map[string]string{"userkey:acct": "legacy", "refresh_token:acct": "rt"}}
	hw := &fakeHardware{items: map[string][]byte{}}
	s := NewBiometricSecretStore(fallback, hw)

	if v, ok, _ := s.Get("userkey:acct"); !ok || v != "legacy" {
		t.Fatal("existing login keychain key not readable before migration")
	}
	if err := s.Set("userkey:acct", "wrapped"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, ok, _ := fallback.Get("userkey:acct"); ok {
		t.Fatal("weaker login keychain copy kept after hardware save")
	}
	if !s.HardwareBound("acct") {
		t.Fatal("HardwareBound = false after hardware save")
	}
	if v, ok, err := s.Get("userkey:acct"); err != nil || !ok || v != "wrapped" || hw.prompts != 1 {
		t.Fatalf("Get = (%q, %v, %v), prompts=%d", v, ok, err, hw.prompts)
	}
	if err := s.Set("refresh_token:acct", "rt2"); err != nil || len(hw.items) != 1 {
		t.Fatal("non-biometric secret routed to the hardware keychain")
	}

	hw.copyErr = errUserCanceled
	if _, _, err := s.Get("userkey:acct"); !errors.Is(err, vaultapp.ErrBiometricCancelled) {
		t.Fatalf("cancelled Get = %v", err)
	}
	hw.copyErr = nil

	if err := s.Delete("userkey:acct"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(hw.items) != 0 || s.HardwareBound("acct") {
		t.Fatal("hardware item survived Delete")
	}
	if err := s.Delete("userkey:acct"); err != nil {
		t.Fatalf("Delete of a missing item: %v", err)
	}

	hw.items["userkey:acct"] = []byte("wrapped")
	hw.deleteErr = errInteractionNotAllowed
	if err := s.Delete("userkey:acct"); !errors.Is(err, errInteractionNotAllowed) {
		t.Fatalf("transient hardware delete error = %v, want it surfaced", err)
	}
	hw.deleteErr = nil

	fallback.m["userkey:acct"] = "legacy"
	fallback.deleteErr = errors.New("keychain locked")
	if err := s.Set("userkey:acct", "wrapped"); err == nil {
		t.Fatal("Set reported success while the login keychain copy remains")
	}
}
