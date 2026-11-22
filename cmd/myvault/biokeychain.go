package main

import (
	"errors"
	"fmt"
	"strings"

	vaultapp "github.com/oneryx/myvault/cmd/myvault/app"
	"github.com/oneryx/myvault/internal/vaultcore/store"
)

const biometricKeyPrefix = "userkey:"

type OSStatusError int32

func (e OSStatusError) Error() string { return fmt.Sprintf("keychain: OSStatus %d", int32(e)) }

const (
	errUserCanceled          OSStatusError = -128
	errUnimplemented         OSStatusError = -4
	errParam                 OSStatusError = -50
	errNotAvailable          OSStatusError = -25291
	errAuthFailed            OSStatusError = -25293
	errItemNotFound          OSStatusError = -25300
	errInteractionNotAllowed OSStatusError = -25308
	errMissingEntitlement    OSStatusError = -34018
)

func statusError(status int32) error {
	if status == 0 {
		return nil
	}
	return OSStatusError(status)
}

type accessControlError struct{ code int }

func (e *accessControlError) Error() string {
	return fmt.Sprintf("keychain: biometric access control unavailable (CFError %d)", e.code)
}

// hardwareKeychain stores secrets that macOS releases only after Touch ID.
type hardwareKeychain interface {
	Add(account string, secret []byte) error
	Copy(account, prompt string) ([]byte, error)
	Exists(account string) (bool, error)
	Delete(account string) error
}

// BiometricSecretStore keeps the biometric unlock key in the hardware-gated
// keychain when the build is entitled to it and in the fallback store
// otherwise. Every other secret goes to the fallback store.
type BiometricSecretStore struct {
	fallback store.SecretStore
	hw       hardwareKeychain
	prompt   string
}

func NewBiometricSecretStore(fallback store.SecretStore, hw hardwareKeychain) *BiometricSecretStore {
	return &BiometricSecretStore{fallback: fallback, hw: hw, prompt: "unlock MyVault"}
}

func isBiometricKey(account string) bool { return strings.HasPrefix(account, biometricKeyPrefix) }

func hardwareUnavailable(err error) bool {
	var acErr *accessControlError
	return errors.As(err, &acErr) || errors.Is(err, errMissingEntitlement) || errors.Is(err, errNotAvailable) ||
		errors.Is(err, errParam) || errors.Is(err, errUnimplemented)
}

func (s *BiometricSecretStore) Get(account string) (string, bool, error) {
	if s.hw != nil && isBiometricKey(account) {
		data, err := s.hw.Copy(account, s.prompt)
		switch {
		case err == nil:
			return string(data), true, nil
		case errors.Is(err, errUserCanceled), errors.Is(err, errAuthFailed):
			return "", false, fmt.Errorf("%w: %v", vaultapp.ErrBiometricCancelled, err)
		case !errors.Is(err, errItemNotFound) && !hardwareUnavailable(err):
			return "", false, err
		}
	}
	return s.fallback.Get(account)
}

func (s *BiometricSecretStore) Set(account, value string) error {
	if s.hw != nil && isBiometricKey(account) {
		_ = s.hw.Delete(account)
		err := s.hw.Add(account, []byte(value))
		if err == nil {
			if err := s.fallback.Delete(account); err != nil {
				return fmt.Errorf("keychain: saved with Touch ID protection, but could not remove the login keychain copy: %w", err)
			}
			return nil
		}
		if !hardwareUnavailable(err) {
			return err
		}
	}
	return s.fallback.Set(account, value)
}

func (s *BiometricSecretStore) Delete(account string) error {
	var firstErr error
	if s.hw != nil && isBiometricKey(account) {
		if err := s.hw.Delete(account); err != nil && !errors.Is(err, errItemNotFound) && !errors.Is(err, errMissingEntitlement) {
			firstErr = err
		}
	}
	if err := s.fallback.Delete(account); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// HardwareBound reports whether the biometric key of accountID is held by
// the hardware-gated keychain, which prompts for Touch ID by itself.
func (s *BiometricSecretStore) HardwareBound(accountID string) bool {
	if s.hw == nil || accountID == "" {
		return false
	}
	ok, err := s.hw.Exists(biometricKeyPrefix + accountID)
	return err == nil && ok
}
