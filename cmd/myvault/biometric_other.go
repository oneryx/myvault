//go:build !darwin

package main

import "github.com/oneryx/myvault/cmd/myvault/core"

func biometricAvailability() core.BiometricKind { return core.BiometricNone }

func authenticateBiometric(_ string, done func(core.BiometricResult)) {
	done(core.BiometricUnavailable)
}
