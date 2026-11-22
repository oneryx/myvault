//go:build darwin && !ios

package main

import (
	"sync"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
	"github.com/oneryx/myvault/cmd/myvault/core"
)

// LocalAuthentication's LAPolicyDeviceOwnerAuthenticationWithBiometrics.
const laPolicyBiometrics = 1

var loadLocalAuthentication = sync.OnceValue(func() bool {
	for _, fw := range []string{
		"/System/Library/Frameworks/Foundation.framework/Foundation",
		"/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication",
	} {
		if _, err := purego.Dlopen(fw, purego.RTLD_NOW|purego.RTLD_GLOBAL); err != nil {
			return false
		}
	}
	return objc.GetClass("LAContext") != 0
})

func newLAContext() objc.ID {
	if !loadLocalAuthentication() {
		return 0
	}
	return objc.ID(objc.GetClass("LAContext")).Send(objc.RegisterName("new"))
}

func biometricAvailability() core.BiometricKind {
	ctx := newLAContext()
	if ctx == 0 {
		return core.BiometricNone
	}
	defer ctx.Send(objc.RegisterName("release"))
	if !objc.Send[bool](ctx, objc.RegisterName("canEvaluatePolicy:error:"), laPolicyBiometrics, objc.ID(0)) {
		return core.BiometricNone
	}
	switch objc.Send[int](ctx, objc.RegisterName("biometryType")) {
	case 1: // LABiometryTypeTouchID
		return core.BiometricFingerprint
	case 2: // LABiometryTypeFaceID
		return core.BiometricFace
	}
	return core.BiometricNone
}

func authenticateBiometric(reason string, done func(core.BiometricResult)) {
	ctx := newLAContext()
	if ctx == 0 {
		done(core.BiometricUnavailable)
		return
	}
	if !objc.Send[bool](ctx, objc.RegisterName("canEvaluatePolicy:error:"), laPolicyBiometrics, objc.ID(0)) {
		ctx.Send(objc.RegisterName("release"))
		done(core.BiometricUnavailable)
		return
	}
	str := objc.ID(objc.GetClass("NSString")).Send(objc.RegisterName("stringWithUTF8String:"), reason+"\x00")
	block := objc.NewBlock(func(_ objc.Block, success bool, err objc.ID) {
		res := core.BiometricFailed
		if success {
			res = core.BiometricSuccess
		} else if err != 0 {
			res = biometricResult(objc.Send[int](err, objc.RegisterName("code")))
		}
		ctx.Send(objc.RegisterName("release"))
		done(res)
	})
	ctx.Send(objc.RegisterName("evaluatePolicy:localizedReason:reply:"), laPolicyBiometrics, str, block)
	block.Release()
}

// biometricResult answers a failed evaluation by its LAError code: a cancel
// by the user, the system or the app, or the fallback button, is a cancel;
// missing hardware, enrolment or passcode and a lockout are unavailable.
func biometricResult(code int) core.BiometricResult {
	switch code {
	case -2, -3, -4, -9: // user cancel, fallback, system cancel, app cancel
		return core.BiometricCancelled
	case -5, -6, -7, -8, -1004: // no passcode, not available, not enrolled, lockout, not interactive
		return core.BiometricUnavailable
	}
	return core.BiometricFailed
}
