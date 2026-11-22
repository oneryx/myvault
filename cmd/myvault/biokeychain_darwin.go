//go:build darwin && !ios

package main

import (
	"errors"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

const (
	kCFStringEncodingUTF8                = 0x08000100
	kSecAccessControlBiometryCurrentSet  = 1 << 3
	biometricKeychainService             = "MyVault Biometric Unlock"
	biometricKeychainDefaultPromptReason = "unlock MyVault"
)

type cfFuncs struct {
	CFRelease                  func(uintptr)
	CFDictionaryCreateMutable  func(alloc uintptr, capacity int, keyCB, valueCB uintptr) uintptr
	CFDictionarySetValue       func(dict, key, value uintptr)
	CFDataCreate               func(alloc uintptr, bytes *byte, length int) uintptr
	CFDataGetBytePtr           func(data uintptr) *byte
	CFDataGetLength            func(data uintptr) int
	CFStringCreateWithCString  func(alloc uintptr, s *byte, encoding uint32) uintptr
	CFErrorGetCode             func(err uintptr) int
	SecItemAdd                 func(attrs uintptr, result *uintptr) int32
	SecItemCopyMatching        func(query uintptr, result *uintptr) int32
	SecItemDelete              func(query uintptr) int32
	SecAccessControlCreateWith func(alloc, protection uintptr, flags uint64, err *uintptr) uintptr
}

type secConsts struct {
	keyCallbacks, valueCallbacks uintptr
	booleanTrue, booleanFalse    uintptr

	class, classGenericPassword, attrService, attrAccount, valueData                   uintptr
	returnData, returnAttributes, matchLimit, matchLimitOne                            uintptr
	useDataProtectionKeychain, attrAccessControl, accessibleWhenUnlockedThisDeviceOnly uintptr
	useOperationPrompt, useAuthenticationUI, useAuthenticationUIFail                   uintptr
}

var (
	secOnce sync.Once
	secErr  error
	cf      cfFuncs
	sc      secConsts
)

func loadSecurity() error {
	secOnce.Do(func() {
		cfLib, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			secErr = err
			return
		}
		secLib, err := purego.Dlopen("/System/Library/Frameworks/Security.framework/Security", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			secErr = err
			return
		}
		purego.RegisterLibFunc(&cf.CFRelease, cfLib, "CFRelease")
		purego.RegisterLibFunc(&cf.CFDictionaryCreateMutable, cfLib, "CFDictionaryCreateMutable")
		purego.RegisterLibFunc(&cf.CFDictionarySetValue, cfLib, "CFDictionarySetValue")
		purego.RegisterLibFunc(&cf.CFDataCreate, cfLib, "CFDataCreate")
		purego.RegisterLibFunc(&cf.CFDataGetBytePtr, cfLib, "CFDataGetBytePtr")
		purego.RegisterLibFunc(&cf.CFDataGetLength, cfLib, "CFDataGetLength")
		purego.RegisterLibFunc(&cf.CFStringCreateWithCString, cfLib, "CFStringCreateWithCString")
		purego.RegisterLibFunc(&cf.CFErrorGetCode, cfLib, "CFErrorGetCode")
		purego.RegisterLibFunc(&cf.SecItemAdd, secLib, "SecItemAdd")
		purego.RegisterLibFunc(&cf.SecItemCopyMatching, secLib, "SecItemCopyMatching")
		purego.RegisterLibFunc(&cf.SecItemDelete, secLib, "SecItemDelete")
		purego.RegisterLibFunc(&cf.SecAccessControlCreateWith, secLib, "SecAccessControlCreateWithFlags")

		sym := func(lib uintptr, name string, deref bool) uintptr {
			addr, err := purego.Dlsym(lib, name)
			if err != nil {
				secErr = err
				return 0
			}
			if !deref {
				return addr
			}
			return **(**uintptr)(unsafe.Pointer(&addr))
		}
		sc.keyCallbacks = sym(cfLib, "kCFTypeDictionaryKeyCallBacks", false)
		sc.valueCallbacks = sym(cfLib, "kCFTypeDictionaryValueCallBacks", false)
		sc.booleanTrue = sym(cfLib, "kCFBooleanTrue", true)
		sc.booleanFalse = sym(cfLib, "kCFBooleanFalse", true)
		for name, dst := range map[string]*uintptr{
			"kSecClass":                                    &sc.class,
			"kSecClassGenericPassword":                     &sc.classGenericPassword,
			"kSecAttrService":                              &sc.attrService,
			"kSecAttrAccount":                              &sc.attrAccount,
			"kSecValueData":                                &sc.valueData,
			"kSecReturnData":                               &sc.returnData,
			"kSecReturnAttributes":                         &sc.returnAttributes,
			"kSecMatchLimit":                               &sc.matchLimit,
			"kSecMatchLimitOne":                            &sc.matchLimitOne,
			"kSecUseDataProtectionKeychain":                &sc.useDataProtectionKeychain,
			"kSecAttrAccessControl":                        &sc.attrAccessControl,
			"kSecAttrAccessibleWhenUnlockedThisDeviceOnly": &sc.accessibleWhenUnlockedThisDeviceOnly,
			"kSecUseOperationPrompt":                       &sc.useOperationPrompt,
			"kSecUseAuthenticationUI":                      &sc.useAuthenticationUI,
			"kSecUseAuthenticationUIFail":                  &sc.useAuthenticationUIFail,
		} {
			*dst = sym(secLib, name, true)
		}
	})
	return secErr
}

// cfScope tracks Core Foundation objects created for one keychain call.
type cfScope struct{ owned []uintptr }

func (s *cfScope) keep(ref uintptr) uintptr {
	if ref != 0 {
		s.owned = append(s.owned, ref)
	}
	return ref
}

func (s *cfScope) release() {
	for _, r := range s.owned {
		cf.CFRelease(r)
	}
}

func (s *cfScope) str(v string) uintptr {
	b := append([]byte(v), 0)
	ref := cf.CFStringCreateWithCString(0, &b[0], kCFStringEncodingUTF8)
	runtime.KeepAlive(b)
	return s.keep(ref)
}

func (s *cfScope) data(v []byte) uintptr {
	var p *byte
	if len(v) > 0 {
		p = &v[0]
	}
	ref := cf.CFDataCreate(0, p, len(v))
	runtime.KeepAlive(v)
	return s.keep(ref)
}

func (s *cfScope) dict(pairs ...uintptr) uintptr {
	d := s.keep(cf.CFDictionaryCreateMutable(0, len(pairs)/2, sc.keyCallbacks, sc.valueCallbacks))
	for i := 0; i+1 < len(pairs); i += 2 {
		cf.CFDictionarySetValue(d, pairs[i], pairs[i+1])
	}
	return d
}

func (s *cfScope) baseQuery(account string, extra ...uintptr) uintptr {
	pairs := []uintptr{
		sc.class, sc.classGenericPassword,
		sc.attrService, s.str(biometricKeychainService),
		sc.attrAccount, s.str(account),
		sc.useDataProtectionKeychain, sc.booleanTrue,
	}
	return s.dict(append(pairs, extra...)...)
}

// dataProtectionKeychain stores items in the Data Protection keychain,
// readable only after macOS verifies the current Touch ID enrollment.
type dataProtectionKeychain struct{}

func (dataProtectionKeychain) Add(account string, secret []byte) error {
	if err := loadSecurity(); err != nil {
		return err
	}
	var s cfScope
	defer s.release()
	var cfErr uintptr
	access := s.keep(cf.SecAccessControlCreateWith(0, sc.accessibleWhenUnlockedThisDeviceOnly, kSecAccessControlBiometryCurrentSet, &cfErr))
	if access == 0 {
		code := 0
		if cfErr != 0 {
			code = cf.CFErrorGetCode(cfErr)
			cf.CFRelease(cfErr)
		}
		return &accessControlError{code: code}
	}
	attrs := s.baseQuery(account, sc.attrAccessControl, access, sc.valueData, s.data(secret))
	return statusError(cf.SecItemAdd(attrs, nil))
}

func (dataProtectionKeychain) Copy(account, prompt string) ([]byte, error) {
	if err := loadSecurity(); err != nil {
		return nil, err
	}
	var s cfScope
	defer s.release()
	if prompt == "" {
		prompt = biometricKeychainDefaultPromptReason
	}
	query := s.baseQuery(account,
		sc.returnData, sc.booleanTrue,
		sc.matchLimit, sc.matchLimitOne,
		sc.useOperationPrompt, s.str(prompt),
	)
	var result uintptr
	if err := statusError(cf.SecItemCopyMatching(query, &result)); err != nil {
		return nil, err
	}
	s.keep(result)
	n := cf.CFDataGetLength(result)
	out := make([]byte, n)
	if n > 0 {
		copy(out, unsafe.Slice(cf.CFDataGetBytePtr(result), n))
	}
	return out, nil
}

func (dataProtectionKeychain) Exists(account string) (bool, error) {
	if err := loadSecurity(); err != nil {
		return false, err
	}
	var s cfScope
	defer s.release()
	query := s.baseQuery(account,
		sc.returnAttributes, sc.booleanTrue,
		sc.matchLimit, sc.matchLimitOne,
		sc.useAuthenticationUI, sc.useAuthenticationUIFail,
	)
	var result uintptr
	err := statusError(cf.SecItemCopyMatching(query, &result))
	s.keep(result)
	switch {
	case err == nil, errors.Is(err, errInteractionNotAllowed):
		return true, nil
	case errors.Is(err, errItemNotFound):
		return false, nil
	}
	return false, err
}

func (dataProtectionKeychain) Delete(account string) error {
	if err := loadSecurity(); err != nil {
		return err
	}
	var s cfScope
	defer s.release()
	return statusError(cf.SecItemDelete(s.baseQuery(account)))
}

func newHardwareKeychain() hardwareKeychain { return dataProtectionKeychain{} }
