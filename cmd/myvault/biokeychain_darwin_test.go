//go:build darwin && !ios

package main

import (
	"os"
	"testing"
	"unsafe"
)

// TestDataProtectionKeychainProbe reports how this macOS host and the signing
// identity of the test binary respond to a Touch ID bound keychain item.
// It never prompts: it only adds, checks for and deletes a throwaway item.
func TestDataProtectionKeychainProbe(t *testing.T) {
	if os.Getenv("GOVAULT_KEYCHAIN_PROBE") == "" {
		t.Skip("set GOVAULT_KEYCHAIN_PROBE=1 to touch the real keychain")
	}
	kc := dataProtectionKeychain{}
	const account = "userkey:myvault-probe"
	_ = kc.Delete(account)
	addErr := kc.Add(account, []byte("probe"))
	exists, existsErr := kc.Exists(account)
	delErr := kc.Delete(account)
	t.Logf("SecItemAdd: %v (hardware unavailable: %v)", addErr, hardwareUnavailable(addErr))
	t.Logf("Exists: %v, %v", exists, existsErr)
	t.Logf("SecItemDelete: %v", delErr)

	if err := loadSecurity(); err != nil {
		t.Fatal(err)
	}
	var s cfScope
	defer s.release()
	query := func(extra ...uintptr) uintptr {
		return s.dict(append([]uintptr{
			sc.class, sc.classGenericPassword,
			sc.attrService, s.str(biometricKeychainService + " Probe"),
			sc.attrAccount, s.str(account),
		}, extra...)...)
	}
	cf.SecItemDelete(query())
	addStatus := cf.SecItemAdd(query(sc.valueData, s.data([]byte("probe-secret"))), nil)
	var result uintptr
	copyStatus := cf.SecItemCopyMatching(query(sc.returnData, sc.booleanTrue, sc.matchLimit, sc.matchLimitOne), &result)
	got := ""
	if result != 0 {
		got = string(unsafe.Slice(cf.CFDataGetBytePtr(result), cf.CFDataGetLength(result)))
		cf.CFRelease(result)
	}
	delStatus := cf.SecItemDelete(query())
	t.Logf("login keychain plumbing: add=%d copy=%d data=%q delete=%d", addStatus, copyStatus, got, delStatus)
	if addStatus != 0 || copyStatus != 0 || got != "probe-secret" || delStatus != 0 {
		t.Fatal("Core Foundation plumbing round trip failed")
	}
}
