package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex %q: %v", s, err)
	}
	return b
}

func TestVector1_ValidateKDF(t *testing.T) {
	invalid := []KDFConfig{
		{Type: KDFPBKDF2, Iterations: 4999},
		{Type: KDFArgon2id, Iterations: 1, MemoryMB: 16, Parallelism: 1},
		{Type: KDFArgon2id, Iterations: 2, MemoryMB: 15, Parallelism: 1},
		{Type: KDFArgon2id, Iterations: 1, MemoryMB: 15, Parallelism: 1},
		{Type: KDFArgon2id, Iterations: 2, MemoryMB: 16, Parallelism: 0},
		{Type: KDFType(99), Iterations: 10000},
		{Type: KDFPBKDF2, Iterations: 2_000_001},
		{Type: KDFArgon2id, Iterations: 21, MemoryMB: 64, Parallelism: 4},
		{Type: KDFArgon2id, Iterations: 3, MemoryMB: 1025, Parallelism: 4},
		{Type: KDFArgon2id, Iterations: 3, MemoryMB: 64, Parallelism: 17},
	}
	for _, cfg := range invalid {
		if err := ValidateKDF(cfg); !errors.Is(err, ErrInvalidKDF) {
			t.Errorf("ValidateKDF(%+v) = %v, want ErrInvalidKDF", cfg, err)
		}
	}

	valid := []KDFConfig{
		{Type: KDFPBKDF2, Iterations: 5000},
		{Type: KDFArgon2id, Iterations: 2, MemoryMB: 16, Parallelism: 1},
		{Type: KDFPBKDF2, Iterations: 2_000_000},
		{Type: KDFArgon2id, Iterations: 20, MemoryMB: 1024, Parallelism: 16},
	}
	for _, cfg := range valid {
		if err := ValidateKDF(cfg); err != nil {
			t.Errorf("ValidateKDF(%+v) unexpected error: %v", cfg, err)
		}
	}
}

func TestVector2_PBKDF2MasterKey(t *testing.T) {
	key, err := DeriveMasterKey([]byte("67t9b5g67$%Dh89n"), "test_key", KDFConfig{
		Type:       KDFPBKDF2,
		Iterations: 10000,
	})
	if err != nil {
		t.Fatalf("DeriveMasterKey failed: %v", err)
	}

	want := mustHex(t, "1f4f68e29647b15ac250acd1118184518aa745a7fe95021b27c5402a16c3564b")
	if !bytes.Equal(key[:], want) {
		t.Fatalf("got %x, want %x", key[:], want)
	}
}

func TestVector3_Argon2idMasterKey(t *testing.T) {
	key, err := DeriveMasterKey([]byte("67t9b5g67$%Dh89n"), "test_key", KDFConfig{
		Type:        KDFArgon2id,
		Iterations:  4,
		MemoryMB:    32,
		Parallelism: 2,
	})
	if err != nil {
		t.Fatalf("DeriveMasterKey failed: %v", err)
	}

	want := mustHex(t, "cff0e1b1a213a34c626ab3afe00911f01493ed2ff6968db83ee183f23335e1f2")
	if !bytes.Equal(key[:], want) {
		t.Fatalf("got %x, want %x", key[:], want)
	}
}

func TestVector4_StretchMasterKey(t *testing.T) {
	var masterKey [32]byte
	copy(masterKey[:], mustHex(t, "1f4f68e29647b15ac250acd1118184518aa745a7fe95021b27c5402a16c3564b"))

	stretched, err := StretchMasterKey(masterKey)
	if err != nil {
		t.Fatalf("StretchMasterKey failed: %v", err)
	}

	wantEnc := mustHex(t, "6f1fb22dee9825728fd77c5387adc3178e8678f93d84a3b671c5bdccbc15ed60")
	wantMac := mustHex(t, "dd7fceea651bca265634221c4e1cb910303d7fa6d1f7c257e81a3055c1f9b39b")
	if !bytes.Equal(stretched.Enc[:], wantEnc) {
		t.Errorf("Enc = %x, want %x", stretched.Enc[:], wantEnc)
	}
	if !bytes.Equal(stretched.Mac[:], wantMac) {
		t.Errorf("Mac = %x, want %x", stretched.Mac[:], wantMac)
	}
}

func TestVector5_MasterPasswordHashPBKDF2Normalization(t *testing.T) {
	const wantHash = "wmyadRMyBZOH7P/a/ucTCbSghKgdzDpPqUnu/DAVtSw="
	cfg := KDFConfig{Type: KDFPBKDF2, Iterations: 100000}

	for _, email := range []string{"test@bitwarden.com", "TEST@bitwarden.com", " test@bitwarden.com"} {
		masterKey, err := DeriveMasterKey([]byte("asdfasdf"), email, cfg)
		if err != nil {
			t.Fatalf("DeriveMasterKey(%q) failed: %v", email, err)
		}
		got := HashMasterPasswordForServer(masterKey, []byte("asdfasdf"))
		if got != wantHash {
			t.Errorf("email %q: got %q, want %q", email, got, wantHash)
		}
	}
}

func TestVector6_MasterPasswordHashArgon2id(t *testing.T) {
	masterKey, err := DeriveMasterKey([]byte("asdfasdf"), "test_salt", KDFConfig{
		Type:        KDFArgon2id,
		Iterations:  4,
		MemoryMB:    32,
		Parallelism: 2,
	})
	if err != nil {
		t.Fatalf("DeriveMasterKey failed: %v", err)
	}

	const wantHash = "PR6UjYmjmppTYcdyTiNbAhPJuQQOmynKbdEl1oyi/iQ="
	if got := HashMasterPasswordForServer(masterKey, []byte("asdfasdf")); got != wantHash {
		t.Fatalf("got %q, want %q", got, wantHash)
	}
}

func TestVector7_Type2EncryptDecryptAndTamper(t *testing.T) {
	rawKey := make([]byte, 64)
	for i := range rawKey {
		rawKey[i] = byte(i)
	}
	key, err := SymmetricKeyFromBytes(rawKey)
	if err != nil {
		t.Fatalf("SymmetricKeyFromBytes failed: %v", err)
	}

	iv := mustHex(t, "d8da2400c4ba965531936ea8b9e32aac")
	const plaintext = "Bitwarden SDK test vector"
	const wantEnc = "2.2NokAMS6llUxk26oueMqrA==|6k0QD71SJLy2WEBDkV4esiTrgkP/z7eoSedSesGLGYE=|PE4sb0jpAwZW+tnyPuW43eeWvSxjvdw3xMJlPGbDlYI="

	enc, err := EncryptBytesWithIV([]byte(plaintext), iv, key)
	if err != nil {
		t.Fatalf("EncryptBytesWithIV failed: %v", err)
	}
	if got := enc.String(); got != wantEnc {
		t.Fatalf("EncString = %q, want %q", got, wantEnc)
	}

	gotPT, err := DecryptString(wantEnc, key)
	if err != nil {
		t.Fatalf("DecryptString failed: %v", err)
	}
	if gotPT != plaintext {
		t.Fatalf("plaintext = %q, want %q", gotPT, plaintext)
	}

	t.Run("tampered IV", func(t *testing.T) {
		parsed, _ := ParseEncString(wantEnc)
		parsed.IV[0] ^= 0x01
		if _, err := DecryptBytes(parsed, key); !errors.Is(err, ErrInvalidMAC) {
			t.Fatalf("got %v, want ErrInvalidMAC", err)
		}
	})

	t.Run("tampered CT", func(t *testing.T) {
		parsed, _ := ParseEncString(wantEnc)
		parsed.CT[0] ^= 0x01
		if _, err := DecryptBytes(parsed, key); !errors.Is(err, ErrInvalidMAC) {
			t.Fatalf("got %v, want ErrInvalidMAC", err)
		}
	})

	t.Run("tampered MAC", func(t *testing.T) {
		parsed, _ := ParseEncString(wantEnc)
		parsed.MAC[0] ^= 0x01
		if _, err := DecryptBytes(parsed, key); !errors.Is(err, ErrInvalidMAC) {
			t.Fatalf("got %v, want ErrInvalidMAC", err)
		}
	})

	t.Run("rejects type 0 for cipher fields", func(t *testing.T) {
		const type0 = "0.8UClLa8IPE1iZT7chy5wzQ==|6PVfHnVk5S3XqEtQemnM5yb4JodxmPkkWzmDRdfyHtjORmvxqlLX40tBJZ+CKxQWmS8tpEB5w39rbgHg/gqs0haGdZG4cPbywsgGzxZ7uNI="
		if _, err := DecryptString(type0, key); !errors.Is(err, ErrUnsupportedEncType) {
			t.Fatalf("got %v, want ErrUnsupportedEncType", err)
		}
	})
}

func TestVector8_LegacyType0UserKeyUnwrap(t *testing.T) {
	masterKey, err := DeriveMasterKey([]byte("asdfasdfasdf"), "legacy@bitwarden.com", KDFConfig{
		Type:       KDFPBKDF2,
		Iterations: 600000,
	})
	if err != nil {
		t.Fatalf("DeriveMasterKey failed: %v", err)
	}

	const protectedKey = "0.8UClLa8IPE1iZT7chy5wzQ==|6PVfHnVk5S3XqEtQemnM5yb4JodxmPkkWzmDRdfyHtjORmvxqlLX40tBJZ+CKxQWmS8tpEB5w39rbgHg/gqs0haGdZG4cPbywsgGzxZ7uNI="
	userKey, err := DecryptUserKey(protectedKey, masterKey)
	if err != nil {
		t.Fatalf("DecryptUserKey failed: %v", err)
	}

	wantEnc := mustHex(t, "0c5f97cb2504ec4389615a3a067ff21cd1a87d1d7618d52c75ca027384a57d94")
	wantMac := mustHex(t, "bad7ea8918a9e31dda39b4ed495bbd33fd1a1134e204864bc2d0b28580e08ca7")
	if !bytes.Equal(userKey.Enc[:], wantEnc) {
		t.Errorf("Enc = %x, want %x", userKey.Enc[:], wantEnc)
	}
	if !bytes.Equal(userKey.Mac[:], wantMac) {
		t.Errorf("Mac = %x, want %x", userKey.Mac[:], wantMac)
	}
}

func TestEncryptDecryptRoundTripAndWrongKey(t *testing.T) {
	var masterKey [32]byte
	for i := range masterKey {
		masterKey[i] = byte(i + 1)
	}
	stretched, err := StretchMasterKey(masterKey)
	if err != nil {
		t.Fatalf("StretchMasterKey failed: %v", err)
	}

	rawUserKey := make([]byte, 64)
	for i := range rawUserKey {
		rawUserKey[i] = byte(0xA0 + i)
	}
	userKey, err := SymmetricKeyFromBytes(rawUserKey)
	if err != nil {
		t.Fatalf("SymmetricKeyFromBytes failed: %v", err)
	}

	encUserKey, err := EncryptBytes(rawUserKey, stretched)
	if err != nil {
		t.Fatalf("EncryptBytes failed: %v", err)
	}
	unwrapped, err := DecryptUserKey(encUserKey.String(), masterKey)
	if err != nil {
		t.Fatalf("DecryptUserKey(type 2) failed: %v", err)
	}
	if unwrapped.Bytes() != userKey.Bytes() {
		t.Fatalf("unwrapped user key mismatch")
	}

	for _, pt := range []string{"", "short", "exact-16-bytes!!", "multi-block vault secret payload with utf-8: café"} {
		ct, err := EncryptString(pt, userKey)
		if err != nil {
			t.Fatalf("EncryptString(%q) failed: %v", pt, err)
		}
		got, err := DecryptString(ct, userKey)
		if err != nil {
			t.Fatalf("DecryptString failed: %v", err)
		}
		if got != pt {
			t.Errorf("round-trip got %q, want %q", got, pt)
		}
		if _, err := DecryptString(ct, stretched); !errors.Is(err, ErrInvalidMAC) {
			t.Errorf("wrong key got %v, want ErrInvalidMAC", err)
		}
	}
}

func TestZeroization(t *testing.T) {
	buf := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ZeroBytes(buf)
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("ZeroBytes left non-zero byte at index %d: %d", i, b)
		}
	}

	raw := make([]byte, 64)
	for i := range raw {
		raw[i] = 0xFF
	}
	key, err := SymmetricKeyFromBytes(raw)
	if err != nil {
		t.Fatalf("SymmetricKeyFromBytes failed: %v", err)
	}
	key.Zero()
	if key.Bytes() != [64]byte{} {
		t.Fatalf("SymmetricKey.Zero left non-zero bytes")
	}
}
