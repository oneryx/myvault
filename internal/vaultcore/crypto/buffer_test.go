package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncryptBufferRoundTripAndTamper(t *testing.T) {
	key, err := GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	plain := bytes.Repeat([]byte("attachment\x00\xff"), 100)
	buf, err := EncryptBuffer(plain, key)
	if err != nil {
		t.Fatal(err)
	}
	if buf[0] != 2 || (len(buf)-encBufferHeader)%16 != 0 {
		t.Fatalf("unexpected layout: type=%d len=%d", buf[0], len(buf))
	}
	got, err := DecryptBuffer(buf, key)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("DecryptBuffer = (%d bytes, %v)", len(got), err)
	}

	for name, idx := range map[string]int{"iv": 1, "mac": 20, "ciphertext": len(buf) - 1} {
		tampered := bytes.Clone(buf)
		tampered[idx] ^= 0x01
		if _, err := DecryptBuffer(tampered, key); !errors.Is(err, ErrInvalidMAC) {
			t.Fatalf("tampered %s: err = %v, want ErrInvalidMAC", name, err)
		}
	}

	other, _ := GenerateSymmetricKey()
	if _, err := DecryptBuffer(buf, other); !errors.Is(err, ErrInvalidMAC) {
		t.Fatalf("wrong key: err = %v", err)
	}
	legacy := append([]byte{0}, buf[1:]...)
	if _, err := DecryptBuffer(legacy, key); !errors.Is(err, ErrUnsupportedEncType) {
		t.Fatalf("legacy type 0: err = %v", err)
	}
	if _, err := DecryptBuffer(buf[:encBufferHeader], key); !errors.Is(err, ErrInvalidEncString) {
		t.Fatalf("truncated: err = %v", err)
	}
}
