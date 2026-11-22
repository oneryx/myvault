package crypto

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

const encBufferHeader = 1 + aes.BlockSize + sha256.Size

// EncryptBuffer encrypts plain into the Bitwarden binary EncArrayBuffer layout:
// type 2 || IV || HMAC-SHA256(IV || ciphertext) || ciphertext.
func EncryptBuffer(plain []byte, key *SymmetricKey) ([]byte, error) {
	enc, err := EncryptBytes(plain, key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, encBufferHeader+len(enc.CT))
	out = append(out, byte(EncAesCbc256HmacSha256B64))
	out = append(out, enc.IV...)
	out = append(out, enc.MAC...)
	return append(out, enc.CT...), nil
}

// DecryptBuffer decrypts a binary EncArrayBuffer. Only the authenticated
// type 2 is accepted; the unauthenticated legacy type 0 is rejected.
func DecryptBuffer(buf []byte, key *SymmetricKey) ([]byte, error) {
	if len(buf) == 0 {
		return nil, ErrInvalidEncString
	}
	if t := EncType(buf[0]); t != EncAesCbc256HmacSha256B64 {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedEncType, t)
	}
	if len(buf) <= encBufferHeader {
		return nil, ErrInvalidEncString
	}
	return DecryptBytes(&EncString{
		Type: EncAesCbc256HmacSha256B64,
		IV:   buf[1 : 1+aes.BlockSize],
		MAC:  buf[1+aes.BlockSize : encBufferHeader],
		CT:   buf[encBufferHeader:],
	}, key)
}

func GenerateSymmetricKey() (*SymmetricKey, error) {
	var raw [64]byte
	defer ZeroBytes(raw[:])
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	return SymmetricKeyFromBytes(raw[:])
}
