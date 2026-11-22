package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

func EncryptBytes(plaintext []byte, key *SymmetricKey) (*EncString, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	return EncryptBytesWithIV(plaintext, iv, key)
}

func EncryptBytesWithIV(plaintext, iv []byte, key *SymmetricKey) (*EncString, error) {
	if key == nil {
		return nil, ErrInvalidKeyLength
	}
	if len(iv) != aes.BlockSize {
		return nil, ErrInvalidIV
	}

	block, err := aes.NewCipher(key.Enc[:])
	if err != nil {
		return nil, err
	}

	padded := pkcs7Pad(plaintext, aes.BlockSize)
	defer ZeroBytes(padded)

	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	ivCopy := make([]byte, aes.BlockSize)
	copy(ivCopy, iv)

	mac := computeMAC(key.Mac[:], ivCopy, ct)
	return &EncString{
		Type: EncAesCbc256HmacSha256B64,
		IV:   ivCopy,
		CT:   ct,
		MAC:  mac,
	}, nil
}

func EncryptString(plaintext string, key *SymmetricKey) (string, error) {
	pt := []byte(plaintext)
	defer ZeroBytes(pt)
	enc, err := EncryptBytes(pt, key)
	if err != nil {
		return "", err
	}
	return enc.String(), nil
}

func DecryptBytes(enc *EncString, key *SymmetricKey) ([]byte, error) {
	if enc == nil {
		return nil, ErrInvalidEncString
	}
	if key == nil {
		return nil, ErrInvalidKeyLength
	}
	if enc.Type != EncAesCbc256HmacSha256B64 {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedEncType, enc.Type)
	}
	if len(enc.IV) != aes.BlockSize {
		return nil, ErrInvalidIV
	}
	if len(enc.MAC) != sha256.Size {
		return nil, ErrInvalidMAC
	}
	if len(enc.CT) == 0 || len(enc.CT)%aes.BlockSize != 0 {
		return nil, ErrInvalidEncString
	}

	// Verify MAC in constant time before AES decryption to prevent padding-oracle leaks.
	expectedMAC := computeMAC(key.Mac[:], enc.IV, enc.CT)
	if !hmac.Equal(enc.MAC, expectedMAC) {
		return nil, ErrInvalidMAC
	}

	return decryptAESCBC(key.Enc[:], enc.IV, enc.CT)
}

func DecryptString(encStr string, key *SymmetricKey) (string, error) {
	enc, err := ParseEncString(encStr)
	if err != nil {
		return "", err
	}
	pt, err := DecryptBytes(enc, key)
	if err != nil {
		return "", err
	}
	defer ZeroBytes(pt)
	return string(pt), nil
}

func DecryptUserKey(protectedKey string, masterKey [32]byte) (*SymmetricKey, error) {
	enc, err := ParseEncString(protectedKey)
	if err != nil {
		return nil, err
	}

	switch enc.Type {
	case EncAesCbc256HmacSha256B64:
		stretched, err := StretchMasterKey(masterKey)
		if err != nil {
			return nil, err
		}
		defer stretched.Zero()

		raw, err := DecryptBytes(enc, stretched)
		if err != nil {
			return nil, err
		}
		defer ZeroBytes(raw)
		return SymmetricKeyFromBytes(raw)

	case EncAesCbc256B64:
		// Legacy pre-migration vaults protect UserKey with raw masterKey (no stretch, no MAC).
		if len(enc.IV) != aes.BlockSize {
			return nil, ErrInvalidIV
		}
		if len(enc.CT) == 0 || len(enc.CT)%aes.BlockSize != 0 {
			return nil, ErrInvalidEncString
		}
		raw, err := decryptAESCBC(masterKey[:], enc.IV, enc.CT)
		if err != nil {
			return nil, err
		}
		defer ZeroBytes(raw)
		return SymmetricKeyFromBytes(raw)

	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedEncType, enc.Type)
	}
}

func computeMAC(macKey, iv, ct []byte) []byte {
	h := hmac.New(sha256.New, macKey)
	h.Write(iv)
	h.Write(ct)
	return h.Sum(nil)
}

func decryptAESCBC(encKey, iv, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(buf, ct)

	pt, err := pkcs7Unpad(buf, aes.BlockSize)
	if err != nil {
		ZeroBytes(buf)
		return nil, err
	}
	out := make([]byte, len(pt))
	copy(out, pt)
	ZeroBytes(buf)
	return out, nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	out := make([]byte, len(data)+padLen)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(padLen)
	}
	return out
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, ErrInvalidPadding
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize || padLen > len(data) {
		return nil, ErrInvalidPadding
	}
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, ErrInvalidPadding
		}
	}
	return data[:len(data)-padLen], nil
}
