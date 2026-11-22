package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

var ErrInvalidPrivateKey = errors.New("crypto: invalid RSA private key")

// DecryptPrivateKey unwraps the account's PKCS#8 RSA private key, which the
// server stores encrypted with the user key.
func DecryptPrivateKey(encPrivateKey string, userKey *SymmetricKey) (*rsa.PrivateKey, error) {
	enc, err := ParseEncString(encPrivateKey)
	if err != nil {
		return nil, err
	}
	der, err := DecryptBytes(enc, userKey)
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(der)
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPrivateKey, err)
	}
	priv, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidPrivateKey
	}
	return priv, nil
}

func DecryptRSA(enc *EncString, priv *rsa.PrivateKey) ([]byte, error) {
	if enc == nil || priv == nil {
		return nil, ErrInvalidEncString
	}
	h, err := oaepHash(enc.Type)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(h, nil, priv, enc.CT, nil)
}

func EncryptRSA(plaintext []byte, pub *rsa.PublicKey, encType EncType) (*EncString, error) {
	h, err := oaepHash(encType)
	if err != nil {
		return nil, err
	}
	ct, err := rsa.EncryptOAEP(h, rand.Reader, pub, plaintext, nil)
	if err != nil {
		return nil, err
	}
	return &EncString{Type: encType, CT: ct}, nil
}

// DecryptOrgKey unwraps an organization's 64-byte symmetric key.
func DecryptOrgKey(encOrgKey string, priv *rsa.PrivateKey) (*SymmetricKey, error) {
	enc, err := ParseEncString(encOrgKey)
	if err != nil {
		return nil, err
	}
	raw, err := DecryptRSA(enc, priv)
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(raw)
	return SymmetricKeyFromBytes(raw)
}

// ZeroPrivateKey overwrites the private key's secret numbers in place.
func ZeroPrivateKey(priv *rsa.PrivateKey) {
	if priv == nil {
		return
	}
	secrets := append([]*big.Int{priv.D, priv.Precomputed.Dp, priv.Precomputed.Dq, priv.Precomputed.Qinv}, priv.Primes...)
	for _, n := range secrets {
		if n != nil {
			clear(n.Bits())
			n.SetInt64(0)
		}
	}
}

func oaepHash(t EncType) (hash.Hash, error) {
	switch t {
	case EncRsa2048OaepSha256B64, EncRsa2048OaepSha256HmacSha256B64:
		return sha256.New(), nil
	case EncRsa2048OaepSha1B64, EncRsa2048OaepSha1HmacSha256B64:
		return sha1.New(), nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedEncType, t)
	}
}
