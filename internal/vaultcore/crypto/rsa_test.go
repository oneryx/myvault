package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func TestOrgKeyUnwrapRSAOAEP(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	rawUser := bytes.Repeat([]byte{7}, 64)
	userKey, _ := SymmetricKeyFromBytes(rawUser)
	encPriv, err := EncryptBytes(der, userKey)
	if err != nil {
		t.Fatal(err)
	}

	unwrapped, err := DecryptPrivateKey(encPriv.String(), userKey)
	if err != nil {
		t.Fatalf("DecryptPrivateKey: %v", err)
	}
	if !unwrapped.Equal(priv) {
		t.Fatal("unwrapped private key differs")
	}

	rawOrg := make([]byte, 64)
	for i := range rawOrg {
		rawOrg[i] = byte(200 - i)
	}
	for _, typ := range []EncType{EncRsa2048OaepSha256B64, EncRsa2048OaepSha1B64, EncRsa2048OaepSha256HmacSha256B64, EncRsa2048OaepSha1HmacSha256B64} {
		enc, err := EncryptRSA(rawOrg, &priv.PublicKey, typ)
		if err != nil {
			t.Fatalf("EncryptRSA(%d): %v", typ, err)
		}
		orgKey, err := DecryptOrgKey(enc.String(), unwrapped)
		if err != nil {
			t.Fatalf("DecryptOrgKey(type %d): %v", typ, err)
		}
		if got := orgKey.Bytes(); !bytes.Equal(got[:], rawOrg) {
			t.Fatalf("type %d org key mismatch", typ)
		}
	}

	wrongHash, _ := EncryptRSA(rawOrg, &priv.PublicKey, EncRsa2048OaepSha1B64)
	wrongHash.Type = EncRsa2048OaepSha256B64
	if _, err := DecryptOrgKey(wrongHash.String(), unwrapped); err == nil {
		t.Fatal("OAEP hash mismatch decrypted")
	}

	ZeroPrivateKey(unwrapped)
	if unwrapped.D.Sign() != 0 {
		t.Fatal("private exponent not zeroed")
	}
}
