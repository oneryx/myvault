package gen

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"

	"golang.org/x/crypto/ssh"
)

type SSHKey struct {
	PrivateKey     string
	PublicKey      string
	KeyFingerprint string
}

func GenerateEd25519SSHKey(comment string) (SSHKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SSHKey{}, err
	}
	defer clear(priv)
	return SSHKeyFromEd25519(priv, comment)
}

func SSHKeyFromEd25519(priv ed25519.PrivateKey, comment string) (SSHKey, error) {
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return SSHKey{}, err
	}
	defer clear(block.Bytes)
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		return SSHKey{}, err
	}
	return SSHKey{
		PrivateKey:     string(pem.EncodeToMemory(block)),
		PublicKey:      authorizedKey(pub, comment),
		KeyFingerprint: ssh.FingerprintSHA256(pub),
	}, nil
}

// InspectSSHPrivateKey derives the public key and fingerprint of an unencrypted private key.
func InspectSSHPrivateKey(privateKey, comment string) (SSHKey, error) {
	signer, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		return SSHKey{}, err
	}
	pub := signer.PublicKey()
	return SSHKey{
		PrivateKey:     privateKey,
		PublicKey:      authorizedKey(pub, comment),
		KeyFingerprint: ssh.FingerprintSHA256(pub),
	}, nil
}

func authorizedKey(pub ssh.PublicKey, comment string) string {
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if c := strings.TrimSpace(comment); c != "" {
		line += " " + c
	}
	return line
}
