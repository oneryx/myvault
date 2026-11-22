package state

import (
	"testing"

	"github.com/oneryx/myvault/internal/vaultcore/api"
)

func fieldVault() map[string]*Cipher {
	return map[string]*Cipher{
		"login": {ID: "login", Type: api.CipherTypeLogin, Name: "Router", Reprompt: 1,
			Login: &Login{Password: "router-password", TOTP: "JBSWY3DPEHPK3PXP",
				Fido2Credentials: []Fido2Credential{{CredentialID: "cred", KeyValue: "passkey-key-material"}}},
			Fields: []CustomField{
				{Name: "region", Value: "eu-west-zone", Type: 0},
				{Name: "api token", Value: "tok-hidden-value", Type: fieldHidden},
			}},
		"card": {ID: "card", Type: api.CipherTypeCard, Name: "Travel card",
			Card: &Card{Brand: "Amex", Number: "378282246310005", Code: "7391", CardholderName: "Jo Traveller"}},
		"ssh": {ID: "ssh", Type: api.CipherTypeSSHKey, Name: "Deploy",
			SSHKey: &SSHKey{PrivateKey: "privkeymaterial", PublicKey: "ssh-ed25519 AAAA", KeyFingerprint: "SHA256:fpsearchable"}},
		"id": {ID: "id", Type: api.CipherTypeIdentity, Name: "Me",
			Identity: &Identity{FirstName: "Ada", LastName: "Lovelace", Company: "Analytical Engines", City: "Marylebone",
				SSN: "123-45-6789", PassportNumber: "P9876543", LicenseNumber: "L5551234"}},
	}
}

func found(ciphers map[string]*Cipher, query string) []string {
	var ids []string
	for _, s := range searchCiphers(ciphers, query, SearchFilter{}, func(c *Cipher) bool { return c.HidePassword }) {
		ids = append(ids, s.ID)
	}
	return ids
}

// Search matches every field an item shows, its hidden fields too, and no
// password, TOTP secret, SSH private key or passkey.
func TestSearchMatchesItemFields(t *testing.T) {
	for q, want := range map[string]string{
		"eu-west-zone": "login", "tok-hidden-value": "login", "api token": "login",
		"amex": "card", "jo traveller": "card", "378282246310005": "card", "7391": "card",
		"fpsearchable": "ssh",
		"analytical":   "id", "marylebone": "id", "123-45-6789": "id", "p9876543": "id", "l5551234": "id", "ada lovelace": "id",
	} {
		if got := found(fieldVault(), q); len(got) != 1 || got[0] != want {
			t.Errorf("search %q = %v, want [%s]", q, got, want)
		}
	}
	for _, q := range []string{"router-password", "jbswy3dpehpk3pxp", "privkeymaterial", "passkey-key-material"} {
		if got := found(fieldVault(), q); len(got) != 0 {
			t.Errorf("search %q found %v", q, got)
		}
	}
}
