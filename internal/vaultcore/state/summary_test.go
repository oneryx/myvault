package state

import (
	"testing"

	"github.com/oneryx/myvault/internal/vaultcore/api"
)

func TestSummaryFlagsPasskeys(t *testing.T) {
	with := &Cipher{ID: "a", Type: api.CipherTypeLogin, Login: &Login{Fido2Credentials: []Fido2Credential{{CredentialID: "c"}}}}
	without := &Cipher{ID: "b", Type: api.CipherTypeLogin, Login: &Login{Username: "u"}}
	if !summarizeCipher(with).HasPasskey || summarizeCipher(without).HasPasskey {
		t.Fatal("HasPasskey does not follow the login's passkeys")
	}
}
