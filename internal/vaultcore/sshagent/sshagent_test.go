//go:build unix

package sshagent

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/oneryx/myvault/internal/vaultcore/gen"
)

func TestServer_ListSignAndClear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.sock")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path); err != ErrNotSocket {
		t.Fatalf("Listen over regular file = %v, want ErrNotSocket", err)
	}
	_ = os.Remove(path)

	srv, err := Listen(path)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v, %v", fi.Mode(), err)
	}

	key, err := gen.GenerateEd25519SSHKey("deploy")
	if err != nil {
		t.Fatal(err)
	}
	if n := srv.SetKeys([]Key{{PrivateKey: key.PrivateKey, Comment: "Deploy Key"}, {PrivateKey: "garbage"}}); n != 1 {
		t.Fatalf("SetKeys loaded %d keys, want 1", n)
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	client := agent.NewClient(conn)

	keys, err := client.List()
	if err != nil || len(keys) != 1 || keys[0].Comment != "Deploy Key" {
		t.Fatalf("List = (%v, %v)", keys, err)
	}
	if ssh.FingerprintSHA256(keys[0]) != key.KeyFingerprint {
		t.Fatalf("fingerprint mismatch")
	}
	data := []byte("challenge")
	sig, err := client.Sign(keys[0], data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := keys[0].Verify(data, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if err := client.RemoveAll(); err == nil {
		t.Fatalf("RemoveAll succeeded on read-only agent")
	}
	if err := client.Lock([]byte("pw")); err == nil {
		t.Fatalf("Lock succeeded on read-only agent")
	}

	pub := keys[0]
	srv.Clear()
	if keys, err := client.List(); err != nil || len(keys) != 0 {
		t.Fatalf("List after Clear = (%v, %v)", keys, err)
	}
	if _, err := client.Sign(pub, data); err == nil {
		t.Fatalf("Sign after Clear succeeded")
	}

	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("socket not removed on Close: %v", err)
	}
	if _, err := client.List(); err == nil {
		t.Fatalf("List succeeded after Close")
	}
}
