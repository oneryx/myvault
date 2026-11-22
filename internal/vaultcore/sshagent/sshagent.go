// Package sshagent serves the SSH keys of the unlocked vault over a local,
// read-only ssh-agent socket.
package sshagent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	ErrReadOnly    = errors.New("sshagent: keys are managed by the vault")
	ErrInUse       = errors.New("sshagent: socket is already served by another process")
	ErrNotSocket   = errors.New("sshagent: socket path exists and is not a socket")
	ErrUnsupported = errors.New("sshagent: unix sockets are not supported on this platform")
)

type Key struct {
	PrivateKey string
	Comment    string
}

type loadedKey struct {
	raw     any
	signer  ssh.Signer
	blob    []byte
	comment string
}

type Server struct {
	path string
	ln   net.Listener

	mu     sync.RWMutex
	keys   []loadedKey
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

// Listen starts serving an empty agent on a user-private Unix socket at path.
func Listen(path string) (*Server, error) {
	ln, err := listen(path)
	if err != nil {
		return nil, err
	}
	s := &Server{path: path, ln: ln, conns: map[net.Conn]struct{}{}}
	s.wg.Add(1)
	go s.acceptLoop()
	return s, nil
}

func (s *Server) Path() string { return s.path }

// SetKeys replaces the served keys and returns how many could be loaded.
// Keys that fail to parse, including passphrase-protected ones, are skipped.
func (s *Server) SetKeys(keys []Key) int {
	loaded := make([]loadedKey, 0, len(keys))
	for _, k := range keys {
		raw, err := ssh.ParseRawPrivateKey([]byte(k.PrivateKey))
		if err != nil {
			continue
		}
		signer, err := ssh.NewSignerFromKey(raw)
		if err != nil {
			zeroKey(raw)
			continue
		}
		loaded = append(loaded, loadedKey{raw: raw, signer: signer, blob: signer.PublicKey().Marshal(), comment: k.Comment})
	}
	s.mu.Lock()
	old := s.keys
	if s.closed {
		old, loaded = loaded, nil
	}
	s.keys = loaded
	s.mu.Unlock()
	zeroKeys(old)
	return len(loaded)
}

// Clear drops and zeroes every served key.
func (s *Server) Clear() {
	s.mu.Lock()
	old := s.keys
	s.keys = nil
	s.mu.Unlock()
	zeroKeys(old)
}

func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	old := s.keys
	s.keys = nil
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	zeroKeys(old)
	err := s.ln.Close()
	s.wg.Wait()
	return err
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = conn.Close()
			return
		}
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			_ = agent.ServeAgent(readOnlyAgent{s}, conn)
			_ = conn.Close()
			s.mu.Lock()
			delete(s.conns, conn)
			s.mu.Unlock()
		}()
	}
}

type readOnlyAgent struct{ s *Server }

var _ agent.ExtendedAgent = readOnlyAgent{}

func (a readOnlyAgent) List() ([]*agent.Key, error) {
	a.s.mu.RLock()
	defer a.s.mu.RUnlock()
	out := make([]*agent.Key, 0, len(a.s.keys))
	for _, k := range a.s.keys {
		pub := k.signer.PublicKey()
		out = append(out, &agent.Key{Format: pub.Type(), Blob: bytes.Clone(k.blob), Comment: k.comment})
	}
	return out, nil
}

func (a readOnlyAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a readOnlyAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	want := key.Marshal()
	a.s.mu.RLock()
	defer a.s.mu.RUnlock()
	for _, k := range a.s.keys {
		if !bytes.Equal(k.blob, want) {
			continue
		}
		var alg string
		switch {
		case flags&agent.SignatureFlagRsaSha512 != 0:
			alg = ssh.KeyAlgoRSASHA512
		case flags&agent.SignatureFlagRsaSha256 != 0:
			alg = ssh.KeyAlgoRSASHA256
		default:
			return k.signer.Sign(rand.Reader, data)
		}
		algSigner, ok := k.signer.(ssh.AlgorithmSigner)
		if !ok {
			return nil, errors.New("sshagent: key does not support the requested signature algorithm")
		}
		return algSigner.SignWithAlgorithm(rand.Reader, data, alg)
	}
	return nil, errors.New("sshagent: key not found")
}

func (readOnlyAgent) Add(agent.AddedKey) error       { return ErrReadOnly }
func (readOnlyAgent) Remove(ssh.PublicKey) error     { return ErrReadOnly }
func (readOnlyAgent) RemoveAll() error               { return ErrReadOnly }
func (readOnlyAgent) Lock([]byte) error              { return ErrReadOnly }
func (readOnlyAgent) Unlock([]byte) error            { return ErrReadOnly }
func (readOnlyAgent) Signers() ([]ssh.Signer, error) { return nil, ErrReadOnly }
func (readOnlyAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

func zeroKeys(keys []loadedKey) {
	for _, k := range keys {
		zeroKey(k.raw)
	}
}

func zeroKey(raw any) {
	switch k := raw.(type) {
	case ed25519.PrivateKey:
		clear(k)
	case *ed25519.PrivateKey:
		clear(*k)
	case *rsa.PrivateKey:
		ints := append([]*big.Int{k.D, k.Precomputed.Dp, k.Precomputed.Dq, k.Precomputed.Qinv}, k.Primes...)
		for _, v := range ints {
			if v != nil {
				clear(v.Bits())
			}
		}
	case *ecdsa.PrivateKey:
		clear(k.D.Bits())
	}
}
