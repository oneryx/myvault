package main

import (
	"path/filepath"
	"sync"

	"github.com/oneryx/myvault/internal/vaultcore/sshagent"
)

type sshAgentHost struct {
	path string

	mu  sync.Mutex
	srv *sshagent.Server
}

// newSSHAgentHost returns nil where SSH clients do not use a Unix socket
// agent: on Windows, OpenSSH talks to a named pipe. A nil host does nothing.
func newSSHAgentHost(goos, dataDir string) *sshAgentHost {
	if goos == "windows" {
		return nil
	}
	return &sshAgentHost{path: filepath.Join(dataDir, "ssh-agent.sock")}
}

func (h *sshAgentHost) SocketPath() string { return h.path }

func (h *sshAgentHost) Start() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.srv != nil {
		return nil
	}
	srv, err := sshagent.Listen(h.path)
	if err != nil {
		return err
	}
	h.srv = srv
	return nil
}

func (h *sshAgentHost) Stop() {
	if h == nil {
		return
	}
	h.mu.Lock()
	srv := h.srv
	h.srv = nil
	h.mu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

func (h *sshAgentHost) SetKeys(keys []sshagent.Key) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.srv != nil {
		h.srv.SetKeys(keys)
	}
}

func (h *sshAgentHost) Clear() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.srv != nil {
		h.srv.Clear()
	}
}
