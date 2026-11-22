//go:build unix

package sshagent

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"time"
)

func listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := removeStale(path); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

func removeStale(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSocket == 0 {
		return ErrNotSocket
	}
	if conn, err := net.DialTimeout("unix", path, 250*time.Millisecond); err == nil {
		_ = conn.Close()
		return ErrInUse
	}
	return os.Remove(path)
}
