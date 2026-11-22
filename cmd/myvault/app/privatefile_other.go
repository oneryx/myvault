//go:build !windows

package app

import "os"

// createPrivateTemp creates a new temporary file in dir that only the
// current user can read or write.
func createPrivateTemp(dir, pattern string) (*os.File, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nil, err
	}
	return f, nil
}
