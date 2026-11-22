package main

import "testing"

func TestSSHAgentHostUnavailableOnWindows(t *testing.T) {
	h := newSSHAgentHost("windows", t.TempDir())
	if h != nil {
		t.Fatal("Windows got a Unix socket ssh-agent host")
	}
	h.Clear()
	h.Stop()
	if newSSHAgentHost("linux", t.TempDir()) == nil {
		t.Fatal("Linux lost its ssh-agent host")
	}
}
