//go:build !unix

package sshagent

import "net"

func listen(string) (net.Listener, error) { return nil, ErrUnsupported }
