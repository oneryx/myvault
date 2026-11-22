//go:build !darwin || ios

package main

func newHardwareKeychain() hardwareKeychain { return nil }
