//go:build !linux

package seccomp

import "errors"

// Install is a no-op stub on non-Linux platforms. xhelix only
// supervises Linux services in production; this stub exists so the
// package compiles for dev workflows on macOS/Windows.
func (p Profile) Install() error {
	return errors.New("seccomp: only available on linux")
}

// SelfTest stub.
func (p Profile) SelfTest() error {
	return errors.New("seccomp: only available on linux")
}
