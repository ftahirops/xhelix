//go:build !linux

package apparmor

import "errors"

// DefaultProfileDir is the canonical apparmor.d location (Linux).
// Defined here so cross-platform tests reference a stable constant.
const DefaultProfileDir = "/etc/apparmor.d"

// Install is a no-op stub on non-Linux platforms.
func (p Profile) Install(dir string, dryRun bool) (Profile, error) {
	return p, errors.New("apparmor: only available on linux")
}

// Unload stub.
func Unload(dir, name string) error {
	return errors.New("apparmor: only available on linux")
}

// Available returns false on non-Linux.
func Available() bool { return false }
