//go:build !linux

package main

// notifyReady is a no-op on non-Linux platforms. xhelix only runs on
// Linux at runtime, but cross-builds (e.g., for Mac developer
// machines) compile cleanly.
func notifyReady() {}
