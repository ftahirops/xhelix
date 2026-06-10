//go:build !linux

package appregistry

// Discover is not implemented on non-Linux platforms.
func Discover() ([]DiscoveredService, error) {
	return nil, nil
}
