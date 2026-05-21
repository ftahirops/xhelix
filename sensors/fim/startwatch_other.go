//go:build !linux

package fim

import "context"

// startInotify is a no-op outside Linux — the dev build stays
// green; the periodic verifier still runs.
func (s *Sensor) startInotify(_ context.Context) (int, error) {
	return 0, nil
}
