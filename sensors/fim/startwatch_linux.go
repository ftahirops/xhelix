//go:build linux

package fim

import (
	"context"
)

// startInotify arms the real-time watcher (Linux only).
func (s *Sensor) startInotify(ctx context.Context) (int, error) {
	w, watched, err := newInotify(s.watchPaths, s.out, s.host)
	if err != nil {
		return 0, err
	}
	go w.Run(ctx)
	return len(watched), nil
}
