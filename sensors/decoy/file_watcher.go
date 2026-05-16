package decoy

import (
	"context"
)

// FileHit is the cross-platform "an open happened" notification.
type FileHit struct {
	Path string
	PID  uint32
	Comm string
}

// HitFn is invoked once per detected honey-file access.
type HitFn func(FileHit)

// fileWatcher is the platform abstraction. Linux uses fanotify;
// other platforms use a polling fallback. Stop must be idempotent.
type fileWatcher interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}
