package decoy

import (
	"context"
	"os"
	"sync"
	"time"
)

// pollWatcher is the cross-platform fallback used when fanotify is
// unavailable. It re-stats every honey file every Interval and fires
// a synthetic FileHit when atime moves forward.
//
// pollWatcher is the default off Linux. On Linux we prefer
// fileWatcherFanotify (gated by build tag).
type pollWatcher struct {
	files    []HoneyFile
	hit      HitFn
	interval time.Duration

	mu     sync.Mutex
	cancel context.CancelFunc
	atimes map[string]time.Time
}

func newPollWatcher(files []HoneyFile, hit HitFn) *pollWatcher {
	return &pollWatcher{
		files:    files,
		hit:      hit,
		interval: 250 * time.Millisecond,
		atimes:   make(map[string]time.Time, len(files)),
	}
}

func (p *pollWatcher) Start(parent context.Context) error {
	for _, f := range p.files {
		if t, err := atimeOf(f.Path); err == nil {
			p.atimes[f.Path] = t
		}
	}
	ctx, cancel := context.WithCancel(parent)
	p.mu.Lock()
	p.cancel = cancel
	p.mu.Unlock()
	go p.loop(ctx)
	return nil
}

func (p *pollWatcher) Stop(ctx context.Context) error {
	p.mu.Lock()
	if p.cancel != nil {
		p.cancel()
	}
	p.mu.Unlock()
	return nil
}

func (p *pollWatcher) loop(ctx context.Context) {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, f := range p.files {
				newAt, err := atimeOf(f.Path)
				if err != nil {
					continue
				}
				prev := p.atimes[f.Path]
				if newAt.After(prev) {
					p.atimes[f.Path] = newAt
					p.hit(FileHit{Path: f.Path})
				}
			}
		}
	}
}

func atimeOf(path string) (time.Time, error) {
	st, err := os.Stat(path)
	if err != nil {
		return time.Time{}, err
	}
	return statATime(st), nil
}
