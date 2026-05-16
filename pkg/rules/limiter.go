package rules

import (
	"strconv"
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

// Limiter is a per-rule, per-key token-counter rate limiter.
//
// Each (rule, key) pair has a sliding 60-second window with at most
// rule.RateLimit.PerMinute fires permitted. Older windows roll off
// automatically; cleanup runs every minute.
type Limiter struct {
	mu       sync.Mutex
	buckets  map[bucketKey]*bucket
	stopCh   chan struct{}
	stopOnce sync.Once
}

type bucketKey struct {
	rule string
	key  string
}

type bucket struct {
	windowStart time.Time
	count       uint
}

// NewLimiter returns a fresh Limiter with a background cleanup
// goroutine.
func NewLimiter() *Limiter {
	l := &Limiter{
		buckets: make(map[bucketKey]*bucket, 1024),
		stopCh:  make(chan struct{}),
	}
	go l.cleaner()
	return l
}

// Stop terminates the cleanup goroutine. Idempotent.
func (l *Limiter) Stop() {
	l.stopOnce.Do(func() { close(l.stopCh) })
}

// Drop reports whether the rule should be silenced for this event.
// Returns true if the rule's per-minute quota is exhausted for the
// applicable key.
//
// Rules without a RateLimit configured are never dropped.
func (l *Limiter) Drop(r *model.Rule, ev model.Event) bool {
	if r.RateLimit == nil || r.RateLimit.PerMinute == 0 {
		return false
	}
	k := bucketKey{rule: r.ID, key: limiterKey(r.RateLimit.PerKey, ev)}
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[k]
	if !ok || now.Sub(b.windowStart) >= time.Minute {
		l.buckets[k] = &bucket{windowStart: now, count: 1}
		return false
	}
	if b.count >= r.RateLimit.PerMinute {
		return true
	}
	b.count++
	return false
}

func (l *Limiter) cleaner() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-l.stopCh:
			return
		case now := <-t.C:
			l.mu.Lock()
			for k, b := range l.buckets {
				if now.Sub(b.windowStart) >= 5*time.Minute {
					delete(l.buckets, k)
				}
			}
			l.mu.Unlock()
		}
	}
}

func limiterKey(perKey string, ev model.Event) string {
	switch perKey {
	case "pid":
		return strconv.FormatUint(uint64(ev.PID), 10)
	case "comm":
		return ev.Comm
	case "host":
		return ev.Host
	default:
		return "*"
	}
}
