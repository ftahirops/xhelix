package memory

import (
	"sync"
	"time"
)

// SegfaultBurst tracks SIGSEGV deliveries per-pid over a rolling
// window and reports when the count crosses Threshold.
//
// The kernel-side counter lives in eBPF (sensors/ebpf/progs/memory/).
// This Go side is the userspace projection used by tests and by
// hosts where the eBPF backend is degraded.
type SegfaultBurst struct {
	Threshold int
	Window    time.Duration

	mu      sync.Mutex
	state   map[uint32]*burstState
}

type burstState struct {
	windowStart time.Time
	count       int
}

// NewSegfaultBurst returns a detector with sane defaults.
func NewSegfaultBurst() *SegfaultBurst {
	return &SegfaultBurst{
		Threshold: 10,
		Window:    time.Minute,
		state:     map[uint32]*burstState{},
	}
}

// Observe increments the per-pid counter; returns true when the
// threshold trips. The counter resets after a trip so the same pid
// can re-trip if it keeps failing.
func (b *SegfaultBurst) Observe(pid uint32, t time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	st, ok := b.state[pid]
	if !ok || t.Sub(st.windowStart) > b.Window {
		b.state[pid] = &burstState{windowStart: t, count: 1}
		return false
	}
	st.count++
	if st.count >= b.Threshold {
		st.count = 0
		return true
	}
	return false
}
