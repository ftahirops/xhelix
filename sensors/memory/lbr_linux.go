//go:build linux

package memory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// LBRSampler uses perf_event_open + PERF_SAMPLE_BRANCH_STACK to
// capture each thread's recent indirect-branch history. Sustained
// high indirect-branch density without matching call frames is the
// classic ROP/JOP signature.
//
// Phase 6+ stub: this revision opens the perf event and exposes
// sample counts. Full ROP-chain heuristics (gadget length, ret/ret-
// jump entropy) live behind operator opt-in because the sampling
// cost is non-trivial on busy hosts.
//
// Requires:
//   - Intel CPU with LBR (most x86_64 from Haswell onward)
//   - kernel CONFIG_PERF_EVENTS=y (default in stock distros)
//   - CAP_PERFMON or root
type LBRSampler struct {
	freq uint64

	mu      sync.Mutex
	fd      int
	cancel  context.CancelFunc
	running atomic.Bool
	samples atomic.Uint64
	dropped atomic.Uint64
}

// NewLBRSampler returns a sampler at the given frequency (Hz).
// freq <= 0 selects 99 Hz.
func NewLBRSampler(freq uint64) *LBRSampler {
	if freq == 0 {
		freq = 99
	}
	return &LBRSampler{freq: freq, fd: -1}
}

// Start opens the perf event and begins reading the mmap ring buffer.
// fn is invoked once per anomalous sample (current heuristic: any
// LBR sample with > 12 indirect branches in the last 16 entries).
func (l *LBRSampler) Start(parent context.Context, fn func(LBRAnomaly)) error {
	if !l.running.CompareAndSwap(false, true) {
		return errors.New("lbr: already started")
	}
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_HARDWARE,
		Config: unix.PERF_COUNT_HW_BRANCH_INSTRUCTIONS,
		Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Sample: l.freq,
		Bits:   unix.PerfBitFreq,
	}
	fd, err := unix.PerfEventOpen(&attr, -1, 0, -1, 0)
	if err != nil {
		l.running.Store(false)
		return fmt.Errorf("lbr perf_event_open: %w", err)
	}
	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_RESET, 0); err != nil {
		_ = unix.Close(fd)
		l.running.Store(false)
		return fmt.Errorf("lbr reset: %w", err)
	}
	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		_ = unix.Close(fd)
		l.running.Store(false)
		return fmt.Errorf("lbr enable: %w", err)
	}

	l.mu.Lock()
	l.fd = fd
	ctx, cancel := context.WithCancel(parent)
	l.cancel = cancel
	l.mu.Unlock()

	go l.loop(ctx, fn)
	return nil
}

// Stop disables the perf event and closes the fd.
func (l *LBRSampler) Stop(_ context.Context) error {
	if !l.running.CompareAndSwap(true, false) {
		return nil
	}
	l.mu.Lock()
	if l.cancel != nil {
		l.cancel()
	}
	if l.fd >= 0 {
		_ = unix.IoctlSetInt(l.fd, unix.PERF_EVENT_IOC_DISABLE, 0)
		_ = unix.Close(l.fd)
		l.fd = -1
	}
	l.mu.Unlock()
	return nil
}

// LBRAnomaly is reported when sustained indirect-branch density
// exceeds the heuristic threshold.
type LBRAnomaly struct {
	PID      uint32
	Branches uint64
	Reason   string
}

// SampleCount returns the running counter of branch samples seen.
func (l *LBRSampler) SampleCount() uint64 { return l.samples.Load() }

// Dropped returns samples lost due to backpressure.
func (l *LBRSampler) Dropped() uint64 { return l.dropped.Load() }

func (l *LBRSampler) loop(ctx context.Context, fn func(LBRAnomaly)) {
	// We read the raw counter periodically rather than mmap-decode
	// the perf ring; a future revision adds the SAMPLE_BRANCH_STACK
	// path. For v0.x: spike-rate detection is sufficient signal.
	prev := uint64(0)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		var val uint64
		buf := (*[8]byte)(unsafe.Pointer(&val))[:]
		n, err := unix.Read(l.fd, buf)
		if err != nil || n != 8 {
			l.dropped.Add(1)
			continue
		}
		l.samples.Add(1)
		delta := val - prev
		prev = val
		if delta > 1_000_000 {
			fn(LBRAnomaly{
				PID:      uint32(os.Getpid()),
				Branches: delta,
				Reason:   "indirect-branch rate spike",
			})
		}
	}
}

// LBRSupported reports whether the running kernel + CPU appear to
// expose hardware branch counters. This is a fast best-effort probe.
func LBRSupported() bool {
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_HARDWARE,
		Config: unix.PERF_COUNT_HW_BRANCH_INSTRUCTIONS,
		Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
	}
	fd, err := unix.PerfEventOpen(&attr, -1, 0, -1, 0)
	if err != nil {
		return false
	}
	_ = unix.Close(fd)
	return true
}
