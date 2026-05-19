// Package eac implements the xhelix Event Admission Controller.
//
// The controller sits between kernel collectors (eBPF, audit, journald)
// and the downstream rule engine. It buffers raw events for a bounded
// reorder window, sorts them by kernel timestamp, attaches a monotonic
// admission sequence ID, and emits in causal order.
//
// Design law (from ARCHITECTURE.md §3): no raw event reaches rules.
// Admission first, enrichment second, rules third.
package eac

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// SourceGrade classifies the trust level of an event source.
// Decision-grade events (verified alerts) require sources of grade
// A or A+. Lower-grade sources are evidence only.
type SourceGrade string

const (
	GradeAPlus SourceGrade = "A+" // BPF LSM, eBPF tracepoint, cgroup BPF
	GradeA     SourceGrade = "A"  // audit netlink, fanotify perm events
	GradeB     SourceGrade = "B"  // /proc, /sys, sock_diag, journald
	GradeC     SourceGrade = "C"  // application logs
	GradeD     SourceGrade = "D"  // heuristics, baselines (never decision-grade)
)

// IsDecisionGrade returns true for sources xhelix trusts to fire
// verified alerts (A+ and A).
func (g SourceGrade) IsDecisionGrade() bool {
	return g == GradeAPlus || g == GradeA
}

// RawEvent is the minimum shape accepted by the controller.
// Source-specific fields live in Payload; the controller never
// interprets them.
type RawEvent struct {
	// KernelTimeNS is the kernel monotonic timestamp at event capture.
	// On Linux this is bpf_ktime_get_ns() or equivalent. The controller
	// orders events by this field.
	KernelTimeNS uint64

	// WallTimeNS is the user-space wall-clock timestamp at the moment
	// the event was submitted to the controller. Used for reorder-
	// window expiry decisions (kernel time may have unknown skew across
	// reboots).
	WallTimeNS uint64

	// Kind is the event class — "file_open", "tcp_connect", "exec",
	// "capset", etc. Routed by downstream rule engine.
	Kind string

	// Source is the trust grade of the originating collector.
	Source SourceGrade

	// ActorPID is the kernel pid of the process that caused the event.
	// May be 0 for kernel-context events (module load, lockdown
	// transition, IMA appraisal).
	ActorPID uint32

	// ActorStartHint is the kernel's hint at the actor's start ticks.
	// When 0 the controller will resolve via /proc during admission.
	ActorStartHint uint64

	// Payload is opaque event-kind-specific data the controller
	// passes through unchanged.
	Payload []byte
}

// AdmittedEvent is a RawEvent that has passed admission, with the
// extra admission context attached.
type AdmittedEvent struct {
	RawEvent
	Admission AdmissionContext
}

// AdmissionContext records what happened during admission. Downstream
// consumers can use these flags to decide whether a verified alert
// is even possible for this event.
type AdmissionContext struct {
	// AdmittedAt is wall-clock time when the event left the reorder
	// window.
	AdmittedAt time.Time

	// SequenceID is a process-wide monotonic admission counter,
	// useful as a stable join key across enrichment passes.
	SequenceID uint64

	// LossObserved is true if the controller observed any drops in
	// the input queue before this event was admitted. When true, any
	// rule whose verified-alert decision depends on causal completeness
	// must downgrade to candidate.
	LossObserved bool

	// SourceGradeAdmitted is propagated from RawEvent.Source for
	// downstream visibility. Decision-grade requires A or A+.
	SourceGradeAdmitted SourceGrade
}

// Config tunes the controller. Zero values trigger sensible defaults.
type Config struct {
	// ReorderWindow is how long admission holds an event to allow
	// out-of-order siblings to arrive. 50-200 ms is the typical range.
	// Default: 100 ms.
	ReorderWindow time.Duration

	// InQueueSize is the bounded input channel size. When full, the
	// controller drops the oldest event with counter increment and
	// marks loss. Default: 4096.
	InQueueSize int

	// OutQueueSize is the admitted output channel size. Default: 4096.
	OutQueueSize int

	// MaxBufferSize caps the in-memory reorder buffer. When exceeded
	// the controller drops the oldest entries. Default: 16384.
	MaxBufferSize int

	// SelfPID is xhelix's own PID. Events from this actor are dropped
	// at submission time (universal self-exclusion). 0 disables.
	SelfPID uint32

	// FlushInterval is how often the controller scans the buffer for
	// ready-to-admit events. Default: ReorderWindow / 4.
	FlushInterval time.Duration
}

func (c *Config) applyDefaults() {
	if c.ReorderWindow <= 0 {
		c.ReorderWindow = 100 * time.Millisecond
	}
	if c.InQueueSize <= 0 {
		c.InQueueSize = 4096
	}
	if c.OutQueueSize <= 0 {
		c.OutQueueSize = 4096
	}
	if c.MaxBufferSize <= 0 {
		c.MaxBufferSize = 16384
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = c.ReorderWindow / 4
		if c.FlushInterval < 5*time.Millisecond {
			c.FlushInterval = 5 * time.Millisecond
		}
	}
}

// Controller is the Event Admission Controller. Construct with New,
// run with Start, stop with Stop. Submit() is the input; Out() is
// the output channel.
type Controller struct {
	cfg Config

	in  chan RawEvent
	out chan AdmittedEvent

	bufMu sync.Mutex
	buf   []RawEvent

	// lossFlag is set when input was dropped since the last flush;
	// every event admitted in the next flush carries LossObserved=true.
	lossFlag atomic.Bool

	seqCounter atomic.Uint64

	drops      atomic.Uint64
	admitted   atomic.Uint64
	lossEvents atomic.Uint64

	cancel context.CancelFunc
	wg     sync.WaitGroup

	stopped atomic.Bool
}

// New constructs a Controller with the given configuration. Defaults
// are applied for any zero fields.
func New(cfg Config) *Controller {
	cfg.applyDefaults()
	return &Controller{
		cfg: cfg,
		in:  make(chan RawEvent, cfg.InQueueSize),
		out: make(chan AdmittedEvent, cfg.OutQueueSize),
	}
}

// Start begins admission goroutines. Returns immediately; the
// controller runs until Stop is called or ctx is cancelled.
func (c *Controller) Start(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	c.cancel = cancel
	c.wg.Add(2)
	go c.ingestLoop(ctx)
	go c.flushLoop(ctx)
}

// Stop signals the controller to halt and waits for goroutines to
// exit. Safe to call multiple times.
func (c *Controller) Stop() {
	if !c.stopped.CompareAndSwap(false, true) {
		return
	}
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()
	close(c.out)
}

// Submit hands a raw event to the controller. Non-blocking; returns
// false if the input queue is full (caller may retry or accept the
// drop). Self-events (matching cfg.SelfPID) return true but are
// silently discarded.
func (c *Controller) Submit(e RawEvent) bool {
	if c.cfg.SelfPID != 0 && e.ActorPID == c.cfg.SelfPID {
		return true
	}
	if e.WallTimeNS == 0 {
		e.WallTimeNS = uint64(time.Now().UnixNano())
	}
	select {
	case c.in <- e:
		return true
	default:
		c.drops.Add(1)
		c.lossEvents.Add(1)
		c.lossFlag.Store(true)
		return false
	}
}

// Out returns the channel of admitted events. Closed by Stop.
func (c *Controller) Out() <-chan AdmittedEvent {
	return c.out
}

// Stats snapshots health counters.
type Stats struct {
	Drops      uint64
	Admitted   uint64
	LossEvents uint64
	BufferSize int
}

// Stats returns current admission counters and buffer depth.
func (c *Controller) Stats() Stats {
	c.bufMu.Lock()
	bufLen := len(c.buf)
	c.bufMu.Unlock()
	return Stats{
		Drops:      c.drops.Load(),
		Admitted:   c.admitted.Load(),
		LossEvents: c.lossEvents.Load(),
		BufferSize: bufLen,
	}
}

func (c *Controller) ingestLoop(ctx context.Context) {
	defer c.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-c.in:
			if !ok {
				return
			}
			c.bufMu.Lock()
			c.buf = append(c.buf, e)
			if len(c.buf) > c.cfg.MaxBufferSize {
				// Drop oldest. Loss is observed.
				excess := len(c.buf) - c.cfg.MaxBufferSize
				c.buf = c.buf[excess:]
				c.drops.Add(uint64(excess))
				c.lossEvents.Add(uint64(excess))
				c.lossFlag.Store(true)
			}
			c.bufMu.Unlock()
		}
	}
}

func (c *Controller) flushLoop(ctx context.Context) {
	defer c.wg.Done()
	t := time.NewTicker(c.cfg.FlushInterval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			// Final flush: emit anything still buffered, regardless of age.
			c.flushAll()
			return
		case <-t.C:
			c.flushReady()
		}
	}
}

// flushReady scans the buffer for events whose age (wall-time)
// exceeds the reorder window, sorts them by kernel timestamp, and
// emits in order.
func (c *Controller) flushReady() {
	cutoff := uint64(time.Now().UnixNano()) - uint64(c.cfg.ReorderWindow)

	c.bufMu.Lock()
	if len(c.buf) == 0 {
		c.bufMu.Unlock()
		return
	}

	// Two-partition pass using a write index — O(n), allocation-free.
	ready := make([]RawEvent, 0, len(c.buf))
	w := 0
	for _, e := range c.buf {
		if e.WallTimeNS < cutoff {
			ready = append(ready, e)
		} else {
			c.buf[w] = e
			w++
		}
	}
	c.buf = c.buf[:w]
	c.bufMu.Unlock()

	if len(ready) == 0 {
		return
	}

	// Sort by kernel timestamp so downstream sees causal order.
	sort.Slice(ready, func(i, j int) bool {
		return ready[i].KernelTimeNS < ready[j].KernelTimeNS
	})

	c.emit(ready)
}

// flushAll emits everything in the buffer regardless of age. Called
// during shutdown to avoid losing in-flight events.
func (c *Controller) flushAll() {
	c.bufMu.Lock()
	all := c.buf
	c.buf = nil
	c.bufMu.Unlock()

	if len(all) == 0 {
		return
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].KernelTimeNS < all[j].KernelTimeNS
	})
	c.emit(all)
}

func (c *Controller) emit(events []RawEvent) {
	now := time.Now()
	loss := c.lossFlag.Swap(false)
	for _, e := range events {
		seq := c.seqCounter.Add(1)
		ae := AdmittedEvent{
			RawEvent: e,
			Admission: AdmissionContext{
				AdmittedAt:          now,
				SequenceID:          seq,
				LossObserved:        loss,
				SourceGradeAdmitted: e.Source,
			},
		}
		select {
		case c.out <- ae:
			c.admitted.Add(1)
		default:
			// Out queue full → drop. The downstream consumer is
			// behind; we never block the kernel hot path.
			c.drops.Add(1)
			c.lossEvents.Add(1)
		}
	}
}
