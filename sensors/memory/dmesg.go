// Package memory implements xhelix's memory-exploit-primitives plane.
//
// Phase 6 ships:
//
//   - DmesgWatcher tails kernel messages via journald or /dev/kmsg
//     and classifies oops/BUG/KASAN/LKRG events as Critical.
//   - SegfaultBurst counter detects spikes in SIGSEGV per pid.
//   - mprotect-RWX detection lives in the eBPF C source under
//     sensors/ebpf/progs/memory/.
//
// LKRG integration consists of recognising its dmesg prefix and
// forwarding the body as a Critical event.
package memory

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/sensors"
)

// DmesgWatcher tails kernel log messages.
//
// Default source is /dev/kmsg; operators on hosts with journald may
// point at a fifo fed from `journalctl -kf`. Each line is classified
// and unrecognised messages are silently ignored.
type DmesgWatcher struct {
	Path string // default /dev/kmsg
	Host string

	mu      sync.Mutex
	out     chan<- model.Event
	cancel  context.CancelFunc
	running atomic.Bool
}

// NewDmesgWatcher constructs a watcher.
func NewDmesgWatcher(path, host string) *DmesgWatcher {
	if path == "" {
		path = "/dev/kmsg"
	}
	return &DmesgWatcher{Path: path, Host: host}
}

// Name implements sensors.Sensor.
func (d *DmesgWatcher) Name() string { return "memory.dmesg" }

// Start opens the source and begins a goroutine tailer.
func (d *DmesgWatcher) Start(parent context.Context, out chan<- model.Event) error {
	if !d.running.CompareAndSwap(false, true) {
		return errors.New("dmesg: already started")
	}
	d.mu.Lock()
	d.out = out
	ctx, cancel := context.WithCancel(parent)
	d.cancel = cancel
	d.mu.Unlock()

	go d.run(ctx)
	return nil
}

// Stop terminates the tailer.
func (d *DmesgWatcher) Stop(ctx context.Context) error {
	if !d.running.CompareAndSwap(true, false) {
		return nil
	}
	d.mu.Lock()
	if d.cancel != nil {
		d.cancel()
	}
	d.mu.Unlock()
	return nil
}

// Health implements sensors.Sensor.
func (d *DmesgWatcher) Health() sensors.Health {
	return sensors.Health{Healthy: d.running.Load()}
}

func (d *DmesgWatcher) run(ctx context.Context) {
	for ctx.Err() == nil {
		f, err := os.Open(d.Path)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}
		_, _ = f.Seek(0, io.SeekEnd)
		d.tail(ctx, f)
		_ = f.Close()
	}
}

func (d *DmesgWatcher) tail(ctx context.Context, f *os.File) {
	r := bufio.NewReader(f)
	for ctx.Err() == nil {
		line, err := r.ReadString('\n')
		if errors.Is(err, io.EOF) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
				continue
			}
		}
		if err != nil {
			return
		}
		if ev, ok := classify(line, d.Host); ok {
			d.deliver(ctx, ev)
		}
	}
}

func (d *DmesgWatcher) deliver(ctx context.Context, ev model.Event) {
	d.mu.Lock()
	out := d.out
	d.mu.Unlock()
	if out == nil {
		return
	}
	select {
	case out <- ev:
	case <-ctx.Done():
	default:
	}
}

// Classify returns the classification token for msg, or "" when the
// message is not interesting.
//
// Exported so the rule engine and tests can call it directly.
func Classify(msg string) string {
	low := strings.ToLower(msg)
	switch {
	case strings.HasPrefix(strings.TrimSpace(msg), "[lkrg]") ||
		strings.Contains(msg, "[lkrg]"):
		return classifyLKRG(msg)
	case strings.Contains(low, "general protection fault"):
		return "gpf"
	case strings.Contains(msg, "kernel BUG at "):
		return "bug"
	case strings.Contains(msg, "BUG: KASAN"):
		return "kasan"
	case strings.Contains(low, "bug: kernel null pointer"):
		return "nullderef"
	case strings.Contains(msg, "Code: Bad RIP value"):
		return "bad_rip"
	case strings.Contains(msg, "WARNING: CPU:"):
		return "warn"
	case strings.Contains(low, "kernel: oops"):
		return "oops"
	case strings.Contains(msg, "Slab corruption"):
		return "slab_corruption"
	case strings.Contains(msg, "list_del corruption"):
		return "list_corruption"
	case strings.Contains(msg, "kernel stack guard page"):
		return "guard_page_hit"
	}
	return ""
}

func classifyLKRG(msg string) string {
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "cred"):
		return "lkrg_cred"
	case strings.Contains(low, "selinux"):
		return "lkrg_selinux"
	case strings.Contains(low, "kaslr"):
		return "lkrg_kaslr"
	case strings.Contains(low, "function pointer"):
		return "lkrg_fnptr"
	}
	return "lkrg_other"
}

func classify(line, host string) (model.Event, bool) {
	cls := Classify(line)
	if cls == "" {
		return model.Event{}, false
	}
	ev := model.NewEvent("memory.dmesg", model.SeverityCritical)
	ev.Host = host
	ev.Tags["class"] = cls
	ev.Tags["raw"] = strings.TrimSpace(line)
	return ev, true
}
