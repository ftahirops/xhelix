package lsmaudit

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/sensors"
)

// Tailer is the Sensor that reads audit log lines and emits Events
// for AppArmor / SELinux denials.
//
// The default source is /var/log/audit/audit.log when present, with
// /var/log/kern.log and /var/log/syslog as fallbacks. Operators on
// pure-journald hosts may point at a fifo from
// `journalctl -k -f -o cat`.
type Tailer struct {
	Path string
	Host string

	mu      sync.Mutex
	out     chan<- model.Event
	cancel  context.CancelFunc
	running atomic.Bool
}

// NewTailer constructs a tailer. path == "" auto-selects.
func NewTailer(path, host string) *Tailer {
	if path == "" {
		for _, p := range []string{
			"/var/log/audit/audit.log",
			"/var/log/kern.log",
			"/var/log/syslog",
		} {
			if _, err := os.Stat(p); err == nil {
				path = p
				break
			}
		}
	}
	return &Tailer{Path: path, Host: host}
}

// Name implements sensors.Sensor.
func (t *Tailer) Name() string { return "lsm.audit" }

// Start begins tailing.
func (t *Tailer) Start(parent context.Context, out chan<- model.Event) error {
	if !t.running.CompareAndSwap(false, true) {
		return errors.New("lsmaudit: already started")
	}
	if t.Path == "" {
		// Degraded: no audit source available. Phase 5+ environments
		// without auditd or journald-kern will see no events; the
		// sensor is healthy but quiet.
		t.running.Store(false)
		return nil
	}
	t.mu.Lock()
	t.out = out
	ctx, cancel := context.WithCancel(parent)
	t.cancel = cancel
	t.mu.Unlock()

	go t.run(ctx)
	return nil
}

// Stop terminates the tailer.
func (t *Tailer) Stop(ctx context.Context) error {
	if !t.running.CompareAndSwap(true, false) {
		return nil
	}
	t.mu.Lock()
	if t.cancel != nil {
		t.cancel()
	}
	t.mu.Unlock()
	return nil
}

// Health implements sensors.Sensor.
func (t *Tailer) Health() sensors.Health {
	return sensors.Health{Healthy: t.running.Load()}
}

func (t *Tailer) run(ctx context.Context) {
	for ctx.Err() == nil {
		f, err := os.Open(t.Path)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}
		_, _ = f.Seek(0, io.SeekEnd)
		t.tail(ctx, f)
		_ = f.Close()
	}
}

func (t *Tailer) tail(ctx context.Context, f *os.File) {
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
		v, ok := Parse(line)
		if !ok {
			continue
		}
		t.deliver(ctx, ToEvent(v, t.Host))
	}
}

func (t *Tailer) deliver(ctx context.Context, ev model.Event) {
	t.mu.Lock()
	out := t.out
	t.mu.Unlock()
	if out == nil {
		return
	}
	select {
	case out <- ev:
	case <-ctx.Done():
	default:
	}
}
