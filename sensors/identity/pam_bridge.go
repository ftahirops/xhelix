package identity

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/sensors"
)

// PAMBridge listens on a Unix datagram socket for JSON lines emitted
// by the bundled pam_exec helper. Operators install
// `session optional pam_exec.so /usr/local/lib/xhelix/pam-bridge.sh`
// in target services (sshd, sudo, login) — the helper script
// pipe-writes one JSON line per PAM event to the socket xhelix is
// listening on.
type PAMBridge struct {
	SocketPath string
	Host       string

	mu      sync.Mutex
	out     chan<- model.Event
	ln      net.Listener
	cancel  context.CancelFunc
	running atomic.Bool
}

// NewPAMBridge constructs a bridge bound to socketPath.
func NewPAMBridge(socketPath, host string) *PAMBridge {
	return &PAMBridge{SocketPath: socketPath, Host: host}
}

// Name implements sensors.Sensor.
func (b *PAMBridge) Name() string { return "identity.pam" }

// Start creates the socket directory and starts the accept loop.
func (b *PAMBridge) Start(parent context.Context, out chan<- model.Event) error {
	if !b.running.CompareAndSwap(false, true) {
		return errors.New("pam: already started")
	}
	if b.SocketPath == "" {
		b.SocketPath = "/run/xhelix/pam.sock"
	}
	if err := os.MkdirAll(filepath.Dir(b.SocketPath), 0o750); err != nil {
		b.running.Store(false)
		return err
	}
	_ = os.Remove(b.SocketPath)

	ln, err := net.Listen("unix", b.SocketPath)
	if err != nil {
		b.running.Store(false)
		return err
	}
	if err := os.Chmod(b.SocketPath, 0o660); err != nil {
		_ = ln.Close()
		b.running.Store(false)
		return err
	}

	b.mu.Lock()
	b.out = out
	b.ln = ln
	ctx, cancel := context.WithCancel(parent)
	b.cancel = cancel
	b.mu.Unlock()

	go b.accept(ctx)
	return nil
}

// Stop closes the listener and removes the socket file.
func (b *PAMBridge) Stop(ctx context.Context) error {
	if !b.running.CompareAndSwap(true, false) {
		return nil
	}
	b.mu.Lock()
	if b.cancel != nil {
		b.cancel()
	}
	if b.ln != nil {
		_ = b.ln.Close()
		b.ln = nil
	}
	b.mu.Unlock()
	_ = os.Remove(b.SocketPath)
	return nil
}

// Health implements sensors.Sensor.
func (b *PAMBridge) Health() sensors.Health {
	return sensors.Health{Healthy: b.running.Load()}
}

func (b *PAMBridge) accept(ctx context.Context) {
	for ctx.Err() == nil {
		c, err := b.ln.Accept()
		if err != nil {
			return
		}
		go b.handle(ctx, c)
	}
}

func (b *PAMBridge) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	for ctx.Err() == nil {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			b.deliver(ctx, line)
		}
		if err != nil {
			return
		}
	}
}

// pamMessage is the JSON shape emitted by pam-bridge.sh.
type pamMessage struct {
	Type    string `json:"type"`
	Service string `json:"service"`
	User    string `json:"user"`
	RHost   string `json:"rhost"`
	TTY     string `json:"tty"`
}

func (b *PAMBridge) deliver(ctx context.Context, line []byte) {
	var msg pamMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		return
	}
	ev := model.NewEvent("identity.pam", model.SeverityInfo)
	ev.Host = b.Host
	ev.Tags["pam_type"] = msg.Type
	ev.Tags["service"] = msg.Service
	ev.Tags["user"] = msg.User
	ev.Tags["src_ip"] = msg.RHost
	ev.Tags["tty"] = msg.TTY

	b.mu.Lock()
	out := b.out
	b.mu.Unlock()
	if out == nil {
		return
	}
	select {
	case out <- ev:
	case <-ctx.Done():
	default:
	}
}
