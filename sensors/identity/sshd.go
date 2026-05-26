// Package identity implements xhelix's authentication and session
// observability plane.
//
// Phase 5 ships:
//
//   - SSH log tailer (regex parser over journald or /var/log/auth.log)
//   - sudo / su event tailer (same source)
//   - PAM bridge (Unix-socket receiver of pam_exec lines)
//
// All sources project to a uniform identity event with tags:
// service, user, target_user, src_ip, tty, session_id, outcome,
// method, key_fp.
package identity

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/sensors"
)

// SSHTailer reads sshd log lines and projects to identity events.
//
// The default source is /var/log/auth.log (Debian/Ubuntu) and
// /var/log/secure (RHEL family). On hosts using journald, callers
// should point Path to a fifo fed by `journalctl -u sshd -f -o short`,
// or use a Phase-5b sd-journal binding.
type SSHTailer struct {
	Path string
	Host string

	mu      sync.Mutex
	out     chan<- model.Event
	cancel  context.CancelFunc
	running atomic.Bool
}

// NewSSHTailer returns a tailer for the given path. path == "" picks
// /var/log/auth.log if it exists, else /var/log/secure.
func NewSSHTailer(path, host string) *SSHTailer {
	if path == "" {
		for _, candidate := range []string{"/var/log/auth.log", "/var/log/secure"} {
			if _, err := os.Stat(candidate); err == nil {
				path = candidate
				break
			}
		}
	}
	return &SSHTailer{Path: path, Host: host}
}

// Name implements sensors.Sensor.
func (s *SSHTailer) Name() string { return "identity.sshd" }

// Start opens the file, seeks to end, and tails for sshd lines.
// If Path is unavailable, Start logs and returns nil — degraded.
func (s *SSHTailer) Start(parent context.Context, out chan<- model.Event) error {
	if !s.running.CompareAndSwap(false, true) {
		return errors.New("sshd: already started")
	}
	if s.Path == "" {
		s.running.Store(false)
		return nil
	}
	s.mu.Lock()
	s.out = out
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	s.mu.Unlock()

	go s.run(ctx)
	return nil
}

// Stop implements sensors.Sensor.
func (s *SSHTailer) Stop(ctx context.Context) error {
	if !s.running.CompareAndSwap(true, false) {
		return nil
	}
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	return nil
}

// Health implements sensors.Sensor.
func (s *SSHTailer) Health() sensors.Health {
	return sensors.Health{Healthy: s.running.Load()}
}

func (s *SSHTailer) run(ctx context.Context) {
	for ctx.Err() == nil {
		f, err := os.Open(s.Path)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}
		_, _ = f.Seek(0, io.SeekEnd)
		s.tail(ctx, f)
		_ = f.Close()
	}
}

func (s *SSHTailer) tail(ctx context.Context, f *os.File) {
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
		if ev, ok := ParseSSHDLine(line, s.Host); ok {
			s.deliver(ctx, ev)
		}
	}
}

func (s *SSHTailer) deliver(ctx context.Context, ev model.Event) {
	s.mu.Lock()
	out := s.out
	s.mu.Unlock()
	if out == nil {
		return
	}
	select {
	case out <- ev:
	case <-ctx.Done():
	default:
	}
}

// Patterns we recognise. Each pattern produces an Event; unmatched
// lines are silently ignored (auth.log has many irrelevant entries).
// Each regex captures the daemon PID as the first group so the parsed
// event can carry ev.PID = the sshd/sudo/su process PID. This lets
// pkg/source.Minter.AttributeSource attach the new SourceAnchor to the
// live process, which is what enables proctree propagation to
// session-spawned descendants. Without the PID, the anchor mints but no
// child events ever inherit (audited 2026-05-24 — 12 SSH anchors had
// only 1 attributed event each, exactly the identity event itself).
var (
	reAccepted = regexp.MustCompile(
		`sshd\[(\d+)\]: Accepted (\w+) for (\S+) from (\S+) port (\d+)`)
	reFailed = regexp.MustCompile(
		`sshd\[(\d+)\]: Failed (\w+) for (\S+) from (\S+) port (\d+)`)
	reInvalid = regexp.MustCompile(
		`sshd\[(\d+)\]: Invalid user (\S+) from (\S+)`)
	reSudo = regexp.MustCompile(
		`sudo\[(\d+)\]:\s+(\S+) : TTY=(\S+)\s+;\s+PWD=(\S+)\s+;\s+USER=(\S+)\s+;\s+COMMAND=(.+)$`)
	reSu = regexp.MustCompile(
		`su\[(\d+)\]:\s+\(to\s+(\S+)\)\s+(\S+)\s+on\s+(\S+)`)
)

// ParseSSHDLine extracts a model.Event from a single auth log line.
// Returns ok=false for lines we don't recognise.
//
// Also handles sudo/su lines so a single tailer can drive both
// sources. v0.2 may split these into dedicated sensors.
func ParseSSHDLine(line, host string) (model.Event, bool) {
	line = strings.TrimRight(line, "\r\n")

	if m := reAccepted.FindStringSubmatch(line); m != nil {
		ev := model.NewEvent("identity.sshd", model.SeverityInfo)
		ev.Host = host
		ev.PID = parsePID(m[1])
		ev.Tags["service"] = "sshd"
		ev.Tags["outcome"] = "success"
		ev.Tags["method"] = m[2]
		ev.Tags["user"] = m[3]
		ev.Tags["src_ip"] = m[4]
		ev.Tags["src_port"] = m[5]
		return ev, true
	}
	if m := reFailed.FindStringSubmatch(line); m != nil {
		ev := model.NewEvent("identity.sshd", model.SeverityWarn)
		ev.Host = host
		ev.PID = parsePID(m[1])
		ev.Tags["service"] = "sshd"
		ev.Tags["outcome"] = "failure"
		ev.Tags["method"] = m[2]
		ev.Tags["user"] = m[3]
		ev.Tags["src_ip"] = m[4]
		ev.Tags["src_port"] = m[5]
		return ev, true
	}
	if m := reInvalid.FindStringSubmatch(line); m != nil {
		ev := model.NewEvent("identity.sshd", model.SeverityNotice)
		ev.Host = host
		ev.PID = parsePID(m[1])
		ev.Tags["service"] = "sshd"
		ev.Tags["outcome"] = "invalid_user"
		ev.Tags["user"] = m[2]
		ev.Tags["src_ip"] = m[3]
		return ev, true
	}
	if m := reSudo.FindStringSubmatch(line); m != nil {
		ev := model.NewEvent("identity.sudo", model.SeverityNotice)
		ev.Host = host
		ev.PID = parsePID(m[1])
		ev.Tags["service"] = "sudo"
		ev.Tags["user"] = m[2]
		ev.Tags["tty"] = m[3]
		ev.Tags["pwd"] = m[4]
		ev.Tags["target_user"] = m[5]
		ev.Tags["command"] = m[6]
		return ev, true
	}
	if m := reSu.FindStringSubmatch(line); m != nil {
		ev := model.NewEvent("identity.su", model.SeverityNotice)
		ev.Host = host
		ev.PID = parsePID(m[1])
		ev.Tags["service"] = "su"
		ev.Tags["target_user"] = m[2]
		ev.Tags["user"] = m[3]
		ev.Tags["tty"] = m[4]
		return ev, true
	}
	return model.Event{}, false
}

// parsePID parses a decimal PID string into uint32. Returns 0 on any
// error; callers treat 0 as "PID unknown" and skip proctree attribution.
func parsePID(s string) uint32 {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}
