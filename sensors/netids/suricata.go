package netids

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// SuricataSupervisor manages a Suricata subprocess.
//
// xhelix does not embed Suricata's GPL source; we run it as a child
// and consume its EVE JSON. This package abstracts the subprocess
// lifecycle behind a Sensor-shaped surface that the daemon can
// register alongside its native sensors.
//
// Phase 4 implements the subprocess + restart-on-crash story. The
// EVE JSON ingest path lives next to it (suricata_eve.go).
type SuricataSupervisor struct {
	// BinaryPath is the suricata executable. Default "suricata".
	BinaryPath string
	// ConfigPath is suricata's yaml config; xhelix renders one
	// from operator config and points here.
	ConfigPath string
	// Interface is the AF_PACKET interface to capture from.
	Interface string
	// EveOutPath is the file Suricata writes EVE JSON to.
	EveOutPath string
	// PIDFile is where Suricata writes its pid.
	PIDFile string
	// MinRestartDelay is the minimum backoff between restarts.
	MinRestartDelay time.Duration
	// Logger is the slog or stdlib logger; nil disables logging.
	Logger Logger

	mu      sync.Mutex
	cmd     *exec.Cmd
	running atomic.Bool
	healthy atomic.Bool
	cancel  context.CancelFunc
	exited  chan error
}

// Logger is the minimal logging interface Phase 4 needs.
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// Start launches Suricata if the binary is available. If it isn't,
// Start returns nil (no-op) so a v0.2 build that targets a host
// without Suricata installed still boots; Healthy() reports false.
func (s *SuricataSupervisor) Start(parent context.Context) error {
	if !s.running.CompareAndSwap(false, true) {
		return errors.New("suricata: already running")
	}
	if s.BinaryPath == "" {
		s.BinaryPath = "suricata"
	}
	if _, err := exec.LookPath(s.BinaryPath); err != nil {
		s.running.Store(false)
		s.logf(s.Logger, "info", "suricata binary not found; netids disabled",
			"err", err.Error())
		return nil
	}
	if s.MinRestartDelay <= 0 {
		s.MinRestartDelay = 2 * time.Second
	}

	ctx, cancel := context.WithCancel(parent)
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()

	go s.supervise(ctx)
	return nil
}

// Stop terminates Suricata and waits for the supervisor to return.
func (s *SuricataSupervisor) Stop(ctx context.Context) error {
	if !s.running.CompareAndSwap(true, false) {
		return nil
	}
	s.mu.Lock()
	cancel := s.cancel
	cmd := s.cmd
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(os.Interrupt)
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	select {
	case <-deadline.C:
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// Healthy reports whether the Suricata subprocess is alive.
func (s *SuricataSupervisor) Healthy() bool { return s.healthy.Load() }

func (s *SuricataSupervisor) supervise(ctx context.Context) {
	delay := s.MinRestartDelay
	for ctx.Err() == nil {
		if err := s.runOnce(ctx); err != nil {
			s.logf(s.Logger, "warn", "suricata exited", "err", err.Error())
		}
		s.healthy.Store(false)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay *= 2
		if delay > 30*time.Second {
			delay = 30 * time.Second
		}
	}
}

func (s *SuricataSupervisor) runOnce(ctx context.Context) error {
	args := []string{
		"-c", s.ConfigPath,
		"--af-packet=" + s.Interface,
		"--runmode=workers",
	}
	if s.PIDFile != "" {
		args = append(args, "--pidfile", s.PIDFile)
		_ = os.MkdirAll(filepath.Dir(s.PIDFile), 0o750)
	}
	cmd := exec.CommandContext(ctx, s.BinaryPath, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil

	s.mu.Lock()
	s.cmd = cmd
	s.mu.Unlock()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	s.healthy.Store(true)
	s.logf(s.Logger, "info", "suricata started", "pid", cmd.Process.Pid)

	err := cmd.Wait()
	s.mu.Lock()
	s.cmd = nil
	s.mu.Unlock()
	return err
}

func (s *SuricataSupervisor) logf(l Logger, level, msg string, args ...any) {
	if l == nil {
		return
	}
	switch level {
	case "info":
		l.Info(msg, args...)
	case "warn":
		l.Warn(msg, args...)
	default:
		l.Error(msg, args...)
	}
}
