// Package alert defines the alert bus and its sink implementations.
//
// Phase 0 ships stdout, file, and a no-op syslog sink. Webhook and
// rich Slack/PagerDuty sinks land in later phases.
package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/xhelix/xhelix/pkg/model"
)

// StdoutSink emits a one-line text summary per alert to stdout.
type StdoutSink struct{}

func NewStdoutSink() *StdoutSink { return &StdoutSink{} }

func (s *StdoutSink) Name() string { return "stdout" }

func (s *StdoutSink) Send(ctx context.Context, a model.Alert) error {
	_, err := fmt.Fprintf(os.Stdout, "[%s] %-9s %-24s %s pid=%d comm=%s\n",
		a.Event.Time.UTC().Format("15:04:05"),
		a.Event.Severity.String(),
		a.RuleID,
		a.Reason,
		a.Event.PID,
		a.Event.Comm,
	)
	return err
}

func (s *StdoutSink) Close() error { return nil }

// FileSink writes one JSON-encoded alert per line to a file.
//
// In Phase 0 the file is opened on construction and never rotated;
// rotation lands in Phase 1 with a small rotator helper.
type FileSink struct {
	mu sync.Mutex
	w  io.WriteCloser
}

// NewFileSink opens path for appending and returns a FileSink.
//
// The directory is created if it does not exist (mode 0o750).
func NewFileSink(path string) (*FileSink, error) {
	if err := os.MkdirAll(dirOf(path), 0o750); err != nil {
		return nil, fmt.Errorf("file sink mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("file sink open: %w", err)
	}
	return &FileSink{w: f}, nil
}

func (s *FileSink) Name() string { return "file" }

func (s *FileSink) Send(ctx context.Context, a model.Alert) error {
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.w.Write(append(body, '\n')); err != nil {
		return fmt.Errorf("file sink write: %w", err)
	}
	return nil
}

func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.w == nil {
		return nil
	}
	err := s.w.Close()
	s.w = nil
	return err
}

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}
