// Package alert defines the alert bus and its sink implementations.
package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"

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

// FileSink writes one JSON-encoded alert per line to a file, with
// size-based rotation.
//
// Rotation policy: when the active file's tracked byte count exceeds
// MaxSizeBytes, the file is renamed with a .1 suffix; existing
// .N files are shifted to .N+1; .Keep is deleted if present. The
// active path is then reopened for append.
//
// Size is tracked in-memory via an atomic counter to avoid one
// stat() syscall per write. The counter is seeded from the file's
// current size at open time.
type FileSink struct {
	mu           sync.Mutex
	w            io.WriteCloser
	path         string
	maxBytes     int64
	keep         int
	writtenBytes atomic.Int64
}

// FileSinkOptions controls rotation behaviour. Zero values disable
// rotation entirely (compatible with the Phase 0 callers).
type FileSinkOptions struct {
	// MaxSizeBytes triggers rotation when exceeded. 0 = no rotation.
	MaxSizeBytes int64

	// Keep is the number of rotated files retained (.1 .. .Keep).
	// Must be >= 1 when MaxSizeBytes > 0; values < 1 default to 7.
	Keep int
}

// NewFileSink opens path for appending and returns an unbounded
// FileSink. Preserved for compatibility with callers that don't
// configure rotation. Equivalent to NewFileSinkWithOptions(path,
// FileSinkOptions{}) — rotation disabled.
func NewFileSink(path string) (*FileSink, error) {
	return NewFileSinkWithOptions(path, FileSinkOptions{})
}

// NewFileSinkWithOptions opens path for appending with rotation
// controlled by opts. The directory is created (mode 0o750) if
// missing.
func NewFileSinkWithOptions(path string, opts FileSinkOptions) (*FileSink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("file sink mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("file sink open: %w", err)
	}
	keep := opts.Keep
	if opts.MaxSizeBytes > 0 && keep < 1 {
		keep = 7
	}
	s := &FileSink{
		w:        f,
		path:     path,
		maxBytes: opts.MaxSizeBytes,
		keep:     keep,
	}
	// Seed the byte counter from the existing file size so rotation
	// doesn't miss a file that was already large at startup.
	if st, err := f.Stat(); err == nil {
		s.writtenBytes.Store(st.Size())
	}
	return s, nil
}

func (s *FileSink) Name() string { return "file" }

func (s *FileSink) Send(ctx context.Context, a model.Alert) error {
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}
	line := append(body, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	// Rotate BEFORE writing if this line would push us over the cap.
	// Done under the same lock so concurrent Sends can't race.
	if s.maxBytes > 0 && s.writtenBytes.Load()+int64(len(line)) > s.maxBytes {
		if err := s.rotateLocked(); err != nil {
			// Rotation failure should not lose the alert — log it
			// inline by best-effort writing to stderr and continue
			// appending to the (oversized) current file.
			fmt.Fprintf(os.Stderr, "xhelix file-sink rotate failed: %v\n", err)
		}
	}

	if _, err := s.w.Write(line); err != nil {
		return fmt.Errorf("file sink write: %w", err)
	}
	s.writtenBytes.Add(int64(len(line)))
	return nil
}

// rotateLocked closes the current writer, shifts .N → .N+1, renames
// the active file to .1, deletes the now-overflow file (if any),
// and reopens the active path. Caller must hold s.mu.
func (s *FileSink) rotateLocked() error {
	if s.w != nil {
		_ = s.w.Close()
		s.w = nil
	}

	// Walk highest-to-lowest so we never overwrite an existing index.
	// .keep → delete; (keep-1) → keep; ... ; .1 → .2.
	for i := s.keep; i >= 1; i-- {
		src := s.path + "." + strconv.Itoa(i)
		dst := s.path + "." + strconv.Itoa(i+1)
		if i == s.keep {
			// Delete the file that would otherwise overflow.
			_ = os.Remove(src)
			continue
		}
		_, err := os.Stat(src)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			continue
		}
		if err := os.Rename(src, dst); err != nil {
			return fmt.Errorf("rotate %s → %s: %w", src, dst, err)
		}
	}

	// Move active → .1
	if _, err := os.Stat(s.path); err == nil {
		if err := os.Rename(s.path, s.path+".1"); err != nil {
			return fmt.Errorf("rotate active → .1: %w", err)
		}
	}

	// Reopen active for append.
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("rotate reopen: %w", err)
	}
	s.w = f
	s.writtenBytes.Store(0)
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
