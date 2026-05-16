// Package replay re-evaluates a stored event stream against a
// (possibly different) ruleset.
//
// Use cases:
//
//   - Test a new rule against historic events before deploying.
//   - Re-investigate a past incident with updated detections.
//   - Audit: confirm a rule actually fired when expected.
//
// Replay is deterministic given the same event input and the same
// ruleset. The hash-chain verifier and replay together let an
// investigator reconstruct exactly what happened on a host even if
// the host has since been compromised.
package replay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/xhelix/xhelix/pkg/model"
)

// Source enumerates a sequence of events (in event-time order).
type Source interface {
	Next() (model.Event, bool)
}

// Sink consumes replayed events.
type Sink interface {
	OnEvent(model.Event)
	OnAlert(model.Alert)
}

// Replay drives source through processFn and routes alerts to sink.
//
// processFn is typically the rule engine's Eval method (or a
// CEP engine's Ingest); the test version is just a no-op so the
// pipeline can be unit-tested without a full engine.
func Replay(ctx context.Context, src Source, sink Sink, processFn func(context.Context, model.Event)) error {
	if src == nil {
		return errors.New("replay: source is required")
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		ev, ok := src.Next()
		if !ok {
			return nil
		}
		sink.OnEvent(ev)
		if processFn != nil {
			processFn(ctx, ev)
		}
	}
}

// FileSource reads events from one or more JSON-lines files in
// chronological order.
type FileSource struct {
	files []string
	cur   int
	dec   *json.Decoder
	rdr   *bytes.Reader
	body  []byte
}

// OpenFiles constructs a Source over the given paths. Paths are
// sorted lexicographically; for our chain layout this happens to be
// chronological because filenames are zero-padded batch IDs.
func OpenFiles(paths ...string) (*FileSource, error) {
	if len(paths) == 0 {
		return nil, errors.New("replay: at least one file is required")
	}
	out := append([]string{}, paths...)
	sort.Strings(out)
	return &FileSource{files: out}, nil
}

// OpenDir constructs a Source over every *.jsonl file in dir.
func OpenDir(dir string) (*FileSource, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if filepath.Ext(e.Name()) == ".jsonl" {
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("replay: no *.jsonl files in %s", dir)
	}
	return OpenFiles(paths...)
}

// Next returns the next event or (zero, false) at end of stream.
func (s *FileSource) Next() (model.Event, bool) {
	for {
		if s.dec == nil {
			if s.cur >= len(s.files) {
				return model.Event{}, false
			}
			body, err := os.ReadFile(s.files[s.cur])
			s.cur++
			if err != nil {
				continue
			}
			s.body = body
			s.rdr = bytes.NewReader(body)
			s.dec = json.NewDecoder(s.rdr)
		}
		var ev model.Event
		err := s.dec.Decode(&ev)
		if errors.Is(err, io.EOF) {
			s.dec = nil
			s.rdr = nil
			continue
		}
		if err != nil {
			s.dec = nil
			s.rdr = nil
			continue
		}
		return ev, true
	}
}

// MemorySource is an in-memory Source useful for tests.
type MemorySource struct {
	events []model.Event
	i      int
}

// NewMemorySource wraps a fixed list of events.
func NewMemorySource(events []model.Event) *MemorySource {
	return &MemorySource{events: events}
}

// Next implements Source.
func (m *MemorySource) Next() (model.Event, bool) {
	if m.i >= len(m.events) {
		return model.Event{}, false
	}
	ev := m.events[m.i]
	m.i++
	return ev, true
}

// CountingSink is a Sink for tests that just counts events and alerts.
type CountingSink struct {
	Events int
	Alerts int
}

// OnEvent implements Sink.
func (c *CountingSink) OnEvent(model.Event) { c.Events++ }

// OnAlert implements Sink.
func (c *CountingSink) OnAlert(model.Alert) { c.Alerts++ }
