package decoy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/sensors"
)

// HoneyFile is a single decoy file plus its allowlist + canary token.
type HoneyFile struct {
	Path          string
	Persona       string
	AllowlistComm []string
	Token         string
}

// FilesSensor renders honey files on Start and (via the platform
// watcher) emits an event on every open. Phase 3's Linux watcher
// uses fanotify; the cross-platform fallback re-reads atime
// periodically.
type FilesSensor struct {
	files []HoneyFile
	out   chan<- model.Event
	host  string

	mu       sync.Mutex
	cancel   context.CancelFunc
	watcher  fileWatcher
	hits     map[string]int
	created  []string
}

// NewFilesSensor returns a configured sensor.
//
// On Start it ensures every file exists (rendering its persona
// content if missing) and records each path's inode for the Linux
// watcher. On Stop it leaves files in place — operators may want to
// keep them.
func NewFilesSensor(files []HoneyFile, host string) *FilesSensor {
	return &FilesSensor{files: files, host: host, hits: map[string]int{}}
}

// Name implements sensors.Sensor.
func (s *FilesSensor) Name() string { return "decoy.files" }

// Start implements sensors.Sensor.
func (s *FilesSensor) Start(parent context.Context, out chan<- model.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.out = out

	for i := range s.files {
		if s.files[i].Token == "" {
			s.files[i].Token = randomToken()
		}
		if err := s.render(&s.files[i]); err != nil {
			return fmt.Errorf("render %s: %w", s.files[i].Path, err)
		}
	}

	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel

	w, err := newFileWatcher(s.files, s.onHit)
	if err != nil {
		return err
	}
	s.watcher = w
	if err := w.Start(ctx); err != nil {
		return err
	}
	return nil
}

// Stop implements sensors.Sensor.
func (s *FilesSensor) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	if s.watcher != nil {
		return s.watcher.Stop(ctx)
	}
	return nil
}

// Health implements sensors.Sensor.
func (s *FilesSensor) Health() sensors.Health {
	s.mu.Lock()
	defer s.mu.Unlock()
	healthy := s.watcher != nil
	return sensors.Health{Healthy: healthy}
}

// Hits returns how many opens were observed per honey path. Useful
// for the TUI Decoys page and for tests.
func (s *FilesSensor) Hits() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.hits))
	for k, v := range s.hits {
		out[k] = v
	}
	return out
}

// onHit is invoked by the watcher when an open event fires. It emits
// a Critical event into the bus.
func (s *FilesSensor) onHit(hit FileHit) {
	s.mu.Lock()
	s.hits[hit.Path]++
	s.mu.Unlock()

	severity := model.SeverityCritical
	if isAllowlisted(hit, s.fileSpec(hit.Path)) {
		severity = model.SeverityNotice
	}
	ev := model.NewEvent("decoy", severity)
	ev.Host = s.host
	ev.PID = hit.PID
	ev.Comm = hit.Comm
	ev.Tags["honey_file_open"] = "true"
	ev.Tags["path"] = hit.Path
	ev.Tags["persona"] = s.fileSpec(hit.Path).Persona
	if s.out != nil {
		select {
		case s.out <- ev:
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (s *FilesSensor) fileSpec(path string) HoneyFile {
	for _, f := range s.files {
		if f.Path == path {
			return f
		}
	}
	return HoneyFile{Path: path}
}

func (s *FilesSensor) render(f *HoneyFile) error {
	p := PersonaByName(f.Persona)
	if p == nil {
		return errors.New("decoy: unknown persona " + f.Persona)
	}
	if f.Path == "" {
		f.Path = p.DefaultPath
	}
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o750); err != nil {
		return err
	}
	body := p.Render(f.Token)
	if err := os.WriteFile(f.Path, body, 0o600); err != nil {
		return err
	}
	s.created = append(s.created, f.Path)
	return nil
}

func isAllowlisted(hit FileHit, spec HoneyFile) bool {
	if hit.Comm == "" {
		return false
	}
	for _, c := range spec.AllowlistComm {
		if c == hit.Comm {
			return true
		}
	}
	return false
}

func randomToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
