package pcap

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Hard caps. Exposed as vars (not consts) so tests can shrink them.
var (
	MaxConcurrent       = 5
	MaxDuration         = 30 * time.Minute
	MaxSizeMB           = 500
	DefaultDuration     = 5 * time.Minute
	DefaultSizeMB       = 50
	PruneOlderThan      = 24 * time.Hour
	tcpdumpSearchPaths  = []string{"/usr/sbin/tcpdump", "/usr/bin/tcpdump"}
	filterAllowedRegexp = regexp.MustCompile(`^[A-Za-z0-9 ._:/\-]*$`)
)

// Capture is the public record describing one capture (running or
// stopped).
type Capture struct {
	ID            string        `json:"id"`
	Filter        string        `json:"filter"`
	Description   string        `json:"description"`
	StartedAt     time.Time     `json:"started_at"`
	StoppedAt     time.Time     `json:"stopped_at,omitempty"`
	DurationLimit time.Duration `json:"duration_limit"`
	SizeLimitMB   int           `json:"size_limit_mb"`
	Path          string        `json:"path"`
	Size          int64         `json:"size"`
	Status        string        `json:"status"` // "running" / "stopped" / "error: ..."
}

type captureRun struct {
	rec    Capture
	cmd    *exec.Cmd
	cancel context.CancelFunc
	doneCh chan struct{}
}

// Manager owns the on-disk capture directory and the set of in-flight
// captures.
type Manager struct {
	dir      string
	tcpdump  string
	mu       sync.RWMutex
	captures map[string]*captureRun
}

// NewManager creates a manager rooted at dir. Returns an error (with
// nil manager) when tcpdump is not installed — callers should log and
// continue without packet-capture support.
func NewManager(dir string) (*Manager, error) {
	bin := ""
	for _, p := range tcpdumpSearchPaths {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			bin = p
			break
		}
	}
	if bin == "" {
		return nil, errors.New("pcap: tcpdump not found in /usr/sbin or /usr/bin — install tcpdump to enable on-demand captures")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("pcap: mkdir %s: %w", dir, err)
	}
	return &Manager{
		dir:      dir,
		tcpdump:  bin,
		captures: map[string]*captureRun{},
	}, nil
}

// Dir returns the on-disk capture directory.
func (m *Manager) Dir() string { return m.dir }

// validateFilter rejects filters containing shell metacharacters AND
// argv flag smuggling (any token starting with '-'). Empty filter is
// allowed (captures all traffic). Returns the cleaned filter.
//
// Why reject leading '-': tcpdump has no end-of-options sentinel for
// the BPF expression on all distributions, so a filter token like
// "-z /bin/sh" would be parsed as the post-rotate command flag and
// give arbitrary command execution. Also blocks -r/-R (file read),
// -W/-G (rotation overrides), -V/-F (script file injection).
func validateFilter(f string) (string, error) {
	f = strings.TrimSpace(f)
	if len(f) > 512 {
		return "", errors.New("filter too long")
	}
	if !filterAllowedRegexp.MatchString(f) {
		return "", errors.New("filter contains disallowed characters (allowed: [A-Za-z0-9 ._:/-])")
	}
	if strings.HasPrefix(f, "-") {
		return "", errors.New("filter may not begin with '-'")
	}
	for _, tok := range splitFilter(f) {
		if strings.HasPrefix(tok, "-") {
			return "", errors.New("filter tokens may not start with '-' (argv flag smuggling guard)")
		}
	}
	return f, nil
}

func newID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Start launches a tcpdump capture with the given BPF filter.
//
// dur and sizeMB are caps — tcpdump exits when either is exceeded. If
// the caller passes 0 or negative values the defaults apply; values
// over MaxDuration / MaxSizeMB are clamped.
func (m *Manager) Start(ctx context.Context, filter, description string, dur time.Duration, sizeMB int) (Capture, error) {
	clean, err := validateFilter(filter)
	if err != nil {
		return Capture{}, err
	}
	if dur <= 0 {
		dur = DefaultDuration
	}
	if dur > MaxDuration {
		dur = MaxDuration
	}
	if sizeMB <= 0 {
		sizeMB = DefaultSizeMB
	}
	if sizeMB > MaxSizeMB {
		sizeMB = MaxSizeMB
	}

	m.mu.Lock()
	// Concurrency cap — count only running captures.
	running := 0
	for _, c := range m.captures {
		if c.rec.Status == "running" {
			running++
		}
	}
	if running >= MaxConcurrent {
		m.mu.Unlock()
		return Capture{}, fmt.Errorf("max concurrent captures reached (%d)", MaxConcurrent)
	}
	id := newID()
	// Avoid collision (extremely unlikely with 32 bits but cheap to check).
	for _, dup := m.captures[id]; dup; _, dup = m.captures[id] {
		id = newID()
	}
	path := filepath.Join(m.dir, id+".pcap")

	cctx, cancel := context.WithCancel(context.Background())
	// tcpdump arg list — -G dur_sec rotates every dur seconds, -W 1
	// stops after one file, -C size_mb sets per-file size cap (tcpdump
	// rotates when the dump file approaches this), -w writes raw pcap,
	// -i any binds to all interfaces, -U flushes per-packet, -n
	// suppresses name resolution (faster + safer).
	args := []string{
		"-i", "any",
		"-w", path,
		"-U",
		"-n",
		"-G", strconv.Itoa(int(dur / time.Second)),
		"-W", "1",
		"-C", strconv.Itoa(sizeMB),
	}
	if clean != "" {
		// Split on space — validated above to be safe.
		for _, tok := range splitFilter(clean) {
			args = append(args, tok)
		}
	}
	cmd := exec.CommandContext(cctx, m.tcpdump, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		cancel()
		m.mu.Unlock()
		return Capture{}, fmt.Errorf("pcap: start tcpdump: %w", err)
	}

	rec := Capture{
		ID:            id,
		Filter:        clean,
		Description:   description,
		StartedAt:     time.Now().UTC(),
		DurationLimit: dur,
		SizeLimitMB:   sizeMB,
		Path:          path,
		Status:        "running",
	}
	run := &captureRun{rec: rec, cmd: cmd, cancel: cancel, doneCh: make(chan struct{})}
	m.captures[id] = run
	m.mu.Unlock()

	// Hard deadline guard in case tcpdump's -G doesn't fire as expected
	// (older builds disagree about -G + -w behaviour). Adds a slop of
	// 10s so the operator-visible duration is honoured.
	go func() {
		select {
		case <-time.After(dur + 10*time.Second):
			cancel()
		case <-run.doneCh:
		}
	}()

	// Waiter — updates status when tcpdump exits.
	go func() {
		werr := cmd.Wait()
		// Try to chmod 0600 (best-effort).
		_ = os.Chmod(path, 0o600)
		m.mu.Lock()
		defer m.mu.Unlock()
		c := m.captures[id]
		if c == nil {
			close(run.doneCh)
			return
		}
		c.rec.StoppedAt = time.Now().UTC()
		if st, err := os.Stat(path); err == nil {
			c.rec.Size = st.Size()
		}
		if werr != nil && cctx.Err() == nil {
			c.rec.Status = "error: " + werr.Error()
		} else {
			c.rec.Status = "stopped"
		}
		close(run.doneCh)
	}()

	return rec, nil
}

// splitFilter splits on single spaces; validateFilter has already
// rejected anything dangerous so this is safe.
func splitFilter(s string) []string {
	out := []string{}
	cur := ""
	for _, r := range s {
		if r == ' ' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// Stop cancels an in-progress capture. No-op if already stopped.
func (m *Manager) Stop(id string) error {
	m.mu.Lock()
	c := m.captures[id]
	m.mu.Unlock()
	if c == nil {
		return errors.New("capture not found")
	}
	c.cancel()
	// Wait briefly so the waiter goroutine can update status.
	select {
	case <-c.doneCh:
	case <-time.After(2 * time.Second):
	}
	return nil
}

// Get returns the current capture record by ID.
func (m *Manager) Get(id string) (Capture, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c := m.captures[id]
	if c == nil {
		return Capture{}, false
	}
	rec := c.rec
	// Refresh size on the fly if still running.
	if rec.Status == "running" {
		if st, err := os.Stat(rec.Path); err == nil {
			rec.Size = st.Size()
		}
	}
	return rec, true
}

// List returns all known captures sorted with running first, then by
// started_at desc.
func (m *Manager) List() []Capture {
	m.mu.RLock()
	out := make([]Capture, 0, len(m.captures))
	for _, c := range m.captures {
		rec := c.rec
		if rec.Status == "running" {
			if st, err := os.Stat(rec.Path); err == nil {
				rec.Size = st.Size()
			}
		}
		out = append(out, rec)
	}
	m.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		ai := out[i].Status == "running"
		aj := out[j].Status == "running"
		if ai != aj {
			return ai
		}
		return out[i].StartedAt.After(out[j].StartedAt)
	})
	return out
}

// Path returns the pcap file path for download.
func (m *Manager) Path(id string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c := m.captures[id]
	if c == nil {
		return "", false
	}
	return c.rec.Path, true
}

// Delete removes a capture file + record. Stops the capture first if
// still running.
func (m *Manager) Delete(id string) error {
	m.mu.RLock()
	c := m.captures[id]
	m.mu.RUnlock()
	if c == nil {
		return errors.New("capture not found")
	}
	if c.rec.Status == "running" {
		_ = m.Stop(id)
	}
	m.mu.Lock()
	delete(m.captures, id)
	path := c.rec.Path
	m.mu.Unlock()
	_ = os.Remove(path)
	return nil
}

// Tick is called periodically by the daemon. Prunes stopped captures
// whose files are older than PruneOlderThan.
func (m *Manager) Tick() {
	cutoff := time.Now().Add(-PruneOlderThan)
	m.mu.Lock()
	stale := []string{}
	for id, c := range m.captures {
		if c.rec.Status == "running" {
			continue
		}
		if !c.rec.StoppedAt.IsZero() && c.rec.StoppedAt.Before(cutoff) {
			stale = append(stale, id)
		}
	}
	for _, id := range stale {
		path := m.captures[id].rec.Path
		delete(m.captures, id)
		_ = os.Remove(path)
	}
	m.mu.Unlock()
}
