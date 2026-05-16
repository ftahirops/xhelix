// Package idlehint is the user-activity detector that feeds the
// "user idle + active egress" exfil correlator.
//
// Detecting "is there a user actively at the keyboard right now"
// is harder than it sounds:
//
//   - X11 has XScreenSaverQueryInfo, but requires linking against
//     libXss or hand-rolling X11 protocol.
//   - Wayland has ext-idle-notify-v1 — clean but needs a Wayland
//     client connection.
//   - GUI-less servers have neither, but still have keyboard /
//     mouse via /dev/input/event* if anyone happens to be
//     attached.
//
// Pure-Go pragmatic option: diff /proc/interrupts counters over
// the polling window. Lines like `i8042` (PS/2-class keyboard) and
// IRQs for USB HID + mouse increment whenever input arrives. Zero
// delta = no input.
//
// This is best-effort and observable: callers fold it into a
// scoring stack rather than treating it as authoritative. Pairs
// naturally with pkg/bandwidthbaseline — `(idle && spike)` becomes
// the "silent exfil" red alert.
package idlehint

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Source is the pluggable activity-counter interface. Tests inject
// fakes; production uses ProcInterruptsSource.
type Source interface {
	// CounterSum returns the current sum of every interrupt line
	// matching the source's input-device filter. Callers diff
	// the returned value across two polls; non-zero delta =
	// activity.
	CounterSum() (uint64, error)
}

// Detector polls a Source and reports "idle for >= window" status.
type Detector struct {
	Source Source

	// IdleThreshold — minimum continuous-no-delta duration to
	// consider the user idle. <=0 selects 60 seconds.
	IdleThreshold time.Duration

	mu          sync.Mutex
	lastCounter uint64
	lastChange  time.Time
	last        time.Time
	bootstrapped bool
	now         func() time.Time
}

// New returns a Detector ready for use. If source is nil, the
// default ProcInterruptsSource is used.
func New(source Source, threshold time.Duration) *Detector {
	if source == nil {
		source = NewProcInterruptsSource("/proc/interrupts")
	}
	if threshold <= 0 {
		threshold = 60 * time.Second
	}
	return &Detector{
		Source:        source,
		IdleThreshold: threshold,
		now:           time.Now,
	}
}

// Poll samples the source. Returns the *current* user activity
// state (true=user is active right now, i.e. seen activity within
// IdleThreshold). Errors from the source are surfaced; on error
// the previous state is preserved.
func (d *Detector) Poll() (active bool, err error) {
	sum, err := d.Source.CounterSum()
	if err != nil {
		return false, err
	}
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.last = now
	if !d.bootstrapped {
		d.lastCounter = sum
		d.lastChange = now
		d.bootstrapped = true
		return true, nil // first poll: optimistically active
	}
	if sum != d.lastCounter {
		d.lastCounter = sum
		d.lastChange = now
		return true, nil
	}
	// No counter change since last poll. User is idle iff the
	// no-change span exceeds the threshold.
	return now.Sub(d.lastChange) < d.IdleThreshold, nil
}

// IsIdle returns the cached state from the last Poll. Convenient
// for hot paths that don't want to incur the file I/O cost on
// every event.
func (d *Detector) IsIdle() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.bootstrapped {
		return false
	}
	return d.now().Sub(d.lastChange) >= d.IdleThreshold
}

// SinceLastActivity returns the elapsed time since the most-recent
// counter delta. Returns 0 before the first Poll.
func (d *Detector) SinceLastActivity() time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.bootstrapped {
		return 0
	}
	return d.now().Sub(d.lastChange)
}

// ── /proc/interrupts source ──────────────────────────────────

// ProcInterruptsSource sums the per-CPU columns of every
// /proc/interrupts line whose label matches an input-device
// pattern.
type ProcInterruptsSource struct {
	Path     string
	Patterns []string // case-insensitive substring match on the line label
}

// NewProcInterruptsSource returns a source pointing at the given
// file, using the default keyboard/mouse/touchpad pattern set.
func NewProcInterruptsSource(path string) *ProcInterruptsSource {
	if path == "" {
		path = "/proc/interrupts"
	}
	return &ProcInterruptsSource{
		Path: path,
		Patterns: []string{
			"i8042", // PS/2 keyboard + mouse
			"keyboard",
			"mouse",
			"touchpad",
			"synaptics",
			"elan",
			"trackpoint",
			"AT keyboard",
		},
	}
}

// CounterSum implements Source.
func (s *ProcInterruptsSource) CounterSum() (uint64, error) {
	f, err := os.Open(s.Path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return s.sumReader(f)
}

func (s *ProcInterruptsSource) sumReader(r io.Reader) (uint64, error) {
	var sum uint64
	br := bufio.NewScanner(r)
	br.Buffer(make([]byte, 64*1024), 1024*1024)
	for br.Scan() {
		line := br.Text()
		// Skip header line
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		label := strings.ToLower(line)
		matched := false
		for _, p := range s.Patterns {
			if strings.Contains(label, strings.ToLower(p)) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		// Sum the per-CPU integer columns between the colon and
		// the first non-digit character of the device label.
		rest := line[colon+1:]
		for _, tok := range strings.Fields(rest) {
			n, err := strconv.ParseUint(tok, 10, 64)
			if err != nil {
				break // hit the label column, done with this row
			}
			sum += n
		}
	}
	return sum, br.Err()
}
