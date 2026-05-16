package yara

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"
)

// External wraps a real YARA-class engine (yara or yara-x) reachable
// on the host as a subprocess. It is consulted by the Scanner when
// available; the pure-Go substring fallback runs otherwise.
//
// Why subprocess rather than CGo: the project's CGO_ENABLED=0 policy
// rules out linking libyara directly. A subprocess also keeps the
// YARA engine's address space disjoint from xhelix's, which is the
// right side of a security boundary.
type External struct {
	Bin     string        // "yara" or "yara-x"
	RuleDir string        // directory of *.yar files passed to the engine
	Timeout time.Duration // per-scan timeout

	available atomic.Bool
}

// NewExternal probes for an installed YARA engine and returns a
// configured wrapper. RuleDir may be empty; in that case the wrapper
// is "available" but every scan returns no matches.
func NewExternal(ruleDir string) *External {
	e := &External{RuleDir: ruleDir, Timeout: 5 * time.Second}
	if path, err := exec.LookPath("yara-x"); err == nil {
		e.Bin = path
		e.available.Store(true)
		return e
	}
	if path, err := exec.LookPath("yara"); err == nil {
		e.Bin = path
		e.available.Store(true)
		return e
	}
	return e
}

// Available reports whether a real engine binary was found.
func (e *External) Available() bool { return e.available.Load() }

// Scan runs the configured engine over a single file and returns the
// list of matched rule names.
//
// We invoke the engine non-recursively, fast-fail on error, and
// honour Timeout. Output format depends on the binary:
//
//   yara:    "<rule_name> <path>"
//   yara-x:  "<rule_name>" matching JSON-lines on -O json (we use
//            the plain-text mode for portability)
func (e *External) Scan(ctx context.Context, path string) ([]string, error) {
	if !e.Available() {
		return nil, errors.New("yara: no engine available")
	}
	if e.RuleDir == "" {
		return nil, nil
	}
	timeout := e.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{"-r", e.RuleDir, path}
	if strings.HasSuffix(e.Bin, "yara-x") {
		args = []string{"scan", "-r", e.RuleDir, path}
	}
	cmd := exec.CommandContext(scanCtx, e.Bin, args...)
	out, err := cmd.Output()
	if err != nil {
		// yara/yara-x return non-zero when no matches but produce no
		// output; treat that as "no match" rather than error.
		if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("yara scan: %w", err)
	}
	var matches []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Both engines start the matched-rule line with the rule name.
		if i := strings.Index(line, " "); i > 0 {
			matches = append(matches, line[:i])
		} else {
			matches = append(matches, line)
		}
	}
	return matches, nil
}
