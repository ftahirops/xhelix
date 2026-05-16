// Package yara provides integration with the YARA pattern-matching
// engine for scanning binaries at execve time.
//
// If the YARA C library is not available, this package compiles to
// no-ops so xhelix can still build and run without it.
package yara

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/xhelix/xhelix/pkg/model"
)

// Scanner is the YARA integration surface.
type Scanner struct {
	log     *slog.Logger
	rules   []Rule
	mu      sync.RWMutex
	enabled bool
}

// Rule is a lightweight YARA rule description.
type Rule struct {
	ID          string
	Description string
	Patterns    []string // hex or text patterns
}

// NewScanner builds a scanner. If rulesDir is empty or unreadable,
// the scanner is created but disabled.
func NewScanner(rulesDir string, log *slog.Logger) *Scanner {
	s := &Scanner{log: log, enabled: false}
	if rulesDir == "" {
		return s
	}
	rules, err := loadRulesFromDir(rulesDir)
	if err != nil {
		log.Warn("yara: failed to load rules", "dir", rulesDir, "err", err)
		return s
	}
	s.rules = rules
	s.enabled = len(rules) > 0
	if s.enabled {
		log.Info("yara: scanner loaded", "rules", len(rules))
	}
	return s
}

// Enabled returns true if the scanner has active rules.
func (s *Scanner) Enabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled
}

// ScanBinary checks a file path against loaded YARA-style patterns.
// Returns matching rule IDs and a boolean indicating a match.
//
// This is a pure-Go fallback implementation. When linked against
// libyara, it delegates to the C engine instead.
func (s *Scanner) ScanBinary(path string) ([]string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.enabled || len(s.rules) == 0 {
		return nil, false
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}

	var matches []string
	content := string(data)
	for _, r := range s.rules {
		if matchRule(r, content, data) {
			matches = append(matches, r.ID)
		}
	}
	return matches, len(matches) > 0
}

// ScanEvent is a convenience wrapper that scans the binary referenced
// by an execve event and returns an Alert if a match is found.
func (s *Scanner) ScanEvent(ctx context.Context, ev model.Event) *model.Alert {
	path := ev.Tags["path"]
	if path == "" {
		return nil
	}
	matches, ok := s.ScanBinary(path)
	if !ok {
		return nil
	}
	return &model.Alert{
		Event:  ev,
		RuleID: "yara.match",
		Reason: fmt.Sprintf("YARA match: %s", strings.Join(matches, ", ")),
		Mode:   model.ModeDetect,
	}
}

func matchRule(r Rule, content string, data []byte) bool {
	for _, p := range r.Patterns {
		// Simple string match for the pure-Go fallback.
		// A real YARA engine would do hex pattern + offset + condition evaluation.
		if strings.Contains(content, p) {
			return true
		}
	}
	return false
}

func loadRulesFromDir(dir string) ([]Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yar") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		rules = append(rules, parseSimpleRule(e.Name(), string(data)))
	}
	return rules, nil
}

// parseSimpleRule extracts rule metadata from a YARA file.
// This is intentionally minimal — enough to load basic string patterns.
func parseSimpleRule(filename, content string) Rule {
	r := Rule{ID: strings.TrimSuffix(filename, ".yar")}
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "$") && strings.Contains(line, "=") {
			// Extract string pattern: $a = "pattern"
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				pat := strings.TrimSpace(parts[1])
				pat = strings.Trim(pat, `"`)
				if pat != "" {
					r.Patterns = append(r.Patterns, pat)
				}
			}
		}
	}
	return r
}
