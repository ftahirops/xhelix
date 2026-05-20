// Package dnspoison is a local DNS shim that resolves attacker-known
// (or attacker-shaped) domains to a sinkhole IP, while forwarding
// every other query transparently to an upstream resolver.
//
// Two classifiers decide whether a query is poisoned:
//
//  1. Known-bad list (substring match). Operator loads threat-intel
//     feeds; matches are unambiguous Tier-1 SignalC2Beacon-grade.
//  2. DGA heuristic. High Shannon entropy, no vowels, mostly digits
//     — classic algorithmically-generated domain patterns. Tier-2.
//
// Everything else is passed through verbatim. Real users keep their
// DNS working; attacker malware ends up on our sinkhole.
//
// See PROTECTED_SERVICES_TRAP.md §4.4.
package dnspoison

import (
	"math"
	"strings"
	"sync"
)

// MatchKind classifies why a domain was poisoned.
type MatchKind string

const (
	MatchNone     MatchKind = ""
	MatchKnownBad MatchKind = "known_bad"
	MatchDGA      MatchKind = "dga_heuristic"
)

// Classifier holds the known-bad list + DGA tuning.
type Classifier struct {
	mu       sync.RWMutex
	knownBad []string // lowercased; substring match

	// DGA thresholds. Defaults are conservative — operators can
	// tune via SetDGA() after observing real traffic for a while.
	MinLabelLen         int     // labels shorter than this can't be DGA. Default 8.
	MinEntropy          float64 // Shannon entropy threshold. Default 3.8.
	MaxVowelRatio       float64 // labels with vowels below this look DGA. Default 0.15.
	MinDigitFlagRatio   float64 // labels with digits above this look DGA. Default 0.40.
	NeedDGAVotes        int     // how many heuristics must agree. Default 2 of 3.

	// IgnoreSuffixes are TLDs we never flag as DGA — local + .arpa
	// look weird but are legitimate.
	IgnoreSuffixes []string
}

// NewClassifier returns a Classifier with conservative defaults.
func NewClassifier() *Classifier {
	return &Classifier{
		MinLabelLen:       8,
		MinEntropy:        3.5, // log2(12) ≈ 3.58 — catches 12+ char unique-char labels
		MaxVowelRatio:     0.15,
		MinDigitFlagRatio: 0.40,
		NeedDGAVotes:      2,
		IgnoreSuffixes:    defaultIgnoreSuffixes(),
	}
}

func defaultIgnoreSuffixes() []string {
	return []string{
		".local", ".localdomain", ".internal", ".intranet",
		".arpa", ".in-addr.arpa", ".ip6.arpa",
		".test", ".invalid", ".example", ".onion",
	}
}

// SetKnownBad replaces the known-bad list. Substring match,
// case-insensitive.
func (c *Classifier) SetKnownBad(domains []string) {
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" {
			out = append(out, d)
		}
	}
	c.mu.Lock()
	c.knownBad = out
	c.mu.Unlock()
}

// Classify returns MatchKnownBad / MatchDGA / MatchNone for the
// given fully-qualified domain. The compared form is lowercase with
// any trailing "." stripped.
func (c *Classifier) Classify(name string) MatchKind {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return MatchNone
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, bad := range c.knownBad {
		if strings.Contains(name, bad) {
			return MatchKnownBad
		}
	}

	for _, suf := range c.IgnoreSuffixes {
		if strings.HasSuffix(name, suf) {
			return MatchNone
		}
	}

	if c.looksDGA(name) {
		return MatchDGA
	}
	return MatchNone
}

// looksDGA runs the heuristic vote. Returns true if ≥ NeedDGAVotes
// of the three signals fire on any label in the domain.
func (c *Classifier) looksDGA(name string) bool {
	labels := strings.Split(name, ".")
	// Drop the TLD; DGA is in the SLD typically.
	if len(labels) >= 2 {
		labels = labels[:len(labels)-1]
	}
	for _, l := range labels {
		if c.labelLooksDGA(l) {
			return true
		}
	}
	return false
}

func (c *Classifier) labelLooksDGA(label string) bool {
	if len(label) < c.MinLabelLen {
		return false
	}
	votes := 0
	if entropy(label) >= c.MinEntropy {
		votes++
	}
	if vowelRatio(label) < c.MaxVowelRatio {
		votes++
	}
	if digitRatio(label) >= c.MinDigitFlagRatio {
		votes++
	}
	return votes >= c.NeedDGAVotes
}

// entropy returns the Shannon entropy of s in bits/char.
func entropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	count := map[rune]int{}
	for _, r := range s {
		count[r]++
	}
	var e float64
	n := float64(len(s))
	for _, c := range count {
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

func vowelRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	n := 0
	for _, r := range strings.ToLower(s) {
		switch r {
		case 'a', 'e', 'i', 'o', 'u', 'y':
			n++
		}
	}
	return float64(n) / float64(len(s))
}

func digitRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	n := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			n++
		}
	}
	return float64(n) / float64(len(s))
}
