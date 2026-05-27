// Package sourcescore assigns a per-source risk score from observed
// TTP tokens (T08 / C2).
//
// The source-anchor subsystem (pkg/source) attributes every process /
// file / net event back to its ingress (HTTP request, SSH session,
// cron tick, dropped-file lineage). Incident assembly accumulates
// TTP tokens per chain. This package turns that token bag into one
// 0-100 score so the operator can rank in-flight sources without
// reading every event.
//
// Why a calibrated bag rather than ML: tokens are deterministic, the
// weights are visible, and operators can audit + tune. ML inference
// would add a black-box dependency and (per project policy) is out
// of scope.
//
// Honest non-promise: the score is an aggregate hint, not a verdict.
// Two tokens of the same weight may mean very different things in
// context; downstream containment should still consult the verifier.
package sourcescore

import (
	"sort"
	"strings"
	"sync"
)

// Token is a short stable TTP token (matches incidentgraph's
// TTPTags strings).
type Token string

// Weight returns the calibrated points contributed by token t. The
// table is tuned so a single "ingress only" stays near 0, a single
// "shell_spawn" lands around 30, and three-token chains like
// (shell_spawn, cred_access, c2_beacon) reach the 80-100 band.
//
// Unknown tokens contribute 5 (a baseline credit so novel signal
// doesn't disappear, but not enough to inflate a score alone).
func Weight(t Token) int {
	if w, ok := weights[t]; ok {
		return w
	}
	return 5
}

var weights = map[Token]int{
	// Foothold / discovery
	"recon":             6,
	"port_scan":         8,
	"path_enum":         6,
	"asset_discovery":   8,

	// Execution
	"shell_spawn":       30,
	"interpreter_exec":  18,
	"lolbin_exec":       22,
	"dropped_binary":    28,
	"living_off_land":   18,

	// Persistence
	"persistence":       25,
	"crontab_install":   24,
	"systemd_install":   24,
	"shell_rc_install":  20,

	// Privilege escalation
	"priv_esc":          35,
	"setuid_drop":       30,
	"sudo_misuse":       25,
	"capability_grant":  22,

	// Defense evasion
	"masquerade":        15,
	"timestomp":         18,
	"log_tamper":        25,
	"selfprotect_evade": 22,

	// Credential access
	"cred_access":       30,
	"shadow_read":       28,
	"ssh_key_read":      26,
	"token_read":        24,

	// Lateral movement
	"lateral_attempt":   25,
	"smb_login":         20,
	"ssh_login_attempt": 14,

	// Command and control
	"c2_beacon":         35,
	"cdn_cloaking":      28,
	"domain_fronting":   30,
	"c2_fallback":       18,

	// Exfiltration / impact
	"data_exfil":        40,
	"volume_breach":     32,
	"encryption_burst":  45,
	"data_destruction":  50,
}

// Score returns an integer 0-100 derived from the token bag.
// Duplicates contribute once. Score caps at 100 even if weights
// would exceed it — operators read "≥90" as "act now" regardless
// of how much further the bag would go.
func Score(tokens []Token) int {
	if len(tokens) == 0 {
		return 0
	}
	seen := map[Token]struct{}{}
	total := 0
	for _, t := range tokens {
		t = Token(strings.TrimSpace(string(t)))
		if t == "" {
			continue
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		total += Weight(t)
	}
	if total > 100 {
		total = 100
	}
	if total < 0 {
		total = 0
	}
	return total
}

// Severity bands the score into PASS / WARN / HIGH / CRITICAL.
// Caller can render these directly to operators.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarn     Severity = "warn"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Band maps an int score to a Severity. Thresholds are chosen so a
// single noisy token doesn't trip CRITICAL, but two clean
// execution+exfil tokens do.
func Band(score int) Severity {
	switch {
	case score >= 80:
		return SeverityCritical
	case score >= 50:
		return SeverityHigh
	case score >= 20:
		return SeverityWarn
	default:
		return SeverityInfo
	}
}

// Tracker keeps per-source token bags + scores. The incidentgraph
// engine calls Add(sourceID, token) as TTPs are recognised; the
// operator UI calls Snapshot to render a sorted leaderboard.
type Tracker struct {
	mu     sync.RWMutex
	bags   map[string]map[Token]struct{}
}

// NewTracker returns an empty Tracker.
func NewTracker() *Tracker {
	return &Tracker{bags: map[string]map[Token]struct{}{}}
}

// Add records a token for sourceID. Duplicates are no-ops.
func (t *Tracker) Add(sourceID string, tok Token) {
	if t == nil || sourceID == "" || tok == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	bag, ok := t.bags[sourceID]
	if !ok {
		bag = map[Token]struct{}{}
		t.bags[sourceID] = bag
	}
	bag[tok] = struct{}{}
}

// Score returns the current score for sourceID (0 if unknown).
func (t *Tracker) Score(sourceID string) int {
	if t == nil {
		return 0
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	bag := t.bags[sourceID]
	tokens := make([]Token, 0, len(bag))
	for tok := range bag {
		tokens = append(tokens, tok)
	}
	return Score(tokens)
}

// Tokens returns the sorted token list for sourceID. Sorted output
// makes test assertions and operator scans stable.
func (t *Tracker) Tokens(sourceID string) []Token {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	bag := t.bags[sourceID]
	out := make([]Token, 0, len(bag))
	for tok := range bag {
		out = append(out, tok)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Forget drops state for sourceID. Called when an incident closes.
func (t *Tracker) Forget(sourceID string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.bags, sourceID)
}

// SourceEntry is one row in Snapshot.
type SourceEntry struct {
	SourceID string
	Score    int
	Severity Severity
	Tokens   []Token
}

// Snapshot returns all tracked sources sorted score-descending.
// Empty bags are skipped.
func (t *Tracker) Snapshot() []SourceEntry {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]SourceEntry, 0, len(t.bags))
	for id, bag := range t.bags {
		if len(bag) == 0 {
			continue
		}
		toks := make([]Token, 0, len(bag))
		for tok := range bag {
			toks = append(toks, tok)
		}
		sort.Slice(toks, func(i, j int) bool { return toks[i] < toks[j] })
		s := Score(toks)
		out = append(out, SourceEntry{
			SourceID: id, Score: s, Severity: Band(s), Tokens: toks,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}
