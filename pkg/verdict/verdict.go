// Package verdict is xhelix's per-connection decision engine.
//
// Given an enriched connection (pid + exe + dst + port + sni + dns hint),
// Decide() runs a fixed ordered chain of layers and returns a Verdict
// with confidence, action, and a reason trace.
//
// The chain is deterministic and side-effect-free. Enforcement is a
// separate concern (pkg/enforce) — verdict only *thinks*; the caller
// chooses whether to act.
//
// Layer order (highest precedence first):
//   0. Policy match    — operator's declared deny / allow rules
//   1. Threat intel    — known-bad IP/ASN/domain
//   2. Telemetry       — known telemetry endpoint, evidence captured
//   3. Known-good      — curated legitimate-service corpus
//   4. Baseline match  — process's learned routine endpoints
//   5. Composite score — fan-out, novelty, port, ASN, time-of-day
//
// Each layer can be skipped under load via Engine.SkipLayers.
package verdict

import (
	"strings"
	"sync"
	"time"
)

// Action is the recommended outcome.
type Action string

const (
	ActionAllow  Action = "allow"
	ActionPrompt Action = "prompt"
	ActionDeny   Action = "deny"
)

// Confidence is 0..100. Below 25 = certainly safe, above 85 = certainly hostile.
type Confidence int

// Verdict is the engine's output. It is JSON-serialisable so the UI
// drill panel can render the full reason trace.
type Verdict struct {
	Action     Action     `json:"action"`
	Confidence Confidence `json:"confidence"`
	Layer      string     `json:"layer"`    // name of the layer that decided
	Reasons    []Reason   `json:"reasons"`  // ordered trace, oldest first
	AnalysedAt time.Time  `json:"analysed_at"`
	Level      int        `json:"level"`    // degradation level when this ran (1..5)
}

// Reason is one note from a layer. RuleID is opaque ("intel.spamhaus",
// "telemetry.vscode", etc.). Note is a one-line human string.
type Reason struct {
	Layer  string `json:"layer"`
	RuleID string `json:"rule_id,omitempty"`
	Note   string `json:"note"`
}

// Conn is the input shape. Caller fills as much as it has; verdict
// layers ignore zero values.
type Conn struct {
	PID      uint32
	Comm     string
	Exe      string
	ExeSHA   string
	UID      string
	DstIP    string
	DstPort  uint16
	DNSName  string
	SNI      string
	Proto    string
	Country  string // 2-letter ISO; empty if GeoIP unset
	ASN      uint32
	ASNName  string
}

// Layer is one decision step. Eval returns (decided, verdict-fragment).
// If decided==true, no further layers run; the engine wraps the
// fragment into a final Verdict and returns. If decided==false, the
// Reasons slice is appended to the trace and the chain continues.
type Layer interface {
	Name() string
	Eval(Conn) (decided bool, action Action, confidence Confidence, reasons []Reason)
}

// Engine composes layers. The zero value is unusable — use New().
type Engine struct {
	layers []Layer

	// SkipLayers is consulted before each layer runs. If the returned
	// set contains the layer's name, the layer is skipped — used by
	// the degradation ladder to drop work under load.
	SkipLayers func() map[string]struct{}

	// Level returns the current degradation level (1..5); recorded
	// in the Verdict for the UI to display.
	Level func() int

	now func() time.Time
	mu  sync.RWMutex
}

// New returns an engine seeded with the canonical layer chain in
// priority order.
func New(layers ...Layer) *Engine {
	return &Engine{layers: layers, now: time.Now}
}

// Decide runs the chain. Always returns a non-zero Verdict.
func (e *Engine) Decide(c Conn) Verdict {
	e.mu.RLock()
	layers := e.layers
	e.mu.RUnlock()

	var skip map[string]struct{}
	if e.SkipLayers != nil {
		skip = e.SkipLayers()
	}
	level := 1
	if e.Level != nil {
		level = e.Level()
	}

	trace := make([]Reason, 0, 4)
	for _, l := range layers {
		if _, ok := skip[l.Name()]; ok {
			continue
		}
		decided, action, conf, reasons := l.Eval(c)
		trace = append(trace, reasons...)
		if decided {
			return Verdict{
				Action: action, Confidence: conf, Layer: l.Name(),
				Reasons: trace, AnalysedAt: e.now(), Level: level,
			}
		}
	}
	// No layer terminated — default allow with low confidence and
	// the full trace.
	return Verdict{
		Action: ActionAllow, Confidence: 35, Layer: "default",
		Reasons: append(trace, Reason{Layer: "default", Note: "no layer matched; allowed by default"}),
		AnalysedAt: e.now(), Level: level,
	}
}

// Add inserts a layer at the end of the chain. Safe to call while
// Decide is running on other goroutines.
func (e *Engine) Add(l Layer) {
	e.mu.Lock()
	e.layers = append(e.layers, l)
	e.mu.Unlock()
}

// Pattern matching shared by knowngood / telemetry / policy layers.
// Patterns support a leading "*." wildcard ("*.googletagmanager.com")
// and an exact match. No regex — fast, predictable.
func MatchHost(pattern, host string) bool {
	if pattern == "" || host == "" {
		return false
	}
	host = strings.ToLower(host)
	pattern = strings.ToLower(pattern)
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
			return true
		}
		// also match the bare apex: "*.x.com" matches "x.com"
		if host == suffix[1:] {
			return true
		}
	}
	return false
}
