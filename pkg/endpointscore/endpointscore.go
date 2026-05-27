// Package endpointscore is the T10 endpoint-level quick-scorer.
//
// Where pkg/sourcescore measures one source anchor's TTP bag and
// pkg/takeover scores one lineage's signal chain, endpointscore
// answers the broader operator question:
//
//   "Across every active source on THIS host right now, how close
//    are we to a recognised attack chain — and which one?"
//
// It evaluates five canonical chains in parallel (per the T10 spec)
// against the union of TTP tokens currently active on the host:
//
//   1. data_exfil       — staging + outbound burst + cred read
//   2. ransomware       — discovery + mass write + encryption burst
//   3. c2_lateral       — c2 beacon + cred access + lateral attempt
//   4. persistence      — exec + persistence + selfprotect_evade
//   5. cred_theft       — cred access + token read + outbound
//
// Each chain has REQUIRED tokens (all must appear) and OPTIONAL
// tokens (each contributes a small bonus). Chains return a 0-100
// score; the endpoint score is the MAXIMUM across chains so a single
// high-confidence chain raises the alarm even when others are quiet.
//
// "Quick" means O(chains × tokens) per evaluation. Default tick is
// every 30s in the daemon; cheap enough to run on the hot path of
// a TTP-tag write if needed.
//
// Honest non-promise: this is a heuristic scoring layer, not a
// detection by itself. Containment decisions still consult the
// verifier + hard-deny invariants. The endpoint score is for
// operator triage ranking and dashboard rollups.
package endpointscore

import (
	"sort"
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/sourcescore"
)

// Chain is one named attack-chain template.
type Chain struct {
	ID       string
	Desc     string
	Required []sourcescore.Token
	Optional []sourcescore.Token
	// MaxBase is the score returned when all Required tokens fire
	// and no Optional ones. Caps at 100.
	MaxBase int
	// OptionalBonus is added per Optional token present.
	OptionalBonus int
}

// DefaultChains returns the five T10 canonical chains. Operators
// override via WithChains() if their environment needs additional
// templates; the defaults are intentionally narrow and high-signal.
func DefaultChains() []Chain {
	return []Chain{
		{
			ID:   "data_exfil",
			Desc: "Stager spawned + outbound volume burst + credential read",
			Required: []sourcescore.Token{
				"shell_spawn", "volume_breach", "cred_access",
			},
			Optional:      []sourcescore.Token{"c2_beacon", "cdn_cloaking"},
			MaxBase:       85,
			OptionalBonus: 7,
		},
		{
			ID:   "ransomware",
			Desc: "Discovery + mass write + encryption burst",
			Required: []sourcescore.Token{
				"asset_discovery", "encryption_burst",
			},
			Optional:      []sourcescore.Token{"data_destruction", "shadow_read"},
			MaxBase:       90,
			OptionalBonus: 5,
		},
		{
			ID:   "c2_lateral",
			Desc: "C2 beacon + credential read + lateral movement attempt",
			Required: []sourcescore.Token{
				"c2_beacon", "cred_access", "lateral_attempt",
			},
			Optional:      []sourcescore.Token{"domain_fronting", "ssh_login_attempt"},
			MaxBase:       80,
			OptionalBonus: 8,
		},
		{
			ID:   "persistence_install",
			Desc: "Foothold + persistence install + defense evasion",
			Required: []sourcescore.Token{
				"shell_spawn", "persistence",
			},
			Optional:      []sourcescore.Token{"selfprotect_evade", "log_tamper", "crontab_install"},
			MaxBase:       65,
			OptionalBonus: 8,
		},
		{
			ID:   "cred_theft",
			Desc: "Credential read + token grab + outbound to attacker",
			Required: []sourcescore.Token{
				"cred_access", "token_read",
			},
			Optional:      []sourcescore.Token{"shadow_read", "ssh_key_read", "data_exfil"},
			MaxBase:       70,
			OptionalBonus: 8,
		},
	}
}

// ChainMatch is one chain's evaluation against a token set.
type ChainMatch struct {
	ChainID  string
	Score    int
	Matched  bool
	Missing  []sourcescore.Token // required tokens absent
	Hit      []sourcescore.Token // tokens that contributed
}

// EndpointScore is the host-level rollup.
type EndpointScore struct {
	Score    int          // max across all chain scores
	Chain    string       // chain ID that produced Score ("" if none)
	Severity sourcescore.Severity
	Matches  []ChainMatch // per-chain detail, sorted score-desc
	At       time.Time
}

// Score runs every chain against the union of tokens and returns
// the endpoint rollup. tokens may contain duplicates; only the
// distinct set matters.
func Score(chains []Chain, tokens []sourcescore.Token, at time.Time) EndpointScore {
	have := map[sourcescore.Token]struct{}{}
	for _, t := range tokens {
		if t != "" {
			have[t] = struct{}{}
		}
	}
	out := EndpointScore{At: at}
	matches := make([]ChainMatch, 0, len(chains))
	for _, c := range chains {
		m := evalChain(c, have)
		matches = append(matches, m)
		if m.Score > out.Score {
			out.Score = m.Score
			out.Chain = c.ID
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].Score > matches[j].Score })
	out.Matches = matches
	out.Severity = sourcescore.Band(out.Score)
	return out
}

func evalChain(c Chain, have map[sourcescore.Token]struct{}) ChainMatch {
	m := ChainMatch{ChainID: c.ID}
	allReq := true
	for _, r := range c.Required {
		if _, ok := have[r]; ok {
			m.Hit = append(m.Hit, r)
		} else {
			m.Missing = append(m.Missing, r)
			allReq = false
		}
	}
	if !allReq {
		m.Matched = false
		// Partial-match credit so the operator sees a chain forming.
		// 30% of MaxBase if at least one Required token landed.
		if len(m.Hit) > 0 {
			m.Score = c.MaxBase * 30 / 100
		}
		return m
	}
	m.Matched = true
	m.Score = c.MaxBase
	for _, opt := range c.Optional {
		if _, ok := have[opt]; ok {
			m.Hit = append(m.Hit, opt)
			m.Score += c.OptionalBonus
		}
	}
	if m.Score > 100 {
		m.Score = 100
	}
	return m
}

// Engine wraps a Tracker (per-source token bags) with a chain set
// and serves periodic / on-demand endpoint rollups. Goroutine-safe.
type Engine struct {
	mu      sync.RWMutex
	chains  []Chain
	tracker *sourcescore.Tracker
}

// NewEngine returns an endpointscore.Engine reading from tracker.
// chains == nil uses DefaultChains.
func NewEngine(tracker *sourcescore.Tracker, chains []Chain) *Engine {
	if chains == nil {
		chains = DefaultChains()
	}
	return &Engine{chains: chains, tracker: tracker}
}

// Evaluate produces a fresh EndpointScore from the union of every
// source's tokens currently in the tracker.
func (e *Engine) Evaluate(at time.Time) EndpointScore {
	if e == nil || e.tracker == nil {
		return EndpointScore{At: at}
	}
	e.mu.RLock()
	chains := e.chains
	e.mu.RUnlock()
	snap := e.tracker.Snapshot()
	seen := map[sourcescore.Token]struct{}{}
	for _, s := range snap {
		for _, t := range s.Tokens {
			seen[t] = struct{}{}
		}
	}
	toks := make([]sourcescore.Token, 0, len(seen))
	for t := range seen {
		toks = append(toks, t)
	}
	return Score(chains, toks, at)
}

// SetChains swaps the chain set at runtime.
func (e *Engine) SetChains(chains []Chain) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.chains = chains
}
