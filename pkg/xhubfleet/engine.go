package xhubfleet

import (
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/baselinehub"
)

// Engine is the top-level fleet engine instance the hub instantiates.
// One per xhub process. Goroutine-safe.
type Engine struct {
	mu         sync.RWMutex
	rarity     *RarityIndex
	trust      *TrustRanker
	weights    Weights
	gates      CandidateGates
	publisher  *Publisher
	candidates []Candidate
	lastBuild  time.Time
}

// EngineConfig is the constructor input.
type EngineConfig struct {
	Weights      Weights
	Gates        CandidateGates
	TrustPolicy  TrustPolicy
	PublisherDir string
}

// NewEngine wires the cohort/trust/publisher subsystems together.
func NewEngine(cfg EngineConfig) (*Engine, error) {
	pub, err := NewPublisher(cfg.PublisherDir)
	if err != nil {
		return nil, err
	}
	return &Engine{
		rarity:    NewRarityIndex(),
		trust:     NewTrustRanker(cfg.TrustPolicy),
		weights:   cfg.Weights,
		gates:     cfg.Gates,
		publisher: pub,
	}, nil
}

// Ingest registers an Upload with the trust+rarity systems.
// Only trusted hosts contribute to the rarity index.
func (e *Engine) Ingest(u baselinehub.Upload, now time.Time) {
	e.trust.See(u.HostTag, now)
	e.trust.Evaluate(u.HostTag, now)
	if e.trust.CanTeach(u.HostTag) {
		e.rarity.Ingest(u)
	}
}

// RebuildCandidates walks the current rarity index and refreshes the
// candidate list. Call this periodically (e.g. every 15 minutes) or
// on operator demand.
func (e *Engine) RebuildCandidates() []Candidate {
	cands := GenerateCandidates(e.rarity, e.gates)
	e.mu.Lock()
	e.candidates = cands
	e.lastBuild = time.Now().UTC()
	e.mu.Unlock()
	return cands
}

// Candidates returns the last-built candidate list. Call RebuildCandidates
// first to refresh it.
func (e *Engine) Candidates() []Candidate {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Candidate, len(e.candidates))
	copy(out, e.candidates)
	return out
}

// LastBuild reports when the candidate list was last rebuilt.
func (e *Engine) LastBuild() time.Time {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.lastBuild
}

// Publisher exposes the signed-profile publisher.
func (e *Engine) Publisher() *Publisher { return e.publisher }

// Trust exposes the trust ranker.
func (e *Engine) Trust() *TrustRanker { return e.trust }

// Rarity exposes the rarity index (mostly for tests).
func (e *Engine) Rarity() *RarityIndex { return e.rarity }
