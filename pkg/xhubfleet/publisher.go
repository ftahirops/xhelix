package xhubfleet

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/brp"
)

// Publisher persists signed BRP profiles to a local directory tree and
// exposes them via the hub HTTP API. The agent-side fetcher pulls
// /api/brp/feed and applies the signed profiles. The directory is the
// canonical store; the HTTP feed is a thin convenience.
type Publisher struct {
	mu   sync.RWMutex
	dir  string
	feed map[string]brp.SignedProfile // profile_id → signed
}

// NewPublisher opens the publish dir (creates it if needed) and loads
// any existing signed profiles back into the in-memory feed.
func NewPublisher(dir string) (*Publisher, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("publisher mkdir: %w", err)
	}
	p := &Publisher{
		dir:  dir,
		feed: map[string]brp.SignedProfile{},
	}
	if err := p.loadDir(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Publisher) loadDir() error {
	entries, err := os.ReadDir(p.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(p.dir, e.Name()))
		if err != nil {
			return err
		}
		var sp brp.SignedProfile
		if err := json.Unmarshal(body, &sp); err != nil {
			return fmt.Errorf("load %s: %w", e.Name(), err)
		}
		p.feed[sp.Profile.ProfileID] = sp
	}
	return nil
}

// Publish signs the candidate with priv and writes it to the feed.
// The signer parameter identifies the signing entity (operator key id).
func (p *Publisher) Publish(cand Candidate, signer string, priv ed25519.PrivateKey) (brp.SignedProfile, error) {
	if err := ValidateForSigning(cand); err != nil {
		return brp.SignedProfile{}, err
	}
	sp, err := brp.Sign(cand.Profile, signer, priv)
	if err != nil {
		return brp.SignedProfile{}, err
	}
	if err := p.PutSigned(sp); err != nil {
		return brp.SignedProfile{}, err
	}
	return sp, nil
}

// PutSigned stores an already-signed profile to disk and registers it
// in the feed. Used by the /api/fleet/publish endpoint where the CLI
// has done the signing locally with the operator key.
func (p *Publisher) PutSigned(sp brp.SignedProfile) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	body, err := json.MarshalIndent(sp, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(p.dir, sanitize(sp.Profile.ProfileID)+".json")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return err
	}
	p.feed[sp.Profile.ProfileID] = sp
	return nil
}

// Feed returns all currently-published signed profiles, newest first.
func (p *Publisher) Feed() []brp.SignedProfile {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]brp.SignedProfile, 0, len(p.feed))
	for _, sp := range p.feed {
		out = append(out, sp)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Profile.SigningEpoch > out[j].Profile.SigningEpoch
	})
	return out
}

// LastUpdated returns the most-recent signing epoch in the feed.
func (p *Publisher) LastUpdated() time.Time {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var latest int64
	for _, sp := range p.feed {
		if sp.Profile.SigningEpoch > latest {
			latest = sp.Profile.SigningEpoch
		}
	}
	if latest == 0 {
		return time.Time{}
	}
	return time.Unix(0, latest).UTC()
}

// Dir returns the on-disk directory the publisher writes to. Exposed
// for diagnostics; callers must not write into it directly.
func (p *Publisher) Dir() string { return p.dir }
