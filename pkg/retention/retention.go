// Package retention is the operator-facing privacy controller.
// Wraps `pkg/store/history.Retention` with two extra knobs:
//
//   - Per-table durations the operator picks (the history defaults
//     are sane but some operators want shorter — privacy — or
//     longer — incident response).
//   - Anonymous mode: nulls or hashes domain-bearing columns
//     before persist so the database carries process+IP+verdict
//     but not the queried hostname.
//
// Pure-Go. Wraps `pkg/store/history` rather than reaching into it,
// so unit tests don't need a real SQLite store.
package retention

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/store/history"
)

// AnonMode controls how qname-bearing columns are sanitised
// before persistence.
type AnonMode uint8

const (
	// AnonOff — store everything as observed. Default.
	AnonOff AnonMode = 0

	// AnonHash — replace qname with sha256(salt + qname)[:16].
	// Lets fleet analytics dedupe domains across hosts without
	// revealing the underlying name.
	AnonHash AnonMode = 1

	// AnonRedact — replace qname with empty string. Hard
	// privacy mode; the hub can't even correlate fleet visits.
	AnonRedact AnonMode = 2
)

// Policy is the operator's retention + anonymity choice.
type Policy struct {
	// Per-table durations. Zero on any field selects the
	// pkg/store/history default for that table.
	Flows      time.Duration
	DNS        time.Duration
	Activities time.Duration
	Processes  time.Duration
	Sessions   time.Duration

	// Anon controls hostname sanitisation.
	Anon AnonMode

	// AnonSalt is used by AnonHash. Operators must set this; if
	// empty, AnonHash falls back to "xhelix" (deterministic
	// across reboots).
	AnonSalt string
}

// Controller threads a Policy through every retention-affecting
// surface in the daemon.
type Controller struct {
	mu     sync.RWMutex
	policy Policy
}

// New returns a Controller with the given Policy.
func New(p Policy) *Controller {
	return &Controller{policy: p}
}

// Get returns the active policy (deep-copy safe).
func (c *Controller) Get() Policy {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.policy
}

// Set replaces the active policy. Callers re-trigger any
// affected actions (re-schedule the pruner, re-arm the
// sanitiser).
func (c *Controller) Set(p Policy) {
	c.mu.Lock()
	c.policy = p
	c.mu.Unlock()
}

// AsHistoryRetention converts the policy into the shape
// `pkg/store/history.Retention` expects. Zero-valued fields are
// replaced with the package's defaults.
func (c *Controller) AsHistoryRetention() history.Retention {
	p := c.Get()
	d := history.DefaultRetention()
	out := history.Retention{
		Flows:      p.Flows,
		DNS:        p.DNS,
		Activities: p.Activities,
		Processes:  p.Processes,
		Sessions:   p.Sessions,
	}
	if out.Flows <= 0 {
		out.Flows = d.Flows
	}
	if out.DNS <= 0 {
		out.DNS = d.DNS
	}
	if out.Activities <= 0 {
		out.Activities = d.Activities
	}
	if out.Processes <= 0 {
		out.Processes = d.Processes
	}
	if out.Sessions <= 0 {
		out.Sessions = d.Sessions
	}
	return out
}

// SanitiseQName applies the configured AnonMode to a qname before
// it's persisted. Caller is responsible for routing every write
// through this — the controller has no hook into the store on
// its own.
func (c *Controller) SanitiseQName(qname string) string {
	p := c.Get()
	switch p.Anon {
	case AnonRedact:
		return ""
	case AnonHash:
		if qname == "" {
			return ""
		}
		salt := p.AnonSalt
		if salt == "" {
			salt = "xhelix"
		}
		h := sha256.New()
		h.Write([]byte(salt))
		h.Write([]byte{0})
		h.Write([]byte(strings.ToLower(strings.TrimSuffix(qname, "."))))
		return hex.EncodeToString(h.Sum(nil)[:16])
	default:
		return qname
	}
}

// SanitiseAnswers applies the same transformation to a slice of
// resolved IPs / domains. IPs are passed through; mixed-shape
// slices have hostnames sanitised.
func (c *Controller) SanitiseAnswers(answers []string) []string {
	p := c.Get()
	if p.Anon == AnonOff {
		return answers
	}
	out := make([]string, len(answers))
	for i, a := range answers {
		if looksLikeIP(a) {
			out[i] = a
		} else {
			out[i] = c.SanitiseQName(a)
		}
	}
	return out
}

// IsAnonymous reports whether the policy is in any anonymisation
// mode. UI uses this to badge the journal "anonymous mode" so
// operators don't think the lack of domain detail is a bug.
func (c *Controller) IsAnonymous() bool {
	return c.Get().Anon != AnonOff
}

// looksLikeIP is a cheap dotted-quad / colon detector — good
// enough for the answers slice (real-world answer lists are
// always IPs or hostnames, never mixed with arbitrary text).
func looksLikeIP(s string) bool {
	if s == "" {
		return false
	}
	isV6 := strings.ContainsRune(s, ':')
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			continue
		case r == '.':
			continue
		case r == ':' && isV6:
			continue
		case (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') && isV6:
			continue
		default:
			return false
		}
	}
	return true
}
