package xhubfleet

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xhelix/xhelix/pkg/brp"
	parser "github.com/xhelix/xhelix/pkg/brp/parser"
)

// CandidateGates are the deterministic gates a candidate BRP must clear
// before it can be presented to the human signer. All gates exist to
// prevent baseline-poisoning from one (or a small subset of) hosts.
type CandidateGates struct {
	// MinHosts is the absolute minimum number of trusted hosts in the
	// cohort that must agree on a behavior for it to be a candidate.
	MinHosts int
	// QuorumFraction is the fraction of cohort hosts that must show
	// the behavior. 0.8 = at least 80% of trusted cohort hosts.
	QuorumFraction float64
	// MinObservedDays is the minimum age of contributing hosts (filtered
	// upstream via TrustRanker; this field is informational + audit).
	MinObservedDays int
	// RequireSamePackageOrigin gates on PackageOrigin field of cohort —
	// true means "all contributing hosts must come from the same
	// package origin" (apt vs source builds shouldn't mix).
	RequireSamePackageOrigin bool
}

// DefaultCandidateGates returns the production defaults.
func DefaultCandidateGates() CandidateGates {
	return CandidateGates{
		MinHosts:                 5,
		QuorumFraction:           0.8,
		MinObservedDays:          7,
		RequireSamePackageOrigin: true,
	}
}

// Candidate is a proposed BRP Profile diff for one (cohort, binary)
// pair. Operator reviews this before signing.
type Candidate struct {
	Cohort       CohortKey      `json:"cohort"`
	Binary       string         `json:"binary"`
	HostsAgreed  int            `json:"hosts_agreed"` // hosts contributing this behavior
	TotalHosts   int            `json:"total_hosts"`  // total hosts in cohort
	QuorumMet    bool           `json:"quorum_met"`
	GeneratedAt  time.Time      `json:"generated_at"`
	Profile      brp.Profile    `json:"profile"`  // proposed Profile
	Evidence     []CandidateRow `json:"evidence"` // per-feature evidence rows
	GateFailures []string       `json:"gate_failures,omitempty"`
}

// CandidateRow describes one feature dimension in the candidate.
type CandidateRow struct {
	Class       string  `json:"class"` // "child" / "endpoint" / "file_write" / "listen_port" / "binary_sha"
	Value       string  `json:"value"`
	HostsAgreed int     `json:"hosts_agreed"`
	Fraction    float64 `json:"fraction"`
}

// GenerateCandidates walks the rarity index and emits one Candidate per
// (cohort, binary) tuple where the gates pass. Use TrustRanker.CanTeach
// upstream to filter hosts; this function trusts the index it's given.
func GenerateCandidates(r *RarityIndex, gates CandidateGates) []Candidate {
	if r == nil {
		return nil
	}
	var out []Candidate
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, c := range r.cohorts {
		// Union of binary keys across feature classes — emit one candidate
		// per (cohort, binary) regardless of which dimension surfaced it.
		seen := map[string]struct{}{}
		for _, idx := range []map[string]map[string]int{
			c.BinaryChildren, c.BinaryEndpoints, c.BinaryFileWrites,
			c.BinarySHAs, c.BinaryListenPorts,
		} {
			for b := range idx {
				if _, dup := seen[b]; dup {
					continue
				}
				seen[b] = struct{}{}
				if cand, ok := buildCandidate(c, b, gates); ok {
					out = append(out, cand)
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Cohort.String() != out[j].Cohort.String() {
			return out[i].Cohort.String() < out[j].Cohort.String()
		}
		return out[i].Binary < out[j].Binary
	})
	return out
}

// buildCandidate constructs a Candidate for one (cohort, binary). Returns
// ok=false if gates fail and no evidence was assembled.
func buildCandidate(c *Cohort, binary string, gates CandidateGates) (Candidate, bool) {
	hosts := c.HostCount()
	if hosts < gates.MinHosts {
		return Candidate{}, false
	}
	threshold := int(float64(hosts) * gates.QuorumFraction)
	if threshold < 1 {
		threshold = 1
	}

	pick := func(class string, idx map[string]map[string]int) []CandidateRow {
		m := idx[binary]
		if m == nil {
			return nil
		}
		rows := make([]CandidateRow, 0, len(m))
		for v, count := range m {
			if count >= threshold {
				rows = append(rows, CandidateRow{
					Class:       class,
					Value:       v,
					HostsAgreed: count,
					Fraction:    float64(count) / float64(hosts),
				})
			}
		}
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].Value < rows[j].Value })
		return rows
	}

	var rows []CandidateRow
	rows = append(rows, pick("child", c.BinaryChildren)...)
	rows = append(rows, pick("endpoint", c.BinaryEndpoints)...)
	rows = append(rows, pick("file_write", c.BinaryFileWrites)...)
	rows = append(rows, pick("listen_port", c.BinaryListenPorts)...)
	// SensitivePaths intentionally not promoted — they belong on the
	// never-learnable list, not on a candidate envelope.
	// BinarySHAs aren't a BRP envelope dimension, but we surface them
	// in evidence for the human reviewer.
	rows = append(rows, pick("binary_sha", c.BinarySHAs)...)

	if len(rows) == 0 {
		return Candidate{}, false
	}

	// Build proposed brp.Profile from quorum rows.
	behavior := parser.ConfigDerivedBehavior{}
	portSet := map[int]struct{}{}
	for _, r := range rows {
		switch r.Class {
		case "child":
			if r.Value != "" {
				behavior.ExecAllowed = appendUnique(behavior.ExecAllowed, r.Value)
			}
		case "endpoint":
			// r.Value is "cidr:port" or similar — map to UpstreamHosts.
			if host := endpointHost(r.Value); host != "" {
				behavior.UpstreamHosts = appendUnique(behavior.UpstreamHosts, host)
			}
		case "file_write":
			if root := writeRoot(r.Value); root != "" {
				behavior.WriteRoots = appendUnique(behavior.WriteRoots, root)
			}
		case "listen_port":
			// "tcp:443" -> 443
			if port := portFromKey(r.Value); port > 0 {
				portSet[port] = struct{}{}
			}
		}
	}
	if len(portSet) > 0 {
		ports := make([]int, 0, len(portSet))
		for p := range portSet {
			ports = append(ports, p)
		}
		sort.Ints(ports)
		behavior.ListenPorts = ports
	}
	sort.Strings(behavior.ExecAllowed)
	sort.Strings(behavior.UpstreamHosts)
	sort.Strings(behavior.WriteRoots)

	profile := brp.Profile{
		SchemaVersion: brp.SchemaVersion,
		ProfileID:     fmt.Sprintf("brp-%s-%s-cohort-%s", sanitize(binary), sanitizeOrEmpty(c.Key.VersionFamily), sanitize(c.Key.String())),
		Confidence:    brp.ConfidenceStableFallback, // candidates default to stable_fallback until operator promotes
		SampleCount:   threshold,
		FleetCount:    hosts,
		VersionRange:  c.Key.VersionFamily,
		Key: parser.ProfileKey{
			App:           binary,
			VersionFamily: c.Key.VersionFamily,
			OSFamily:      c.Key.OSFamily,
			PackageOrigin: c.Key.PackageOrigin,
			Role:          c.Key.AppRole,
		},
		Behavior: behavior,
	}

	cand := Candidate{
		Cohort:      c.Key,
		Binary:      binary,
		HostsAgreed: threshold,
		TotalHosts:  hosts,
		QuorumMet:   true,
		GeneratedAt: time.Now().UTC(),
		Profile:     profile,
		Evidence:    rows,
	}

	if gates.RequireSamePackageOrigin && c.Key.PackageOrigin == "" {
		cand.GateFailures = append(cand.GateFailures, "package_origin empty — refusing to candidate")
		cand.QuorumMet = false
	}

	if len(cand.GateFailures) > 0 {
		return cand, false
	}
	return cand, true
}

// ValidateForSigning runs our gating rules on a candidate before the
// operator signs it. This is intentionally lighter than brp.Profile.Validate
// — Sign() auto-populates SigningEpoch and re-runs Profile.Validate. We
// only check the operator-facing invariants here.
func ValidateForSigning(c Candidate) error {
	if !c.QuorumMet {
		return errors.New("candidate quorum not met")
	}
	if c.Profile.ProfileID == "" {
		return errors.New("profile_id empty")
	}
	if c.Profile.Key.App == "" {
		return errors.New("profile.key.app empty")
	}
	return nil
}

// --- helpers ---

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func endpointHost(key string) string {
	// "cidr:port" → "cidr"
	if i := strings.LastIndex(key, ":"); i >= 0 {
		return key[:i]
	}
	return key
}

func writeRoot(path string) string {
	// Use parent directory as the write root.
	if i := strings.LastIndex(path, "/"); i > 0 {
		return path[:i]
	}
	return path
}

func portFromKey(k string) int {
	// "tcp:443" or "udp:53"
	if i := strings.Index(k, ":"); i >= 0 {
		n, _ := strconv.Atoi(k[i+1:])
		return n
	}
	return 0
}

func sanitize(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' {
			out = append(out, c)
		} else {
			out = append(out, '-')
		}
	}
	return string(out)
}

func sanitizeOrEmpty(s string) string {
	if s == "" {
		return "unknown"
	}
	return sanitize(s)
}
