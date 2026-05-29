// Workflow turns observed ledger flows into a draft Policy for review.
//
//   observed flows from EgressLedger
//       → ProposalRule (one per distinct (binary, dest_cidr, port, sni))
//       → Proposal     (one per binary, with mode_suggestion)
//       → Sign (operator action)
//       → Store.Save (file lands on disk under /etc/xhelix/policies/)
//       → daemon reloads, Engine.Decide starts enforcing
//
// This file is Week 4 of the Egress Option A roadmap. Heuristics here
// are intentionally conservative — we only suggest deny_default when
// the observation window is dense enough to give operators a useful
// baseline; otherwise we suggest observe so they don't get locked out
// of their own infra by a half-baked policy.
package egresspolicy

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sort"
	"strings"
	"time"
)

// LedgerSource is what the workflow consumes — a minimal surface so we
// don't pull pkg/egressledger as a dep (would create import cycle in
// some configurations; clean interface is cheaper).
type LedgerSource interface {
	QueryBinary(binary string, start, end time.Time) []LedgerFlow
}

// LedgerFlow is the projection we need from one egressledger.FlowRecord.
type LedgerFlow struct {
	Binary    string
	DestCIDR  string
	DestPort  uint16
	Protocol  string
	SNI       string
	DNSName   string
	DestClass string
	BytesOut  uint64
	BytesIn   uint64
	Connects  uint64
	FirstSeen time.Time
	LastSeen  time.Time
}

// ProposalRule is one suggested allow entry derived from observed traffic.
type ProposalRule struct {
	DestCIDR     string    `yaml:"dest_cidr,omitempty"   json:"dest_cidr,omitempty"`
	DestPort     uint16    `yaml:"dest_port,omitempty"   json:"dest_port,omitempty"`
	Protocol     string    `yaml:"protocol,omitempty"    json:"protocol,omitempty"`
	SNI          string    `yaml:"sni,omitempty"         json:"sni,omitempty"`
	DNSName      string    `yaml:"dns_name,omitempty"    json:"dns_name,omitempty"`
	DestClass    string    `yaml:"dest_class,omitempty"  json:"dest_class,omitempty"`
	Observations uint64    `yaml:"observations"          json:"observations"`
	BytesOut     uint64    `yaml:"bytes_out"             json:"bytes_out"`
	LastSeen     time.Time `yaml:"last_seen"             json:"last_seen"`
	Reason       string    `yaml:"reason,omitempty"      json:"reason,omitempty"`
	// Confidence is a 0-100 hint for the operator. Combines volume +
	// stability + dest class. Calibrated by attachConfidence.
	Confidence int `yaml:"confidence" json:"confidence"`
}

// Proposal is the per-binary draft policy for operator review.
type Proposal struct {
	Binary        string         `yaml:"binary"         json:"binary"`
	ObservedDays  int            `yaml:"observed_days"  json:"observed_days"`
	TotalConnects uint64         `yaml:"total_connects" json:"total_connects"`
	TotalBytesOut uint64         `yaml:"total_bytes_out" json:"total_bytes_out"`
	UniqueDests   int            `yaml:"unique_dests"   json:"unique_dests"`
	UniqueClasses []string       `yaml:"unique_classes,omitempty" json:"unique_classes,omitempty"`
	SuggestedMode Mode           `yaml:"suggested_mode" json:"suggested_mode"`
	Allow         []ProposalRule `yaml:"allow,omitempty" json:"allow,omitempty"`
	Notes         []string       `yaml:"notes,omitempty" json:"notes,omitempty"`
}

// maxAllowRules is the upper bound at which we still suggest
// deny_default. Above this the rule set becomes operator noise and we
// fall back to observe.
const maxAllowRules = 30

// wellKnownInfraClasses is the set of dest_class tokens we treat as
// trustworthy enough to bump rule confidence. Hand-picked from the
// dest classifier vocabulary; intentionally not exhaustive.
var wellKnownInfraClasses = map[string]bool{
	"cloudflare": true,
	"google":     true,
	"aws":        true,
	"azure":      true,
	"akamai":     true,
	"fastly":     true,
	"cdn":        true,
}

// ProposeFromLedger builds Proposals for ALL binaries with observed
// traffic in [start, end]. If binaries is empty, the caller must
// provide names — this function does not enumerate every binary the
// ledger knows about (that would require a different LedgerSource
// surface). Callers that want "every binary" should pass the list
// they got from a prior aggregate.
func ProposeFromLedger(ctx context.Context, src LedgerSource, binaries []string, start, end time.Time) []Proposal {
	if src == nil {
		return nil
	}
	if start.IsZero() {
		start = time.Now().Add(-14 * 24 * time.Hour)
	}
	if end.IsZero() {
		end = time.Now()
	}
	out := make([]Proposal, 0, len(binaries))
	for _, b := range binaries {
		if ctx != nil {
			select {
			case <-ctx.Done():
				return out
			default:
			}
		}
		flows := src.QueryBinary(b, start, end)
		out = append(out, proposeOne(b, flows, start, end))
	}
	return out
}

// proposeOne is the per-binary core of ProposeFromLedger. Split out
// for direct test access.
func proposeOne(binary string, flows []LedgerFlow, start, end time.Time) Proposal {
	p := Proposal{
		Binary:        binary,
		SuggestedMode: ModeObserve,
	}
	if len(flows) == 0 {
		p.Notes = append(p.Notes, "no observed flows in window — suggest observe to collect baseline")
		return p
	}
	// Aggregate distinct (dest_cidr, port, protocol, sni, dns_name) keys.
	type ruleKey struct {
		DestCIDR string
		DestPort uint16
		Protocol string
		SNI      string
		DNSName  string
	}
	type ruleAgg struct {
		key       ruleKey
		destClass string
		connects  uint64
		bytesOut  uint64
		firstSeen time.Time
		lastSeen  time.Time
		// days set: stringified YYYY-MM-DD for cheap span counting.
		days map[string]struct{}
	}
	agg := map[ruleKey]*ruleAgg{}
	classes := map[string]struct{}{}
	for _, f := range flows {
		k := ruleKey{
			DestCIDR: f.DestCIDR,
			DestPort: f.DestPort,
			Protocol: f.Protocol,
			SNI:      f.SNI,
			DNSName:  f.DNSName,
		}
		a := agg[k]
		if a == nil {
			a = &ruleAgg{key: k, destClass: f.DestClass, firstSeen: f.FirstSeen, lastSeen: f.LastSeen, days: map[string]struct{}{}}
			agg[k] = a
		}
		a.connects += f.Connects
		a.bytesOut += f.BytesOut
		if !f.FirstSeen.IsZero() && (a.firstSeen.IsZero() || f.FirstSeen.Before(a.firstSeen)) {
			a.firstSeen = f.FirstSeen
		}
		if f.LastSeen.After(a.lastSeen) {
			a.lastSeen = f.LastSeen
		}
		// Span tracking: each flow bucket usually corresponds to one
		// hour, so use LastSeen's date as the day-of-activity stamp.
		// FirstSeen may sit in a different day for the very first
		// bucket; add both when they differ.
		if !f.LastSeen.IsZero() {
			a.days[f.LastSeen.UTC().Format("2006-01-02")] = struct{}{}
		}
		if !f.FirstSeen.IsZero() {
			a.days[f.FirstSeen.UTC().Format("2006-01-02")] = struct{}{}
		}
		if f.DestClass != "" {
			classes[f.DestClass] = struct{}{}
			if a.destClass == "" {
				a.destClass = f.DestClass
			}
		}
		p.TotalConnects += f.Connects
		p.TotalBytesOut += f.BytesOut
	}

	rules := make([]ProposalRule, 0, len(agg))
	for _, a := range agg {
		r := ProposalRule{
			DestCIDR:     a.key.DestCIDR,
			DestPort:     a.key.DestPort,
			Protocol:     a.key.Protocol,
			SNI:          a.key.SNI,
			DNSName:      a.key.DNSName,
			DestClass:    a.destClass,
			Observations: a.connects,
			BytesOut:     a.bytesOut,
			LastSeen:     a.lastSeen,
		}
		spanDays := len(a.days)
		attachConfidence(&r, spanDays)
		switch {
		case a.connects > 100 && spanDays >= 3:
			r.Reason = fmt.Sprintf("observed %d connects across %d days", a.connects, spanDays)
		case a.connects > 10 && spanDays >= 1:
			r.Reason = fmt.Sprintf("observed %d connects across %d day(s)", a.connects, spanDays)
		default:
			r.Reason = fmt.Sprintf("sparse: %d connect(s) in %d day(s) — review", a.connects, spanDays)
		}
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Confidence != rules[j].Confidence {
			return rules[i].Confidence > rules[j].Confidence
		}
		if rules[i].Observations != rules[j].Observations {
			return rules[i].Observations > rules[j].Observations
		}
		return rules[i].DestCIDR < rules[j].DestCIDR
	})
	p.Allow = rules
	p.UniqueDests = len(rules)
	p.UniqueClasses = sortedKeys(classes)

	// ObservedDays — span between earliest FirstSeen and latest LastSeen.
	var minFirst, maxLast time.Time
	for _, a := range agg {
		if !a.firstSeen.IsZero() && (minFirst.IsZero() || a.firstSeen.Before(minFirst)) {
			minFirst = a.firstSeen
		}
		if a.lastSeen.After(maxLast) {
			maxLast = a.lastSeen
		}
	}
	if !minFirst.IsZero() && !maxLast.IsZero() {
		d := maxLast.Sub(minFirst)
		p.ObservedDays = int(d/(24*time.Hour)) + 1
	}

	// Mode suggestion.
	switch {
	case p.TotalConnects == 0:
		p.SuggestedMode = ModeObserve
		p.Notes = append(p.Notes, "no connects observed — keep observing")
	case len(rules) <= maxAllowRules:
		p.SuggestedMode = ModeDenyDefault
		p.Notes = append(p.Notes, fmt.Sprintf("%d distinct destinations — tight enough for deny_default", len(rules)))
	default:
		p.SuggestedMode = ModeObserve
		p.Notes = append(p.Notes, fmt.Sprintf("%d distinct destinations — too noisy to lock down; keep observing", len(rules)))
	}
	// Window context.
	if !start.IsZero() && !end.IsZero() {
		p.Notes = append(p.Notes, fmt.Sprintf("window: %s → %s", start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339)))
	}
	return p
}

// attachConfidence assigns a 0-100 confidence score based on observed
// volume + temporal span + dest class. Heuristic, not statistical —
// helps operators triage which rules to keep vs. drop.
func attachConfidence(r *ProposalRule, spanDays int) {
	switch {
	case r.Observations > 100 && spanDays >= 3:
		r.Confidence = 80
	case r.Observations > 10 && spanDays >= 1:
		r.Confidence = 60
	case r.Observations >= 1:
		r.Confidence = 30
	default:
		r.Confidence = 0
	}
	if wellKnownInfraClasses[strings.ToLower(r.DestClass)] {
		r.Confidence += 10
	}
	// "raw" / unclassified destinations cap at 30 — unknown peers
	// deserve operator review regardless of volume.
	if strings.EqualFold(r.DestClass, "raw") && r.Confidence > 30 {
		r.Confidence = 30
	}
	if r.Confidence > 100 {
		r.Confidence = 100
	}
}

// ToPolicy converts an approved Proposal into a Policy ready for Sign.
// Operator may have edited the Proposal in place before calling this.
// The returned Policy is NOT signed.
func (p Proposal) ToPolicy() Policy {
	allow := make([]Rule, 0, len(p.Allow))
	for _, pr := range p.Allow {
		r := Rule{
			DestCIDR:  pr.DestCIDR,
			DestClass: pr.DestClass,
			SNI:       pr.SNI,
			DNSName:   pr.DNSName,
			Comment:   pr.Reason,
		}
		if pr.DestPort != 0 {
			r.Ports = []uint16{pr.DestPort}
		}
		if pr.Protocol != "" {
			r.Protocols = []string{pr.Protocol}
		}
		allow = append(allow, r)
	}
	mode := p.SuggestedMode
	if mode == "" {
		mode = ModeObserve
	}
	return Policy{
		SchemaVersion: SchemaVersion,
		Binary:        p.Binary,
		Mode:          mode,
		Allow:         allow,
		Comment:       proposalComment(p),
	}
}

func proposalComment(p Proposal) string {
	parts := []string{
		fmt.Sprintf("auto-proposed from %d observed connect(s)", p.TotalConnects),
	}
	if p.ObservedDays > 0 {
		parts = append(parts, fmt.Sprintf("%d day(s) of observation", p.ObservedDays))
	}
	if len(p.UniqueClasses) > 0 {
		parts = append(parts, "classes: "+strings.Join(p.UniqueClasses, ","))
	}
	return strings.Join(parts, "; ")
}

// ProposalToSignedPolicy is the one-shot "approve and sign" helper.
// Useful for CLI / tests; the long-form path is Proposal.ToPolicy →
// edit → Sign.
func ProposalToSignedPolicy(p Proposal, signer string, priv ed25519.PrivateKey) (SignedPolicy, error) {
	pol := p.ToPolicy()
	return Sign(pol, signer, priv)
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
