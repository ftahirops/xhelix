// Package policy implements the L1-L6 protection-tier enforcement
// described in CROWN_JEWEL_PROFILE.md §4 and BEHAVIORAL_DEFENSE.md
// §3.12-a. Given a route and the Request Contract that authorizes
// the request, it decides whether the contract carries enough proofs
// to satisfy the route's declared tier.
//
// xhelix does NOT mint WebAuthn assertions or DBSC challenges — the
// portal / L7 bridge does that and reports the result by setting
// fields on the Request Contract (`WebAuthnTS`, `DBSCBound`). This
// package is purely a verifier.
//
// Decision is deterministic — same inputs, same answer, zero false
// positives. Per BEHAVIORAL_DEFENSE.md's Tier-1 doctrine this can
// hard-block.
package policy

import (
	"fmt"
	"time"

	"github.com/xhelix/xhelix/pkg/catalog"
	"github.com/xhelix/xhelix/pkg/reqcontract"
)

// DefaultWebAuthnMaxAge is the maximum acceptable assertion age when
// neither the route nor the operator overrides it. Per the proposal:
// fresh-WebAuthn-within-5m for sensitive actions; tighter for higher
// tiers.
var defaultMaxAge = map[catalog.Tier]time.Duration{
	catalog.TierL3: 5 * time.Minute,
	catalog.TierL4: 2 * time.Minute,
	catalog.TierL5: 60 * time.Second,
	catalog.TierL6: 30 * time.Second,
}

// Decision is the verdict returned by Check.
type Decision uint8

const (
	DecisionAllow Decision = iota
	DecisionDeny
)

func (d Decision) String() string {
	if d == DecisionAllow {
		return "allow"
	}
	return "deny"
}

// Verdict carries the full decision context for logging + LocalAPI.
type Verdict struct {
	Decision      Decision     `json:"decision"`
	Route         string       `json:"route"`
	RequiredTier  catalog.Tier `json:"required_tier"`
	RequiredTierStr string     `json:"required_tier_str"`
	MissingProofs []string     `json:"missing_proofs,omitempty"`
	Reason        string       `json:"reason"`
}

// Check evaluates whether `c` satisfies the route's declared tier.
// A nil catalog means "no policy loaded" → allow with a warning
// reason. A nil contract means "anonymous request" → deny iff the
// route has a declared tier > L1.
func Check(cat *catalog.Catalog, route string, c *reqcontract.Contract) Verdict {
	v := Verdict{
		Route:        route,
		RequiredTier: catalog.TierUnset,
	}

	if cat == nil {
		v.Decision = DecisionAllow
		v.Reason = "no catalog loaded"
		return v
	}

	tier := cat.RouteTier(route)
	v.RequiredTier = tier
	v.RequiredTierStr = tier.String()

	if tier == catalog.TierUnset {
		v.Decision = DecisionAllow
		v.Reason = "route has no declared protection tier"
		return v
	}

	// L1 = valid session only. We trust that the bridge already
	// authenticated the user before issuing the contract; presence
	// of any non-nil contract satisfies L1.
	if tier == catalog.TierL1 {
		if c == nil {
			v.Decision = DecisionDeny
			v.MissingProofs = []string{"session"}
			v.Reason = "L1 requires a valid session"
			return v
		}
		v.Decision = DecisionAllow
		v.Reason = "L1 satisfied (valid session)"
		return v
	}

	// All tiers above L1 require a contract.
	if c == nil {
		v.Decision = DecisionDeny
		v.MissingProofs = []string{"contract"}
		v.Reason = fmt.Sprintf("%s requires a Request Contract; none presented", tier)
		return v
	}

	// L2 = L1 + admin-allow-list source. The allow-list is enforced
	// by pkg/adminguard at the bridge; if the contract reached us,
	// adminguard already approved. So L2 is automatic if the
	// adminguard allow-list covers the route (operator's
	// responsibility to keep them aligned).
	if tier == catalog.TierL2 {
		v.Decision = DecisionAllow
		v.Reason = "L2 satisfied (contract present; adminguard enforces source)"
		return v
	}

	// L3 = L2 + fresh WebAuthn within window.
	maxAge := operatorMaxAge(cat, route, tier)
	if c.WebAuthnTS.IsZero() {
		v.Decision = DecisionDeny
		v.MissingProofs = []string{"webauthn_assertion"}
		v.Reason = fmt.Sprintf("%s requires a fresh WebAuthn assertion (none in contract)", tier)
		return v
	}
	if age := time.Since(c.WebAuthnTS); age > maxAge {
		v.Decision = DecisionDeny
		v.MissingProofs = []string{"webauthn_assertion_fresh"}
		v.Reason = fmt.Sprintf("%s requires WebAuthn ≤ %s old; assertion is %s old", tier, maxAge, age.Round(time.Second))
		return v
	}

	if tier == catalog.TierL3 {
		v.Decision = DecisionAllow
		v.Reason = "L3 satisfied (fresh WebAuthn)"
		return v
	}

	// L4 = L3 + DBSC device-binding.
	if !c.DBSCBound {
		v.Decision = DecisionDeny
		v.MissingProofs = []string{"dbsc_bound"}
		v.Reason = fmt.Sprintf("%s requires DBSC device-binding on the session", tier)
		return v
	}

	if tier == catalog.TierL4 {
		v.Decision = DecisionAllow
		v.Reason = "L4 satisfied (WebAuthn + DBSC)"
		return v
	}

	// L5 = L4 + Data Passport. The contract itself doesn't carry
	// the passport ID directly today — the Egress Valve consults
	// pkg/passport at decision time. So L5 is "all of the above PLUS
	// the route is operator-known to require a passport, enforced
	// by Egress Valve". We approve here; passport-presence is the
	// Egress Valve's job. Future P-RC.4 enrichment may stamp the
	// passport id on the contract for stronger correlation.
	if tier == catalog.TierL5 {
		v.Decision = DecisionAllow
		v.Reason = "L5 satisfied (WebAuthn + DBSC; passport enforcement at Egress Valve)"
		return v
	}

	// L6 = L5 + two-person workflow. xhelix's Data Passport supports
	// approved_by; the operator must wire the two-distinct-issuer
	// rule in the issuance flow. v1 of this verifier approves; the
	// L6 generalization is P-CJ.4 future work.
	if tier == catalog.TierL6 {
		v.Decision = DecisionAllow
		v.Reason = "L6 satisfied (issuance-side two-person workflow not yet enforced — see P-CJ.4)"
		return v
	}

	v.Decision = DecisionDeny
	v.Reason = fmt.Sprintf("unrecognised tier %v", tier)
	return v
}

func operatorMaxAge(cat *catalog.Catalog, route string, tier catalog.Tier) time.Duration {
	if secs := cat.RouteWebAuthnMaxAge(route); secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if d, ok := defaultMaxAge[tier]; ok {
		return d
	}
	return 5 * time.Minute
}
