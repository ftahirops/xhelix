package credbroker

import "time"

// AlertKind enumerates credbroker decision outcomes that warrant an
// external alert. These map onto rule IDs the takeover scorer scores.
type AlertKind string

const (
	// AlertSealedDenied: a sealed file open was refused by the broker.
	// Strongest deterministic signal credbroker emits — by construction
	// no legitimate caller can hit this unless their contract is wrong.
	// Score weight should be Tier-1.
	AlertSealedDenied AlertKind = "credbroker_unauthentic_open"

	// AlertHoneyTouched: a decoy honey file was opened. Honey files
	// have zero legitimate readers; any touch is adversarial-by-
	// construction. Highest-confidence signal in the system.
	AlertHoneyTouched AlertKind = "credbroker_honey_touched"

	// AlertHoneyMarkerSeen: a sensor saw a honey marker in network
	// traffic, env vars, or another file — meaning the attacker
	// exfiltrated and is now USING the honey credential. Fires once
	// per (marker, observation source).
	AlertHoneyMarkerSeen AlertKind = "credbroker_honey_marker_in_flight"

	// AlertPlaintextRead: a watched plaintext credential file
	// (~/.aws/credentials, ~/.npmrc, .env, etc.) was opened. Unlike
	// AlertSealedDenied this fires for EVERY read because the file
	// hasn't been converted to sealed form; the reader's identity +
	// lineage is the signal. In detect mode the open is allowed; in
	// enforce mode it can be denied based on a reader allowlist.
	AlertPlaintextRead AlertKind = "credbroker_plaintext_read"
)

// BrokerAlert is the structured payload emitted on each significant
// broker decision. The daemon's pkg/alert sink consumes these and
// hands them to the rule engine + takeover scorer.
type BrokerAlert struct {
	Kind       AlertKind
	SealedPath string
	PID        uint32
	Lineage    []LineageNode
	Reason     string
	At         time.Time
	// HoneyMarker is populated only for AlertHoneyTouched /
	// AlertHoneyMarkerSeen events.
	HoneyMarker string
}

// AlertEmitter is the broker's outbound interface to the daemon's
// alert bus. The credbroker package defines it; the cmd/xhelix daemon
// implements it (so we avoid an import cycle on pkg/alert).
type AlertEmitter interface {
	Emit(BrokerAlert)
}

// NopEmitter is the safe default for tests.
type NopEmitter struct{}

// Emit discards the alert.
func (NopEmitter) Emit(BrokerAlert) {}
