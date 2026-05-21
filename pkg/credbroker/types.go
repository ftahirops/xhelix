// Package credbroker is the universal credential gate described in
// docs/UNIVERSAL_SECRET_GATE_ARCHITECTURE_2026-05-21.md.
//
// The broker replaces plaintext-on-disk credentials with sealed
// objects + a mediated release API. Reads of a managed credential
// go through the broker, which decides — based on source identity,
// time-window capability, and out-of-band attestation — whether to:
//
//   * release the real (possibly short-lived) credential
//   * return a honey credential (deception)
//   * deny outright
//
// This file (types.go) defines the data shapes only. seal.go has
// the AES-256-GCM primitive. broker.go has decision logic.
//
// Honest scope of USG.1a (this commit):
//   - sealed-file format defined and round-trippable
//   - seal/unseal primitives work
//   - broker has a stub allow-all decision (real policy comes in USG.1b)
//   - no kernel hook yet (USG.2)
//   - no provider integration yet (USG.1b ships AWS STS)
//   - no honey-on-deny yet (USG.1c)
//   - no Slack approval yet (USG.1d)
//
// What this commit gives you: a working Sealer that turns
// ~/.aws/credentials into ~/.aws/credentials.sealed and back, with
// audit metadata embedded in the sealed envelope. Foundation for
// every later milestone.
package credbroker

import "time"

// Class is the catalog data-class (mirrors pkg/catalog).
// Empty class is treated as untrusted by all decision policies.
type Class string

const (
	ClassAPIKey      Class = "api_key"
	ClassCredentials Class = "credentials"
	ClassPaymentTok  Class = "payment_token"
	ClassBackup      Class = "backup"
	ClassSourceCode  Class = "source_code"
	ClassCanary      Class = "canary"
)

// Meta is the metadata carried inside every sealed object.
// Operator-visible (not encrypted) so xhelixctl can show what a
// sealed file holds without unsealing it.
type Meta struct {
	Version   int       `json:"version"`            // schema version (1 today)
	Class     Class     `json:"class"`              // catalog class
	Purpose   string    `json:"purpose,omitempty"`  // human-readable purpose
	Created   time.Time `json:"created"`            // sealing time
	Issuer    string    `json:"issuer,omitempty"`   // who sealed it (operator, automation)
	OrigPath  string    `json:"orig_path,omitempty"` // original on-disk path before sealing
	// KeyID identifies which master key sealed this object so we
	// can rotate keys without breaking older sealed files. Zero
	// value means "current default key."
	KeyID string `json:"key_id,omitempty"`
}

// Request describes one credential-release attempt that the broker
// must decide on. It's the gateway's per-call input — the broker
// has to look at all of these factors before returning a Result.
//
// USG.1b will widen this to include Passport / RequestContract
// references and IDE plugin identity. USG.1a only carries lineage.
type Request struct {
	// SealedPath is the absolute path of the sealed file the
	// requester is trying to open (or the broker handle ID for
	// pure-API consumers).
	SealedPath string

	// PID + Lineage describe the requester. PID is the immediate
	// process; Lineage is the full causal chain.
	PID     uint32
	Lineage []LineageNode

	// Now is the decision timestamp. Injected so tests can pin time.
	Now time.Time

	// Reason is operator-supplied text for ad-hoc xhelixctl unseals.
	// Audit-only; doesn't affect the decision.
	Reason string
}

// LineageNode is one step in the causal chain. Mirrors
// pkg/lineage.Node fields we care about for decisions.
type LineageNode struct {
	PID   uint32
	Comm  string
	Image string
	UID   uint32
}

// Outcome is the broker's per-request decision.
type Outcome string

const (
	OutcomeAllow Outcome = "allow"  // plaintext returned
	OutcomeHoney Outcome = "honey"  // honey credential returned (looks real, exfil triggers alert)
	OutcomeDeny  Outcome = "deny"   // nothing returned; reader gets an error
)

// Result is what the broker returns for one Request.
type Result struct {
	Outcome   Outcome
	Plaintext []byte  // populated when Outcome == Allow OR Honey (honey-data here is the honey)
	Reason    string  // human-readable explanation for audit log
	// Audit is the structured event record that should land in the
	// xhelix evidence chain regardless of outcome.
	Audit AuditRecord
}

// AuditRecord is the immutable record of one broker decision.
// Every Result has one; the broker is responsible for emitting it
// to the alert bus + chain.
type AuditRecord struct {
	Time       time.Time
	SealedPath string
	Class      Class
	Outcome    Outcome
	PID        uint32
	Comm       string
	Image      string
	UID        uint32
	Lineage    []LineageNode
	Reason     string
}
