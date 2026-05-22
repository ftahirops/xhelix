package credbroker

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Broker is the central decision engine. USG.1a implements:
//   - Seal: take plaintext + Meta, return a SealedFile
//   - Unseal: take a SealedFile, return plaintext (audited)
//   - Decide: take a Request against a sealed file, return Result
//
// Decide in USG.1a uses a stub allow-all-with-audit policy. The
// real purpose-bound policy (lineage match + passport + 2FA) lands
// in USG.1b. Shipping the broker now with a stub policy lets us
// migrate `.aws/credentials` to sealed form today and harden the
// decision logic incrementally without re-touching the on-disk
// format.
type Broker struct {
	sealer       Sealer
	contract     *Contract       // Layer-1: image-regex × class (defaults)
	appContracts *AppContractSet // Layer-2: path-anchored per-app

	mu    sync.RWMutex
	audit []AuditRecord // ring buffer; xhelixctl credbroker history reads from this
	cap   int           // max audit records retained
}

// NewBroker constructs a Broker. cap is the audit ring-buffer
// capacity (default 1024 when ≤0). contract may be nil for the
// migration-only stub behaviour (allow + audit); production
// daemon callers must pass a real contract.
func NewBroker(sealer Sealer, cap int) *Broker {
	if cap <= 0 {
		cap = 1024
	}
	return &Broker{
		sealer: sealer,
		cap:    cap,
	}
}

// WithContract sets the Layer-1 (image-regex × class) policy contract.
// Returns broker for chaining.
func (b *Broker) WithContract(c *Contract) *Broker {
	b.contract = c
	return b
}

// WithAppContracts sets the Layer-2 (path-anchored per-app) contract
// set. When a sealed-file path is claimed by any AppContract,
// authorisation is exclusive: only matching AppContracts can authorise
// access; Layer-1 image-regex fallback is bypassed for that path.
// This is what makes "developer ships their contract with the app"
// work — once declared, only the declared callers can open the file.
func (b *Broker) WithAppContracts(s *AppContractSet) *Broker {
	b.appContracts = s
	return b
}

// AppContracts returns the loaded Layer-2 set (may be nil).
func (b *Broker) AppContracts() *AppContractSet { return b.appContracts }

// Seal encrypts plaintext under sealer, embeds meta, returns the
// SealedFile ready for Write. The caller chooses where to write it
// (typically the original path with ".sealed" suffix).
func (b *Broker) Seal(plaintext []byte, meta Meta) (*SealedFile, error) {
	if meta.Version == 0 {
		meta.Version = 1
	}
	if meta.Created.IsZero() {
		meta.Created = time.Now().UTC()
	}
	if meta.KeyID == "" {
		meta.KeyID = b.sealer.KeyID()
	}
	ct, err := b.sealer.Seal(plaintext)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	return &SealedFile{Meta: meta, Ciphertext: ct}, nil
}

// Unseal decrypts a SealedFile's ciphertext and returns plaintext.
// No policy check here — callers that respect the broker's gate use
// Decide instead. This is exposed for the migration tool
// (`xhelixctl credbroker unseal --force`) and operator recovery.
func (b *Broker) Unseal(sf *SealedFile) ([]byte, error) {
	if sf == nil {
		return nil, fmt.Errorf("unseal: nil SealedFile")
	}
	// Check the sealer's KeyID matches; in v2 we'll consult a
	// keyring of historical keys for rotation. v1 fails closed.
	if sf.Meta.KeyID != "" && sf.Meta.KeyID != b.sealer.KeyID() {
		return nil, fmt.Errorf("unseal: keyID mismatch (file=%q, sealer=%q) — key rotation not supported yet",
			sf.Meta.KeyID, b.sealer.KeyID())
	}
	pt, err := b.sealer.Unseal(sf.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("unseal: %w", err)
	}
	return pt, nil
}

// Decide is the policy gate. USG.1a: stubAllowAll returns Allow +
// audit. USG.1b will replace the body with real logic:
//   1. lineage match against credcontract
//   2. passport / request-contract presence
//   3. 2FA attestation for sensitive classes
//   4. honey-on-deny lookup
func (b *Broker) Decide(sf *SealedFile, req Request) Result {
	if req.Now.IsZero() {
		req.Now = time.Now().UTC()
	}
	rec := AuditRecord{
		Time:       req.Now,
		SealedPath: req.SealedPath,
		Class:      sf.Meta.Class,
		PID:        req.PID,
		Lineage:    req.Lineage,
		Reason:     req.Reason,
	}
	if len(req.Lineage) > 0 {
		rec.Comm = req.Lineage[0].Comm
		rec.Image = req.Lineage[0].Image
		rec.UID = req.Lineage[0].UID
	}

	// Layer-2 (per-app, path-anchored) takes precedence when any
	// AppContract claims this sealed path. Authorisation is then
	// exclusive — Layer-1 image-regex fallback is bypassed.
	if b.appContracts != nil && b.appContracts.HasContractFor(req.SealedPath) {
		m2 := b.appContracts.Match(req.Lineage, req.SealedPath, req.Now)
		if m2.Matched {
			pt, err := b.Unseal(sf)
			if err != nil {
				rec.Outcome = OutcomeDeny
				rec.Reason = fmt.Sprintf("unseal failed: %v", err)
				b.recordAudit(rec)
				return Result{Outcome: OutcomeDeny, Audit: rec, Reason: rec.Reason}
			}
			rec.Outcome = OutcomeAllow
			rec.Reason = m2.Reason
			b.recordAudit(rec)
			return Result{Outcome: OutcomeAllow, Plaintext: pt, Reason: rec.Reason, Audit: rec}
		}
		// Path is claimed by Layer-2 contracts but caller doesn't
		// satisfy any. DENY — this is the universal-rock-solid
		// guarantee: the credential's contract said "only these
		// callers" and this caller isn't one.
		rec.Outcome = OutcomeDeny
		rec.Reason = "Layer-2: " + m2.Reason
		b.recordAudit(rec)
		return Result{Outcome: OutcomeDeny, Audit: rec, Reason: rec.Reason}
	}

	// No contract loaded: legacy fall-through (allow + audit).
	// Production callers must pass a contract via WithContract.
	if b.contract == nil {
		pt, err := b.Unseal(sf)
		if err != nil {
			rec.Outcome = OutcomeDeny
			rec.Reason = fmt.Sprintf("unseal failed: %v", err)
			b.recordAudit(rec)
			return Result{Outcome: OutcomeDeny, Audit: rec, Reason: rec.Reason}
		}
		rec.Outcome = OutcomeAllow
		rec.Reason = "no contract loaded (migration-only stub)"
		b.recordAudit(rec)
		return Result{Outcome: OutcomeAllow, Plaintext: pt, Reason: rec.Reason, Audit: rec}
	}

	// Real policy: match the lineage against the contract.
	m := b.contract.Match(req.Lineage, sf.Meta.Class)

	if !m.Matched {
		// Two cases:
		//  - contract has DefaultDeny=true (strict)  → deny
		//  - contract has DefaultDeny=false (legacy) → allow w/ warn
		// USG.1c will add honey-on-deny here; for now we just deny.
		if b.contract.DefaultDeny {
			rec.Outcome = OutcomeDeny
			rec.Reason = fmt.Sprintf(
				"no contract rule matches lineage for class=%s (default_deny=true)",
				sf.Meta.Class)
			b.recordAudit(rec)
			return Result{Outcome: OutcomeDeny, Audit: rec, Reason: rec.Reason}
		}
		// Not-strict: warn + allow. Operator can read the warning
		// in `xhelixctl credbroker history` and tighten policy.
		pt, err := b.Unseal(sf)
		if err != nil {
			rec.Outcome = OutcomeDeny
			rec.Reason = fmt.Sprintf("unseal failed: %v", err)
			b.recordAudit(rec)
			return Result{Outcome: OutcomeDeny, Audit: rec, Reason: rec.Reason}
		}
		rec.Outcome = OutcomeAllow
		rec.Reason = fmt.Sprintf(
			"WARN: no contract rule for class=%s; allowed (default_deny=false)",
			sf.Meta.Class)
		b.recordAudit(rec)
		return Result{Outcome: OutcomeAllow, Plaintext: pt, Reason: rec.Reason, Audit: rec}
	}

	// Matched rule. USG.1d enforces AttestRequired via Slack
	// approval; until then we record the requirement and audit
	// loudly. USG.1c adds honey-on-deny for repeat unattested.
	if m.AttestRequired {
		// For USG.1b, treat attest_required as warn+allow with a
		// clear audit message. Real 2FA happens in USG.1d.
		pt, err := b.Unseal(sf)
		if err != nil {
			rec.Outcome = OutcomeDeny
			rec.Reason = fmt.Sprintf("unseal failed: %v", err)
			b.recordAudit(rec)
			return Result{Outcome: OutcomeDeny, Audit: rec, Reason: rec.Reason}
		}
		rec.Outcome = OutcomeAllow
		rec.Reason = fmt.Sprintf(
			"matched rule=%s (attest_required; not yet enforced, USG.1d)",
			m.RuleName)
		b.recordAudit(rec)
		return Result{Outcome: OutcomeAllow, Plaintext: pt, Reason: rec.Reason, Audit: rec}
	}

	// Clean match — allow.
	pt, err := b.Unseal(sf)
	if err != nil {
		rec.Outcome = OutcomeDeny
		rec.Reason = fmt.Sprintf("unseal failed: %v", err)
		b.recordAudit(rec)
		return Result{Outcome: OutcomeDeny, Audit: rec, Reason: rec.Reason}
	}
	rec.Outcome = OutcomeAllow
	rec.Reason = fmt.Sprintf("matched rule=%s", m.RuleName)
	b.recordAudit(rec)
	return Result{Outcome: OutcomeAllow, Plaintext: pt, Reason: rec.Reason, Audit: rec}
}

// History returns a copy of the audit ring buffer (newest last).
// xhelixctl credbroker history reads this.
func (b *Broker) History() []AuditRecord {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]AuditRecord, len(b.audit))
	copy(out, b.audit)
	return out
}

func (b *Broker) recordAudit(r AuditRecord) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.audit = append(b.audit, r)
	if len(b.audit) > b.cap {
		// Drop the oldest. O(n) shift is fine for cap=1024; we'll
		// switch to a ring buffer if profiling justifies it.
		b.audit = b.audit[len(b.audit)-b.cap:]
	}
}

// ─────────────────────── master-key custody ──────────────────────

// LoadOrCreateMasterKey reads the master key from path, generating
// a fresh one if the file doesn't exist. Returns the 32-byte key.
//
// Honest scope: USG.1a stores the master key as a file on disk
// (mode 0600, root-only). This is the weakest possible custody
// model — a root attacker can read it. The
// LOW_FALSE_POSITIVE_ARCHITECTURE doc §7.1 explicitly names this
// as a v1 acceptable starting point, with TPM/KMS custody as
// follow-on work. Keyguard's existing Signer interface (file →
// TPM → KMS) is the model we'll extend in USG.1d.
func LoadOrCreateMasterKey(path string) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil {
		if len(data) != 32 {
			return nil, fmt.Errorf("master key at %s is %d bytes (want 32) — manually inspect; do NOT delete (it would brick every sealed file)",
				path, len(data))
		}
		return data, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read master key: %w", err)
	}
	// Create.
	key, err := GenerateMasterKey()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(parentDir(path), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir for key: %w", err)
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, fmt.Errorf("write master key: %w", err)
	}
	return key, nil
}

func parentDir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}
