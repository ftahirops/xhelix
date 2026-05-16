// Package tpmattest defines the attestation interface xhelix uses
// to prove "this is the binary that booted, on this host, with
// this configuration" to the hub.
//
// Two implementations live behind a build tag:
//
//   - default (no TPM hardware): a deterministic-but-unsigned stub
//     so the daemon's hub-side verification path can be exercised
//     without hardware. Documented as INSECURE — operator gets a
//     loud log line.
//   - hardware (build tag `tpmhw`): go-tpm-backed TPM 2.0 quote
//     using AK from NV index. Hub verifies via the AK's
//     certificate.
//
// This file defines the interface + stub. The hardware backend
// lives in tpmattest_hw.go (build tag).
package tpmattest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Quote is the attestation evidence presented to the hub.
type Quote struct {
	// PCRs is the per-PCR digest map (index → hex SHA-256 digest).
	PCRs map[uint32]string

	// Nonce is the hub-supplied challenge echoed back into the
	// signature to prevent replay.
	Nonce []byte

	// Signature is the TPM's signature over (PCRs ++ Nonce). For
	// the stub backend this is a fake deterministic value.
	Signature []byte

	// AKPub is the attestation key's public material. Hub verifies
	// the Signature against AKPub and trusts AKPub via an EK
	// certificate chain.
	AKPub []byte

	// Stub is true when the quote came from the no-hardware stub.
	// Hub-side policy can refuse to accept stub quotes.
	Stub bool
}

// Attester is the interface every backend implements.
type Attester interface {
	// Quote produces an attestation evidence over the configured
	// PCR set, signed by the AK.
	Quote(nonce []byte) (Quote, error)

	// Available reports whether real TPM hardware is reachable.
	Available() bool
}

// Verifier checks a Quote on the hub side.
type Verifier interface {
	// Verify validates the Signature against AKPub + the
	// claimed PCRs and the original challenge nonce. Returns
	// nil on success.
	Verify(q Quote, expectedNonce []byte) error
}

// StubAttester is the no-hardware backend. It produces
// deterministic SHA-256 over a fixed identity string + the nonce,
// so a hub running the matching StubVerifier can sanity-check the
// challenge flow without real attestation.
//
// THIS IS NOT SECURE. The point is to keep the hub-side
// verification surface testable. Production deployments using
// the stub MUST be tagged accordingly so the hub doesn't grant
// production-level trust to stub-signed hosts.
type StubAttester struct {
	HostID string
}

// Available always reports false for the stub backend so callers
// know they're not talking to real hardware.
func (s *StubAttester) Available() bool { return false }

// Quote returns a deterministic fake quote.
func (s *StubAttester) Quote(nonce []byte) (Quote, error) {
	if s.HostID == "" {
		return Quote{}, errors.New("tpmattest: stub requires HostID")
	}
	pcrs := map[uint32]string{
		0:  stubPCR(s.HostID, "boot"),
		7:  stubPCR(s.HostID, "secure-boot-policy"),
		11: stubPCR(s.HostID, "xhelix-binary"),
	}
	sig := stubSignature(s.HostID, pcrs, nonce)
	return Quote{
		PCRs:      pcrs,
		Nonce:     append([]byte(nil), nonce...),
		Signature: sig,
		AKPub:     []byte("STUB-AK:" + s.HostID),
		Stub:      true,
	}, nil
}

// StubVerifier verifies the stub backend's signatures.
type StubVerifier struct{}

// Verify checks the stub deterministic-signature shape.
func (StubVerifier) Verify(q Quote, expectedNonce []byte) error {
	if !q.Stub {
		return errors.New("tpmattest: not a stub quote")
	}
	if !bytesEqual(q.Nonce, expectedNonce) {
		return errors.New("tpmattest: nonce mismatch")
	}
	// Re-derive AKPub identity (encoded HostID) and re-compute
	// the expected stub signature.
	if !bytesHasPrefix(q.AKPub, []byte("STUB-AK:")) {
		return errors.New("tpmattest: malformed AKPub")
	}
	hostID := string(q.AKPub[len("STUB-AK:"):])
	want := stubSignature(hostID, q.PCRs, expectedNonce)
	if !bytesEqual(want, q.Signature) {
		return errors.New("tpmattest: stub signature mismatch")
	}
	return nil
}

// HardwareAvailable reports whether the hardware backend was
// compiled in. Operators consult this to decide which Attester to
// instantiate at runtime.
//
// The default no-TPM build returns false; the tpmhw build tag
// flips it true.
var HardwareAvailable = false

// ── helpers ───────────────────────────────────────────────────

func stubPCR(hostID, slot string) string {
	h := sha256.Sum256([]byte("xhelix-stub:" + hostID + ":" + slot))
	return hex.EncodeToString(h[:])
}

func stubSignature(hostID string, pcrs map[uint32]string, nonce []byte) []byte {
	// Order-independent canonical encoding of PCR map by index.
	h := sha256.New()
	h.Write([]byte("xhelix-stub-sig:"))
	h.Write([]byte(hostID))
	for i := uint32(0); i < 24; i++ {
		if v, ok := pcrs[i]; ok {
			h.Write([]byte{byte(i)})
			h.Write([]byte(v))
		}
	}
	h.Write(nonce)
	return h.Sum(nil)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func bytesHasPrefix(b, pfx []byte) bool {
	if len(b) < len(pfx) {
		return false
	}
	for i := range pfx {
		if b[i] != pfx[i] {
			return false
		}
	}
	return true
}
