package brp

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// AlgorithmEd25519 is the only signature algorithm currently supported.
// New algorithms may be added but old binaries must reject unknown ones.
const AlgorithmEd25519 = "ed25519"

// Sign produces a SignedProfile by signing the canonical bytes of p
// with priv. signer is recorded as the wire-format identifier for the
// public key (e.g. "xhelix-project-2026" or "operator-douxl-com").
//
// If p has SchemaVersion == 0 or SigningEpoch == 0, they are populated
// here with sensible defaults (current schema, current time).
func Sign(p Profile, signer string, priv ed25519.PrivateKey) (SignedProfile, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return SignedProfile{}, fmt.Errorf("invalid private key size %d (want %d)", len(priv), ed25519.PrivateKeySize)
	}
	if signer == "" {
		return SignedProfile{}, errors.New("signer is required")
	}
	if p.SchemaVersion == 0 {
		p.SchemaVersion = SchemaVersion
	}
	if p.SigningEpoch == 0 {
		p.SigningEpoch = time.Now().UnixNano()
	}
	if err := p.Validate(); err != nil {
		return SignedProfile{}, fmt.Errorf("validate: %w", err)
	}
	canonical, err := p.CanonicalBytes()
	if err != nil {
		return SignedProfile{}, fmt.Errorf("canonicalise: %w", err)
	}
	sig := ed25519.Sign(priv, canonical)
	return SignedProfile{
		Profile:   p,
		Signer:    signer,
		Algorithm: AlgorithmEd25519,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// Verify checks sp's signature against pub. Returns nil on success.
//
// Failure modes (all returned as wrapped errors):
//
//   - wrong algorithm (only ed25519 supported in v1)
//   - signature decode failure
//   - cryptographic signature mismatch
//   - structural validation failure (Profile.Validate)
//
// The protect-our-own check inside Validate runs as part of Verify,
// so an HSM-signed profile claiming write access to /etc/shadow STILL
// fails verification — this is the v2 "curator cannot subvert
// endpoint" invariant.
func Verify(sp SignedProfile, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size %d (want %d)", len(pub), ed25519.PublicKeySize)
	}
	if sp.Algorithm != AlgorithmEd25519 {
		return fmt.Errorf("unsupported algorithm %q (only %q supported)", sp.Algorithm, AlgorithmEd25519)
	}
	if sp.Signer == "" {
		return errors.New("signer is empty")
	}
	if err := sp.Profile.Validate(); err != nil {
		return fmt.Errorf("validate: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sp.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	canonical, err := sp.Profile.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("canonicalise: %w", err)
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return errors.New("ed25519 signature does not verify")
	}
	return nil
}

// MarshalSigned produces the on-disk wire format for a SignedProfile
// (indented JSON for human review; signature payload is binary-stable
// regardless of indentation).
func MarshalSigned(sp SignedProfile) ([]byte, error) {
	return json.MarshalIndent(sp, "", "  ")
}

// UnmarshalSigned parses a wire-format SignedProfile.
func UnmarshalSigned(data []byte) (SignedProfile, error) {
	var sp SignedProfile
	if err := json.Unmarshal(data, &sp); err != nil {
		return SignedProfile{}, fmt.Errorf("unmarshal: %w", err)
	}
	return sp, nil
}

// LoadSigned reads and parses a SignedProfile from disk. Does NOT
// verify the signature — caller must invoke Verify with the appropriate
// public key. Separating load from verify lets the operator inspect a
// candidate profile (`xhelixctl brp show`) without holding a key.
func LoadSigned(path string) (SignedProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return SignedProfile{}, fmt.Errorf("read %s: %w", path, err)
	}
	return UnmarshalSigned(data)
}

// WriteSigned writes sp to path with 0o644 perms. Profiles are read by
// xhelix as the daemon user; they don't need to be secret (the
// signature attests authenticity).
func WriteSigned(path string, sp SignedProfile) error {
	data, err := MarshalSigned(sp)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
