// Package keyguard is the signing-key abstraction. Today's chain
// signs every batch with an Ed25519 key kept in a file at
// /var/lib/xhelix/chain.key. Root on the box can forge batches by
// reading that file.
//
// keyguard fronts the key behind a Signer interface so the operator
// can promote chain.key out of the filesystem onto:
//
//   - TPM (sealed against PCR-bound policy)
//   - cloud KMS (AWS KMS, GCP KMS, Azure Key Vault)
//   - HashiCorp Vault Transit
//
// The xhelix daemon never sees the raw key when an off-host Signer
// is in use; it sends batch hashes over the Signer API and receives
// signatures back. Root compromise can still drive signing while
// xhelix is alive, but the attacker can no longer forge batches
// retroactively (e.g. after rewriting old chain entries) — the
// off-host signer refuses to sign anything not matching the current
// prev-hash.
//
// This package ships the **abstraction** + a file-backed default
// (behaviour-equivalent to today's chain.key). TPM, KMS, Vault
// adapters are stubs that operators can wire in by setting
// signer.kind in the YAML once the relevant runtime is available.
package keyguard

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Signer signs a batch hash and exposes its verification pubkey.
// Implementations must be safe for concurrent use.
type Signer interface {
	// Sign produces a signature over the batch hash (already
	// computed in pkg/chain). Length-32 hash → 64-byte ed25519 sig.
	Sign(hash []byte) ([]byte, error)
	// PublicKey returns the verification key that xhelix-verify
	// uses. Length-32 ed25519 pubkey.
	PublicKey() []byte
	// Kind returns a short string identifier ("file", "tpm",
	// "aws-kms", "gcp-kms", "vault"). Logged by the daemon.
	Kind() string
}

// Config selects which Signer backend to use.
//
//	kind=file       — file-backed Ed25519 (default; today's behavior).
//	kind=tpm        — TPM-2.0 sealed key (Linux /dev/tpmrm0).
//	kind=aws-kms    — AWS KMS asymmetric KEY_USAGE=SIGN_VERIFY.
//	kind=gcp-kms    — GCP KMS asymmetric signing key.
//	kind=vault      — Vault Transit signing.
//
// Unknown kinds → error at New(). Unwired kinds → return ErrSignerNotImpl.
type Config struct {
	Kind     string `yaml:"kind"`        // file | tpm | aws-kms | gcp-kms | vault
	Path     string `yaml:"path"`        // file kind: key path
	KeyID    string `yaml:"key_id"`      // KMS-class: key ARN / resource ID
	VaultURL string `yaml:"vault_url"`   // vault kind: base URL
	TPMHandle uint32 `yaml:"tpm_handle"` // tpm kind: persistent handle (e.g. 0x81000001)
}

// ErrSignerNotImpl indicates the operator selected a Signer kind
// whose adapter is not built into this binary. The xhelix daemon
// must refuse to start in this case so we never silently fall back
// to a weaker primitive.
var ErrSignerNotImpl = errors.New("signer kind not implemented in this build")

// New builds a Signer per the config. Default kind is "file".
func New(cfg Config) (Signer, error) {
	kind := strings.ToLower(strings.TrimSpace(cfg.Kind))
	if kind == "" {
		kind = "file"
	}
	switch kind {
	case "file":
		return newFileSigner(cfg.Path)
	case "tpm":
		return nil, fmt.Errorf("%w: tpm (use sealed-key adapter; see docs/CROWN_JEWEL_PROFILE.md §3.2)", ErrSignerNotImpl)
	case "aws-kms":
		return nil, fmt.Errorf("%w: aws-kms (operator must build with KMS adapter)", ErrSignerNotImpl)
	case "gcp-kms":
		return nil, fmt.Errorf("%w: gcp-kms", ErrSignerNotImpl)
	case "vault":
		return nil, fmt.Errorf("%w: vault", ErrSignerNotImpl)
	}
	return nil, fmt.Errorf("unknown signer kind %q", kind)
}

// ─── file-backed (default) ───────────────────────────────────

type fileSigner struct {
	mu     sync.RWMutex
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	path   string
}

func newFileSigner(path string) (*fileSigner, error) {
	if path == "" {
		path = "/var/lib/xhelix/chain.key"
	}
	s := &fileSigner{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		// First-time generate
		pub, priv, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return nil, fmt.Errorf("generate ed25519: %w", gerr)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, fmt.Errorf("mkdir for chain.key: %w", err)
		}
		if err := os.WriteFile(path, priv, 0o600); err != nil {
			return nil, fmt.Errorf("write chain.key: %w", err)
		}
		s.priv = priv
		s.pub = pub
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read chain.key: %w", err)
	}
	if len(data) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("chain.key wrong size: got %d want %d",
			len(data), ed25519.PrivateKeySize)
	}
	s.priv = ed25519.PrivateKey(data)
	s.pub = s.priv.Public().(ed25519.PublicKey)
	return s, nil
}

func (s *fileSigner) Sign(hash []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.priv) == 0 {
		return nil, errors.New("file signer: key not loaded")
	}
	return ed25519.Sign(s.priv, hash), nil
}

func (s *fileSigner) PublicKey() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]byte(nil), s.pub...)
}

func (s *fileSigner) Kind() string { return "file" }

// PublicKeyHex helper for logs / health checks.
func PublicKeyHex(s Signer) string {
	return hex.EncodeToString(s.PublicKey())
}
