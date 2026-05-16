// Package releaseverify verifies signed release manifests at
// startup — the "this binary is what the release engineer signed"
// check that pairs with cosign-attested release artifacts.
//
// Design: the package is stdlib-only. It doesn't pull in
// sigstore-go (which transitively pulls dozens of deps and breaks
// the static-binary contract). Instead, it implements the subset
// of Sigstore verification xhelix needs:
//
//   - Parse a release manifest JSON containing
//     {sha256, cert_pem, signature_b64, rekor_log_url}.
//   - Verify the certificate chains to a trusted root (operator-
//     supplied or the bundled Fulcio root).
//   - Verify the signature over sha256||cert_pem using the
//     certificate's public key.
//   - Verify that sha256 matches the running binary's hash.
//
// The Rekor transparency-log lookup is deferred to operator-side
// cosign tooling — xhelix consumes the result (a manifest the
// operator pre-fetched) rather than reaching out to the log at
// startup. This keeps the verifier offline-friendly.
package releaseverify

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// Manifest is the on-disk signed-release record.
type Manifest struct {
	// Binary sha256 in hex.
	SHA256 string `json:"sha256"`

	// PEM-encoded signing certificate.
	CertPEM string `json:"cert_pem"`

	// Base64 signature over the digest of (SHA256 + CertPEM).
	SignatureB64 string `json:"signature_b64"`

	// Optional Rekor log URL (informational; full verification
	// is operator-side).
	RekorLogURL string `json:"rekor_log_url,omitempty"`

	// Optional release version/tag.
	Version string `json:"version,omitempty"`

	// Optional release timestamp.
	IssuedAt time.Time `json:"issued_at,omitempty"`
}

// Trust holds the operator-configured trust anchors.
type Trust struct {
	// Roots accepted at the top of the cert chain. Caller fills
	// with operator-supplied Fulcio roots or a private CA.
	Roots *x509.CertPool

	// Intermediates is optional.
	Intermediates *x509.CertPool

	// AllowExpired bypasses NotBefore/NotAfter checks. Required
	// to be false in production; tests flip it.
	AllowExpired bool

	// Now overrides the wall clock (tests). Defaults to time.Now().
	Now func() time.Time
}

// LoadManifest reads a manifest from JSON bytes.
func LoadManifest(b []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("releaseverify: parse manifest: %w", err)
	}
	if m.SHA256 == "" || m.CertPEM == "" || m.SignatureB64 == "" {
		return nil, errors.New("releaseverify: manifest missing required fields")
	}
	return &m, nil
}

// LoadManifestFromFile is a convenience wrapper.
func LoadManifestFromFile(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadManifest(b)
}

// Verify checks the manifest against trust + binaryPath. Returns
// nil only when:
//   - the manifest's certificate chains to a Roots anchor;
//   - the manifest's signature is valid over (SHA256 || CertPEM);
//   - the binary's actual SHA-256 matches the manifest claim.
func Verify(m *Manifest, t Trust, binaryPath string) error {
	if t.Roots == nil {
		return errors.New("releaseverify: Trust.Roots required")
	}
	now := time.Now
	if t.Now != nil {
		now = t.Now
	}

	// 1. Parse the cert.
	cert, err := parseCertPEM(m.CertPEM)
	if err != nil {
		return fmt.Errorf("releaseverify: %w", err)
	}

	// 2. Chain verify.
	opts := x509.VerifyOptions{
		Roots:         t.Roots,
		Intermediates: t.Intermediates,
		CurrentTime:   now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageAny},
	}
	if t.AllowExpired {
		opts.CurrentTime = cert.NotBefore.Add(time.Second)
	}
	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("releaseverify: cert chain: %w", err)
	}

	// 3. Decode signature.
	sig, err := base64.StdEncoding.DecodeString(m.SignatureB64)
	if err != nil {
		return fmt.Errorf("releaseverify: bad signature base64: %w", err)
	}

	// 4. Compute the digest the signature claims to cover.
	digest := digestOver(m.SHA256, m.CertPEM)

	// 5. Verify signature.
	if err := verifySignature(cert, digest, sig); err != nil {
		return fmt.Errorf("releaseverify: signature: %w", err)
	}

	// 6. Hash the binary on disk and compare.
	if binaryPath == "" {
		return errors.New("releaseverify: binaryPath required")
	}
	got, err := hashFile(binaryPath)
	if err != nil {
		return fmt.Errorf("releaseverify: hash binary: %w", err)
	}
	if got != m.SHA256 {
		return fmt.Errorf("releaseverify: binary hash mismatch: have %s want %s", got, m.SHA256)
	}
	return nil
}

// HashFile returns the hex SHA-256 of the file at path. Exposed
// so callers can verify their own running binary independently
// of Verify().
func HashFile(path string) (string, error) {
	return hashFile(path)
}

// ── helpers ───────────────────────────────────────────────────

func parseCertPEM(s string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("not a PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func digestOver(sha256Hex, certPEM string) []byte {
	h := sha256.New()
	h.Write([]byte("xhelix-release-v1:"))
	h.Write([]byte(sha256Hex))
	h.Write([]byte{0})
	h.Write([]byte(certPEM))
	return h.Sum(nil)
}

func verifySignature(cert *x509.Certificate, digest, sig []byte) error {
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if ecdsa.VerifyASN1(pub, digest, sig) {
			return nil
		}
		return errors.New("ecdsa signature invalid")
	case *rsa.PublicKey:
		// RSA-PSS or PKCS1v15 — try PKCS1v15 first since cosign
		// historically used it.
		if err := rsa.VerifyPKCS1v15(pub, 0, digest, sig); err == nil {
			return nil
		}
		// Try PSS.
		if err := rsa.VerifyPSS(pub, 0, digest, sig, nil); err == nil {
			return nil
		}
		return errors.New("rsa signature invalid")
	default:
		return errors.New("unsupported public key type")
	}
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ── BuildManifest helper (for the release pipeline) ──────────

// SignDigest is the operator-pipeline-side helper that, given a
// signer + cert, produces the Manifest. Operators typically use
// cosign for this; we provide a stdlib path for self-hosted CA
// deployments.
type Signer interface {
	// Sign signs the given digest and returns the signature
	// bytes (raw, the verifier will base64-encode).
	Sign(digest []byte) ([]byte, error)
}

// BuildManifest hashes the binary at binaryPath, signs the
// release digest with signer, and returns a populated Manifest.
func BuildManifest(binaryPath, version string, certPEM string, signer Signer) (*Manifest, error) {
	sha, err := hashFile(binaryPath)
	if err != nil {
		return nil, err
	}
	digest := digestOver(sha, certPEM)
	sig, err := signer.Sign(digest)
	if err != nil {
		return nil, err
	}
	return &Manifest{
		SHA256:       sha,
		CertPEM:      certPEM,
		SignatureB64: base64.StdEncoding.EncodeToString(sig),
		Version:      version,
		IssuedAt:     time.Now().UTC(),
	}, nil
}
