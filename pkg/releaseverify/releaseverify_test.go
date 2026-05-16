package releaseverify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testCA produces a self-signed root + a code-signing leaf for tests.
type testCA struct {
	root     *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	rootPool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-root"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{root: cert, rootKey: key, rootPool: pool}
}

func (c *testCA) issueLeaf(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "release-signer"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.root, &key.PublicKey, c.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return cert, key, certPEM
}

// ecdsaSigner adapts an ECDSA private key to the Signer interface.
type ecdsaSigner struct{ k *ecdsa.PrivateKey }

func (s *ecdsaSigner) Sign(digest []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, s.k, digest)
}

func writeBinary(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xhelix")
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVerifyHappyPath(t *testing.T) {
	ca := newTestCA(t)
	_, key, certPEM := ca.issueLeaf(t)
	bin := writeBinary(t, "fake xhelix binary")

	m, err := BuildManifest(bin, "0.0.11", certPEM, &ecdsaSigner{k: key})
	if err != nil {
		t.Fatal(err)
	}

	if err := Verify(m, Trust{Roots: ca.rootPool}, bin); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyDetectsBinaryTamper(t *testing.T) {
	ca := newTestCA(t)
	_, key, certPEM := ca.issueLeaf(t)
	bin := writeBinary(t, "original")
	m, _ := BuildManifest(bin, "v", certPEM, &ecdsaSigner{k: key})

	// Mutate the binary.
	_ = os.WriteFile(bin, []byte("attacker-modified"), 0o755)
	err := Verify(m, Trust{Roots: ca.rootPool}, bin)
	if err == nil {
		t.Fatal("expected hash mismatch")
	}
}

func TestVerifyDetectsManifestTamper(t *testing.T) {
	ca := newTestCA(t)
	_, key, certPEM := ca.issueLeaf(t)
	bin := writeBinary(t, "x")
	m, _ := BuildManifest(bin, "v", certPEM, &ecdsaSigner{k: key})

	// Mutate the SHA in the manifest.
	m.SHA256 = "ff" + m.SHA256[2:]
	if err := Verify(m, Trust{Roots: ca.rootPool}, bin); err == nil {
		t.Fatal("expected sig invalid after manifest tamper")
	}
}

func TestVerifyRejectsUntrustedRoot(t *testing.T) {
	caA := newTestCA(t)
	caB := newTestCA(t)
	_, key, certPEM := caA.issueLeaf(t)
	bin := writeBinary(t, "x")
	m, _ := BuildManifest(bin, "v", certPEM, &ecdsaSigner{k: key})

	if err := Verify(m, Trust{Roots: caB.rootPool}, bin); err == nil {
		t.Fatal("verify against wrong root should fail")
	}
}

func TestLoadManifestRejectsEmpty(t *testing.T) {
	if _, err := LoadManifest([]byte(`{}`)); err == nil {
		t.Fatal("empty manifest must fail")
	}
}

func TestLoadManifestFromFile(t *testing.T) {
	ca := newTestCA(t)
	_, key, certPEM := ca.issueLeaf(t)
	bin := writeBinary(t, "x")
	m, _ := BuildManifest(bin, "v", certPEM, &ecdsaSigner{k: key})

	path := filepath.Join(filepath.Dir(bin), "release.json")
	b, _ := json.MarshalIndent(m, "", "  ")
	_ = os.WriteFile(path, b, 0o644)

	loaded, err := LoadManifestFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SHA256 != m.SHA256 {
		t.Fatal("round-trip mismatch")
	}
}

func TestVerifyRequiresRoots(t *testing.T) {
	if err := Verify(&Manifest{SHA256: "x", CertPEM: "y", SignatureB64: "z"},
		Trust{}, "/dev/null"); err == nil {
		t.Fatal("Verify without Roots should fail")
	}
}

func TestVerifyBadBase64Signature(t *testing.T) {
	ca := newTestCA(t)
	_, _, certPEM := ca.issueLeaf(t)
	bin := writeBinary(t, "x")
	sha, _ := HashFile(bin)
	m := &Manifest{SHA256: sha, CertPEM: certPEM, SignatureB64: "not-base64!"}
	if err := Verify(m, Trust{Roots: ca.rootPool}, bin); err == nil {
		t.Fatal("bad base64 should fail")
	}
}

func TestHashFileMissing(t *testing.T) {
	if _, err := HashFile("/no/such/path"); err == nil {
		t.Fatal("missing file should error")
	}
}

func TestVerifyBadCertPEM(t *testing.T) {
	ca := newTestCA(t)
	bin := writeBinary(t, "x")
	sha, _ := HashFile(bin)
	m := &Manifest{SHA256: sha, CertPEM: "not a PEM", SignatureB64: "abc"}
	if err := Verify(m, Trust{Roots: ca.rootPool}, bin); err == nil {
		t.Fatal("bad PEM should fail")
	}
}

// LoadManifestFromFile uses encoding/json indirectly; import here
// so the package isn't accidentally unused above.
var _ = json.Marshal
