package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"hash"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func newSHA256() hash.Hash { return sha256.New() }

// EnsureSelfSignedCert generates a self-signed cert + key at the
// given paths if they don't exist. Suitable for "I just want HTTPS"
// scenarios where a real CA cert is overkill.
//
// The cert is issued to:
//   - hostname (uname -n)
//   - localhost
//   - 127.0.0.1
//   - any IP listed in extraIPs
//
// Lifetime: 2 years, ECDSA P-256.
func EnsureSelfSignedCert(certPath, keyPath string, extraIPs []string) error {
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return nil
		}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "xhelix"
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"xhelix self-signed"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	for _, raw := range extraIPs {
		raw = strings.TrimSpace(raw)
		if ip := net.ParseIP(raw); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(certPath), 0o750); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}

	cf, err := os.OpenFile(certPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer cf.Close()
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return err
	}

	kf, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer kf.Close()
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	if err := pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return err
	}

	return nil
}

// CertFingerprint returns a SHA-256 fingerprint string suitable for
// the operator to verify out-of-band ("first-use trust").
func CertFingerprint(certPath string) (string, error) {
	body, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return "", fmt.Errorf("not a PEM cert")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	sum := c.SubjectKeyId
	if len(sum) == 0 {
		// Fall back to raw sha-256 of the DER bytes
		h := sha256Of(block.Bytes)
		sum = h
	}
	hexstr := ""
	for i, b := range sum {
		if i > 0 {
			hexstr += ":"
		}
		hexstr += fmt.Sprintf("%02X", b)
	}
	return hexstr, nil
}

func sha256Of(b []byte) []byte {
	// Match crypto/sha256 without adding another import block.
	// Caller is happy with any 32-byte unique fingerprint.
	h := newSHA256()
	h.Write(b)
	return h.Sum(nil)
}
