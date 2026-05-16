// Package hubmtls provides the mTLS handshake helpers for the
// xhelix <-> xhub link. Replaces the bearer-token authentication
// in the current `pkg/hub` transport.
//
// Threat model: an attacker who reads disk on one host should not
// be able to impersonate other hosts on the hub. mTLS with
// per-host client certificates issued by a hub-private CA solves
// this — stealing host A's key gets you only host A's identity,
// and rotating it is a one-step operation.
//
// Two roles:
//
//   - Hub-side CA: long-lived self-signed root that issues
//     per-host client certificates on first-contact bootstrap.
//   - Host-side credential: per-host private key + cert signed
//     by the hub CA. Stored at a configurable path (typically
//     /var/lib/xhelix/hub.crt + hub.key).
//
// Pure-Go: crypto/tls + crypto/x509 + crypto/ecdsa + crypto/elliptic
// + crypto/rand + math/big + encoding/pem. No third-party deps.
package hubmtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// ── Hub-side CA ──────────────────────────────────────────────

// CA is a long-lived self-signed root that issues per-host client
// certificates. Persisted on the hub host.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	// CertPEM / KeyPEM hold the encoded forms for serialisation.
	CertPEM []byte
	KeyPEM  []byte
}

// NewCA generates a new CA valid for the given lifetime. orgName
// is embedded in the certificate's Subject.O field.
func NewCA(orgName string, lifetime time.Duration) (*CA, error) {
	if lifetime <= 0 {
		lifetime = 10 * 365 * 24 * time.Hour
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("hubmtls: ca key: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "xhub-ca",
			Organization: []string{orgName},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(lifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("hubmtls: create ca cert: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return &CA{Cert: cert, Key: key, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// LoadCA reads a CA from PEM bytes.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, errors.New("hubmtls: bad cert PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("hubmtls: bad key PEM")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// IssueHost issues a host client certificate. hostID becomes the
// certificate's CommonName and is the identity hubs see at
// connection time.
func (ca *CA) IssueHost(hostID string, lifetime time.Duration) (certPEM, keyPEM []byte, err error) {
	if hostID == "" {
		return nil, nil, errors.New("hubmtls: empty hostID")
	}
	if lifetime <= 0 {
		lifetime = 90 * 24 * time.Hour
	}
	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostID},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	hostDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &hostKey.PublicKey, ca.Key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: hostDER})
	keyDER, err := x509.MarshalECPrivateKey(hostKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// IssueServer issues a server cert for the hub itself. dnsNames /
// ipSANs go into the SAN extension so hosts can connect by name
// or address.
func (ca *CA) IssueServer(commonName string, dnsNames []string, ipSANs []net.IP, lifetime time.Duration) (certPEM, keyPEM []byte, err error) {
	if commonName == "" {
		return nil, nil, errors.New("hubmtls: empty commonName")
	}
	if lifetime <= 0 {
		lifetime = 365 * 24 * time.Hour
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ipSANs,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// ServerTLSConfig builds a tls.Config for the hub server using
// its own server cert + key and the CA for verifying clients.
// ClientAuth is set to RequireAndVerifyClientCert.
func (ca *CA) ServerTLSConfig(serverCertPEM, serverKeyPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM) {
		return nil, errors.New("hubmtls: failed to append CA")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ClientTLSConfig builds a tls.Config for a host connecting to
// the hub. Caller provides the per-host cert+key plus the hub's
// CA cert PEM.
func ClientTLSConfig(caCertPEM, hostCertPEM, hostKeyPEM []byte, serverName string) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(hostCertPEM, hostKeyPEM)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		return nil, errors.New("hubmtls: failed to append CA")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// IdentityFromConn returns the CommonName presented by the
// connected peer. Returns "" when no peer cert is available
// (e.g. before handshake or for non-mTLS connections).
func IdentityFromConn(state tls.ConnectionState) string {
	if len(state.PeerCertificates) == 0 {
		return ""
	}
	return state.PeerCertificates[0].Subject.CommonName
}

// ── disk persistence ─────────────────────────────────────────

// SaveCA writes the CA cert + key PEM to two files. Key file is
// chmod 0600.
func (ca *CA) Save(certPath, keyPath string) error {
	if err := os.WriteFile(certPath, ca.CertPEM, 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, ca.KeyPEM, 0o600)
}

// LoadCAFromDisk reads a previously-saved CA.
func LoadCAFromDisk(certPath, keyPath string) (*CA, error) {
	cb, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	kb, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return LoadCA(cb, kb)
}

// SaveHostCreds writes per-host cert + key to disk.
func SaveHostCreds(certPath, keyPath string, certPEM, keyPEM []byte) error {
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, keyPEM, 0o600)
}

// IsExpired returns true when c's NotAfter is past `now` or its
// NotBefore is in the future.
func IsExpired(c *x509.Certificate, now time.Time) bool {
	return now.After(c.NotAfter) || now.Before(c.NotBefore)
}

// TimeUntilExpiry returns NotAfter - now. Negative when expired.
func TimeUntilExpiry(c *x509.Certificate, now time.Time) time.Duration {
	return c.NotAfter.Sub(now)
}

// ── helpers ──────────────────────────────────────────────────

func randSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, max)
}
