package hubmtls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestCAGenerates(t *testing.T) {
	ca, err := NewCA("test-org", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if ca.Cert == nil || ca.Key == nil {
		t.Fatal("missing fields")
	}
	if !ca.Cert.IsCA {
		t.Fatal("cert should be CA")
	}
	if ca.Cert.Subject.Organization[0] != "test-org" {
		t.Fatalf("org = %v", ca.Cert.Subject.Organization)
	}
}

func TestCARoundTripPEM(t *testing.T) {
	ca, _ := NewCA("test", 24*time.Hour)
	loaded, err := LoadCA(ca.CertPEM, ca.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Cert.Subject.CommonName != ca.Cert.Subject.CommonName {
		t.Fatalf("CN mismatch: %s vs %s",
			loaded.Cert.Subject.CommonName, ca.Cert.Subject.CommonName)
	}
}

func TestIssueHostProducesValidCert(t *testing.T) {
	ca, _ := NewCA("test", 24*time.Hour)
	certPEM, keyPEM, err := ca.IssueHost("host-007", 0)
	if err != nil {
		t.Fatal(err)
	}
	// Reload and check identity
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(pair.Certificate) == 0 {
		t.Fatal("no cert")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "host-007" {
		t.Errorf("CN = %s", leaf.Subject.CommonName)
	}
	if leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("EKU wrong: %v", leaf.ExtKeyUsage)
	}
}

func TestHostCertVerifiesAgainstCA(t *testing.T) {
	ca, _ := NewCA("test", 24*time.Hour)
	certPEM, _, err := ca.IssueHost("h1", 0)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM)
	// Parse the host cert
	hostBlock, _ := parseFirstCert(t, certPEM)
	if _, err := hostBlock.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func TestIssueServerWithSANs(t *testing.T) {
	ca, _ := NewCA("test", 24*time.Hour)
	certPEM, _, err := ca.IssueServer("hub.local",
		[]string{"hub.local", "hub.internal"},
		[]net.IP{net.ParseIP("10.0.0.1")},
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := parseFirstCert(t, certPEM)
	if c.Subject.CommonName != "hub.local" {
		t.Errorf("CN = %s", c.Subject.CommonName)
	}
	if len(c.DNSNames) != 2 || len(c.IPAddresses) != 1 {
		t.Errorf("SANs wrong: dns=%v ip=%v", c.DNSNames, c.IPAddresses)
	}
}

func TestEndToEndHandshake(t *testing.T) {
	ca, _ := NewCA("test", 24*time.Hour)
	serverCert, serverKey, _ := ca.IssueServer("localhost",
		[]string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}, 0)
	hostCert, hostKey, _ := ca.IssueHost("host-007", 0)

	serverCfg, err := ca.ServerTLSConfig(serverCert, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg, err := ClientTLSConfig(ca.CertPEM, hostCert, hostKey, "localhost")
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- "accept-err: " + err.Error()
			return
		}
		defer conn.Close()
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			done <- "handshake-err: " + err.Error()
			return
		}
		id := IdentityFromConn(tlsConn.ConnectionState())
		_, _ = io.WriteString(conn, "hello")
		done <- id
	}()

	client, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Errorf("payload = %q", buf)
	}
	select {
	case got := <-done:
		if got != "host-007" {
			t.Errorf("server saw client identity %q, want host-007", got)
		}
	case <-time.After(time.Second):
		t.Fatal("server goroutine never reported identity")
	}
}

func TestUnauthorisedClientRejected(t *testing.T) {
	hubCA, _ := NewCA("hub", 24*time.Hour)
	rogueCA, _ := NewCA("rogue", 24*time.Hour)
	serverCert, serverKey, _ := hubCA.IssueServer("localhost",
		[]string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}, 0)
	rogueCert, rogueKey, _ := rogueCA.IssueHost("attacker", 0)

	serverCfg, _ := hubCA.ServerTLSConfig(serverCert, serverKey)
	clientCfg, _ := ClientTLSConfig(hubCA.CertPEM, rogueCert, rogueKey, "localhost")

	ln, _ := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.(*tls.Conn).Handshake() // expected to fail
	}()
	// In TLS 1.3 the server may accept the TCP connection but
	// reject the client cert during the handshake — the client
	// notices on first read/write. Dial alone is not authoritative.
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		return // rejected at Dial time — good
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	// Force a real handshake completion.
	if hs := conn.Handshake(); hs == nil {
		buf := make([]byte, 1)
		if _, rerr := conn.Read(buf); rerr == nil {
			t.Fatal("rogue client read succeeded; expected rejection")
		}
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ca, _ := NewCA("test", 24*time.Hour)
	cp := filepath.Join(dir, "ca.crt")
	kp := filepath.Join(dir, "ca.key")
	if err := ca.Save(cp, kp); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCAFromDisk(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Cert.Subject.CommonName != ca.Cert.Subject.CommonName {
		t.Fatal("mismatch after load")
	}
}

func TestExpiredCertDetected(t *testing.T) {
	ca, _ := NewCA("test", 24*time.Hour)
	hostCertPEM, _, _ := ca.IssueHost("h", time.Hour)
	c, _ := parseFirstCert(t, hostCertPEM)
	if IsExpired(c, time.Now()) {
		t.Fatal("fresh cert should not be expired")
	}
	future := c.NotAfter.Add(time.Hour)
	if !IsExpired(c, future) {
		t.Fatal("cert past NotAfter should be expired")
	}
}

func TestTimeUntilExpiry(t *testing.T) {
	ca, _ := NewCA("test", 24*time.Hour)
	hostCertPEM, _, _ := ca.IssueHost("h", 2*time.Hour)
	c, _ := parseFirstCert(t, hostCertPEM)
	d := TimeUntilExpiry(c, time.Now())
	if d < time.Hour || d > 3*time.Hour {
		t.Fatalf("ttl = %v, want ~2h", d)
	}
}

func TestIssueHostEmptyIDErrors(t *testing.T) {
	ca, _ := NewCA("test", 24*time.Hour)
	if _, _, err := ca.IssueHost("", 0); err == nil {
		t.Fatal("empty hostID should error")
	}
}

func TestLoadCABadPEMErrors(t *testing.T) {
	if _, err := LoadCA([]byte("not-pem"), []byte("nope")); err == nil {
		t.Fatal("bad PEM should error")
	}
}

func TestIdentityFromConnEmptyOnNoCert(t *testing.T) {
	state := tls.ConnectionState{}
	if got := IdentityFromConn(state); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func parseFirstCert(t *testing.T, pemBytes []byte) (*x509.Certificate, error) {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}
