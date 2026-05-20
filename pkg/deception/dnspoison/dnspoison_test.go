package dnspoison

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- classify tests ---

func TestClassify_KnownBad(t *testing.T) {
	c := NewClassifier()
	c.SetKnownBad([]string{"evilcorp.com", "badnet.io"})

	cases := []struct {
		name string
		want MatchKind
	}{
		{"login.evilcorp.com", MatchKnownBad},
		{"evilcorp.com.", MatchKnownBad},
		{"EVILCORP.com", MatchKnownBad},
		{"good.example.com", MatchNone},
		{"badnet.io", MatchKnownBad},
		{"", MatchNone},
	}
	for _, tc := range cases {
		if got := c.Classify(tc.name); got != tc.want {
			t.Errorf("Classify(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestClassify_DGAPatterns(t *testing.T) {
	c := NewClassifier()
	// High-entropy, no vowels, mixed digits — classic DGA.
	if got := c.Classify("kx9vqzm7nbwt.com"); got != MatchDGA {
		t.Fatalf("DGA-shaped name not flagged: got %q", got)
	}
	// Long all-digits — flagged.
	if got := c.Classify("8473820194834.com"); got != MatchDGA {
		t.Fatalf("digit-DGA not flagged: got %q", got)
	}
}

func TestClassify_NormalDomainsNotFlagged(t *testing.T) {
	c := NewClassifier()
	for _, n := range []string{
		"google.com", "github.com", "example.org",
		"login.microsoftonline.com", "stackoverflow.com",
		"ubuntu.com", "kernel.org",
	} {
		if got := c.Classify(n); got != MatchNone {
			t.Errorf("real domain %q misclassified as %q", n, got)
		}
	}
}

func TestClassify_IgnoresLocalSuffixes(t *testing.T) {
	c := NewClassifier()
	for _, n := range []string{
		"weirdlongname.local", "kx9vqzm7nbwt.internal", "x.arpa",
	} {
		if got := c.Classify(n); got != MatchNone {
			t.Errorf("%q should be ignored: got %q", n, got)
		}
	}
}

// --- wire-format tests ---

// buildQuery encodes a minimal DNS query for the given name +
// qtype. Returns the wire bytes — used in tests.
func buildQuery(t *testing.T, id uint16, name string, qtype uint16) []byte {
	t.Helper()
	var b bytes.Buffer
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // RD=1
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT=1
	b.Write(hdr)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b.WriteByte(byte(len(label)))
		b.WriteString(label)
	}
	b.WriteByte(0) // root
	footer := make([]byte, 4)
	binary.BigEndian.PutUint16(footer[0:2], qtype)
	binary.BigEndian.PutUint16(footer[2:4], 1) // CLASS IN
	b.Write(footer)
	return b.Bytes()
}

func TestParseQuery_RoundTrip(t *testing.T) {
	q := buildQuery(t, 0xabcd, "evil.example.com", 1)
	m, err := parseQuery(q)
	if err != nil {
		t.Fatalf("parseQuery: %v", err)
	}
	if m.id != 0xabcd {
		t.Errorf("id=%04x want abcd", m.id)
	}
	if m.qtype != 1 {
		t.Errorf("qtype=%d want 1", m.qtype)
	}
	if got := m.question.String(); got != "evil.example.com" {
		t.Errorf("name=%q want evil.example.com", got)
	}
}

func TestEncodeAResponse_ReadableByGoResolver(t *testing.T) {
	q := buildQuery(t, 0x1234, "evil.example.com", 1)
	resp, err := encodeAResponse(q, [4]byte{127, 0, 0, 99}, 60)
	if err != nil {
		t.Fatal(err)
	}
	// Header: QR=1, RA=1, ANCOUNT=1.
	if binary.BigEndian.Uint16(resp[2:4])&0x8000 == 0 {
		t.Fatal("QR bit not set")
	}
	if binary.BigEndian.Uint16(resp[6:8]) != 1 {
		t.Fatalf("ANCOUNT=%d want 1", binary.BigEndian.Uint16(resp[6:8]))
	}
	// Last 4 bytes are the A-record RDATA.
	last := resp[len(resp)-4:]
	if !bytes.Equal(last, []byte{127, 0, 0, 99}) {
		t.Fatalf("RDATA=%v want 127.0.0.99", last)
	}
}

func TestEncodeNXDomain(t *testing.T) {
	q := buildQuery(t, 0xbeef, "weird.com", 1)
	resp, err := encodeNXDomain(q)
	if err != nil {
		t.Fatal(err)
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x000F != 3 {
		t.Fatalf("RCODE=%d want 3 (NXDOMAIN)", flags&0x000F)
	}
}

// --- server integration tests ---

type captureLogger struct {
	mu      sync.Mutex
	poisons []PoisonEvent
	passes  []PassthroughEvent
}

func (c *captureLogger) OnPoisoned(e PoisonEvent)        { c.mu.Lock(); defer c.mu.Unlock(); c.poisons = append(c.poisons, e) }
func (c *captureLogger) OnPassthrough(e PassthroughEvent) { c.mu.Lock(); defer c.mu.Unlock(); c.passes = append(c.passes, e) }
func (c *captureLogger) snapshot() (poisons []PoisonEvent, passes []PassthroughEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]PoisonEvent(nil), c.poisons...), append([]PassthroughEvent(nil), c.passes...)
}

func startServer(t *testing.T, classifier *Classifier, upstream string) (*Server, string, *captureLogger) {
	t.Helper()
	log := &captureLogger{}
	if classifier == nil {
		classifier = NewClassifier()
	}
	s, err := New(Config{
		UDPAddr:        "127.0.0.1:0",
		Classifier:     classifier,
		Upstream:       upstream,
		Logger:         log,
		LogPassthrough: true,
		SinkIP:         net.IPv4(127, 0, 0, 99),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(s.Stop)
	return s, s.UDPAddr().String(), log
}

func sendQuery(t *testing.T, addr string, query []byte) []byte {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(query); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return buf[:n]
}

func TestServer_PoisonsKnownBadDomain(t *testing.T) {
	cl := NewClassifier()
	cl.SetKnownBad([]string{"attacker.example.com"})
	_, addr, log := startServer(t, cl, "")

	q := buildQuery(t, 0x1111, "c2.attacker.example.com", 1)
	resp := sendQuery(t, addr, q)

	// Last 4 bytes of an A-record response are the IP.
	if !bytes.Equal(resp[len(resp)-4:], []byte{127, 0, 0, 99}) {
		t.Fatalf("expected sinkhole IP in response, got %v", resp[len(resp)-4:])
	}

	waitFor(t, func() bool {
		p, _ := log.snapshot()
		return len(p) == 1
	}, "poisoned event")

	p, _ := log.snapshot()
	if p[0].Match != MatchKnownBad {
		t.Errorf("Match=%q want known_bad", p[0].Match)
	}
	if p[0].Name != "c2.attacker.example.com" {
		t.Errorf("Name=%q", p[0].Name)
	}
	if p[0].SinkIP != "127.0.0.99" {
		t.Errorf("SinkIP=%q want 127.0.0.99", p[0].SinkIP)
	}
}

func TestServer_PoisonsDGADomain(t *testing.T) {
	_, addr, log := startServer(t, nil, "")
	q := buildQuery(t, 0x2222, "kx9vqzm7nbwt.com", 1)
	resp := sendQuery(t, addr, q)
	if !bytes.Equal(resp[len(resp)-4:], []byte{127, 0, 0, 99}) {
		t.Fatal("DGA domain should resolve to sink IP")
	}
	waitFor(t, func() bool {
		p, _ := log.snapshot()
		return len(p) == 1 && p[0].Match == MatchDGA
	}, "dga event")
}

func TestServer_NXDomainOnAAAAForPoisoned(t *testing.T) {
	cl := NewClassifier()
	cl.SetKnownBad([]string{"attacker.example.com"})
	_, addr, _ := startServer(t, cl, "")

	q := buildQuery(t, 0x3333, "attacker.example.com", 28) // AAAA
	resp := sendQuery(t, addr, q)
	// Flags low-nibble = 3 (NXDOMAIN)
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x000F != 3 {
		t.Fatalf("expected NXDOMAIN for AAAA on poisoned name, got rcode=%d", flags&0x000F)
	}
}

func TestServer_NormalDomainPasstroughRefusedWithoutUpstream(t *testing.T) {
	_, addr, log := startServer(t, nil, "") // no upstream
	q := buildQuery(t, 0x4444, "google.com", 1)
	resp := sendQuery(t, addr, q)
	// Should be NXDOMAIN (no upstream configured).
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x000F != 3 {
		t.Fatalf("expected NXDOMAIN without upstream, got rcode=%d", flags&0x000F)
	}
	waitFor(t, func() bool {
		_, p := log.snapshot()
		return len(p) == 1 && !p[0].Forwarded
	}, "passthrough refused event")
}

func TestServer_StopIdempotent(t *testing.T) {
	s, _, _ := startServer(t, nil, "")
	s.Stop()
	s.Stop() // must not panic
}

// --- helpers ---

func waitFor(t *testing.T, cond func() bool, label string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s: never became true", label)
}
