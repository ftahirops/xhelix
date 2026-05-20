package sinkhole

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// captureLogger records every event for inspection.
type captureLogger struct {
	mu        sync.Mutex
	starts    []BeaconMeta
	data      []BeaconData
	responses []BeaconResponse
	ends      []BeaconEnd
}

func (c *captureLogger) OnBeaconStart(m BeaconMeta)       { c.mu.Lock(); defer c.mu.Unlock(); c.starts = append(c.starts, m) }
func (c *captureLogger) OnBeaconData(d BeaconData)        { c.mu.Lock(); defer c.mu.Unlock(); c.data = append(c.data, d) }
func (c *captureLogger) OnBeaconResponse(r BeaconResponse) { c.mu.Lock(); defer c.mu.Unlock(); c.responses = append(c.responses, r) }
func (c *captureLogger) OnBeaconEnd(e BeaconEnd)           { c.mu.Lock(); defer c.mu.Unlock(); c.ends = append(c.ends, e) }

func (c *captureLogger) snapshot() (starts []BeaconMeta, data []BeaconData, resps []BeaconResponse, ends []BeaconEnd) {
	c.mu.Lock()
	defer c.mu.Unlock()
	starts = append(starts, c.starts...)
	data = append(data, c.data...)
	resps = append(resps, c.responses...)
	ends = append(ends, c.ends...)
	return
}

// startListener boots a sinkhole on dynamic ports and returns the
// addresses + logger + cleanup.
func startListener(t *testing.T, ports []PortConfig) (*Listener, []net.Addr, *captureLogger) {
	t.Helper()
	log := &captureLogger{}
	l, err := New(Config{
		Ports:                 ports,
		LatencyMin:            0,
		LatencyMax:            0,
		MaxConnectionDuration: 5 * time.Second,
		MaxBytesPerConnection: 1024 * 1024,
		Logger:                log,
		Rand:                  rand.New(rand.NewSource(1)),
		Sleep:                 func(time.Duration) {},
		Now:                   time.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := l.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = l.Stop() })
	return l, l.Addrs(), log
}

func TestHTTP_PlausibleResponse(t *testing.T) {
	_, addrs, log := startListener(t, []PortConfig{{Addr: "127.0.0.1:0", Mode: ModeHTTP}})
	addr := addrs[0].String()

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	// Send a realistic beacon-shaped GET.
	_, err = c.Write([]byte("GET /admin/api/v1/check.json?id=abc HTTP/1.1\r\n" +
		"Host: c2.attacker.example.com\r\n" +
		"User-Agent: BadMalware/2.1\r\n" +
		"Accept: */*\r\n" +
		"Connection: close\r\n\r\n"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 8192)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	resp := string(buf[:n])
	for _, want := range []string{
		"HTTP/1.1 200 OK", "Server: nginx", "Content-Type: application/json",
		`{"status":"ok"`,
	} {
		if !strings.Contains(resp, want) {
			t.Errorf("response missing %q in:\n%s", want, resp)
		}
	}

	// Wait for the sinkhole to record the BeaconEnd.
	waitFor(t, log, "http close")

	starts, data, resps, ends := log.snapshot()
	if len(starts) != 1 || starts[0].Protocol != "http" {
		t.Fatalf("start record wrong: %+v", starts)
	}
	if len(data) == 0 || data[0].HTTPMethod != "GET" || data[0].HTTPHost != "c2.attacker.example.com" {
		t.Fatalf("data record wrong: %+v", data)
	}
	if data[0].HTTPPath != "/admin/api/v1/check.json" {
		t.Fatalf("path not captured: %q", data[0].HTTPPath)
	}
	if data[0].UserAgent != "BadMalware/2.1" {
		t.Fatalf("UA not captured: %q", data[0].UserAgent)
	}
	if len(resps) == 0 || resps[0].Status != "200 OK" {
		t.Fatalf("response record wrong: %+v", resps)
	}
	if len(ends) != 1 || ends[0].BytesRecv == 0 || ends[0].BytesSent == 0 {
		t.Fatalf("end record wrong: %+v", ends)
	}
}

func TestHTTP_KeepAliveAllowsMultipleRequests(t *testing.T) {
	_, addrs, log := startListener(t, []PortConfig{{Addr: "127.0.0.1:0", Mode: ModeHTTP}})
	addr := addrs[0].String()

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	for i := 0; i < 3; i++ {
		_, _ = c.Write([]byte("GET /tick HTTP/1.1\r\nHost: x\r\n\r\n"))
		buf := make([]byte, 4096)
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = c.Read(buf)
	}
	c.Close()
	waitFor(t, log, "keepalive")

	_, data, resps, _ := log.snapshot()
	if len(data) < 3 || len(resps) < 3 {
		t.Fatalf("expected ≥3 exchanges, got data=%d resps=%d", len(data), len(resps))
	}
}

func TestHTTP_PathExtensionShapesResponse(t *testing.T) {
	cases := []struct {
		path   string
		needle string
	}{
		{"/", "<html"},
		{"/api/info.json", "application/json"},
		{"/x.png", "image/png"},
		{"/x.js", "application/javascript"},
		{"/robots.txt", "text/plain"},
	}
	for _, tc := range cases {
		req, _ := http.NewRequest("GET", "http://x"+tc.path, nil)
		wire, _ := fakeHTTPResponse(req)
		if !bytes.Contains(wire, []byte(tc.needle)) {
			t.Errorf("path %q: missing %q in response", tc.path, tc.needle)
		}
	}
}

func TestRaw_EchoesPrefix(t *testing.T) {
	_, addrs, log := startListener(t, []PortConfig{{Addr: "127.0.0.1:0", Mode: ModeRaw}})
	addr := addrs[0].String()

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	payload := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD}
	_, _ = c.Write(payload)
	buf := make([]byte, 16)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != 4 {
		t.Fatalf("expected 4-byte ACK, got %d", n)
	}
	if !bytes.Equal(buf[:4], payload[:4]) {
		t.Fatalf("ack should mirror first 4 bytes, got %x", buf[:4])
	}
	c.Close()
	waitFor(t, log, "raw close")

	_, data, _, ends := log.snapshot()
	if len(data) == 0 {
		t.Fatal("expected data record")
	}
	if data[0].Length != len(payload) {
		t.Fatalf("data length=%d want %d", data[0].Length, len(payload))
	}
	if data[0].IsText {
		t.Fatal("binary payload should be IsText=false")
	}
	if len(ends) != 1 {
		t.Fatalf("ends=%d", len(ends))
	}
}

func TestTLS_HandshakeAndJA3(t *testing.T) {
	_, addrs, log := startListener(t, []PortConfig{{Addr: "127.0.0.1:0", Mode: ModeTLS}})
	addr := addrs[0].String()

	conf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "c2.evil.example.com",
		NextProtos:         []string{"http/1.1"},
	}
	c, err := tls.Dial("tcp", addr, conf)
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer c.Close()

	// Send an HTTP request inside the TLS tunnel.
	_, _ = c.Write([]byte("GET /beacon HTTP/1.1\r\nHost: c2.evil.example.com\r\nConnection: close\r\n\r\n"))
	buf := make([]byte, 8192)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := c.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(buf[:n]), "HTTP/1.1 200 OK") {
		t.Fatalf("no 200 OK over TLS:\n%s", string(buf[:n]))
	}
	c.Close()
	waitFor(t, log, "tls close")

	starts, _, _, _ := log.snapshot()
	if len(starts) == 0 || starts[0].SNI != "c2.evil.example.com" {
		t.Fatalf("SNI not captured: %+v", starts)
	}
	if starts[0].JA3 == "" || starts[0].JA3Hash == "" {
		t.Fatalf("JA3 missing: %+v", starts[0])
	}
}

func TestJSONLLogger_EmitsValidLines(t *testing.T) {
	var buf bytes.Buffer
	l := NewJSONLLogger(&buf)
	l.OnBeaconStart(BeaconMeta{BeaconID: "abc", Protocol: "http"})
	l.OnBeaconData(BeaconData{BeaconID: "abc", Length: 10})
	l.OnBeaconResponse(BeaconResponse{BeaconID: "abc", Length: 100})
	l.OnBeaconEnd(BeaconEnd{BeaconID: "abc", BytesRecv: 10, BytesSent: 100})

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 JSON lines, got %d", len(lines))
	}
	for i, line := range lines {
		var v map[string]interface{}
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Errorf("line %d not JSON: %v (%s)", i, err, line)
		}
		if v["type"] == nil {
			t.Errorf("line %d missing type", i)
		}
	}
}

func TestClassifyAndEncode_TextVsBinary(t *testing.T) {
	enc, isText, sha := classifyAndEncode([]byte("GET / HTTP/1.1\r\n"))
	if !isText {
		t.Fatal("ASCII payload should be text")
	}
	if !strings.HasPrefix(enc, "GET ") {
		t.Fatalf("text payload should be passthrough: %q", enc)
	}
	if len(sha) != 64 {
		t.Fatalf("sha hex len=%d want 64", len(sha))
	}

	enc, isText, _ = classifyAndEncode([]byte{0x00, 0x01, 0x02, 0xff, 0xfe})
	if isText {
		t.Fatal("binary payload should be binary")
	}
	if _, err := hex.DecodeString(enc); err != nil {
		t.Fatalf("binary should be hex-encoded: %v", err)
	}
}

func TestClassifyAndEncode_TruncatesHugePayloads(t *testing.T) {
	huge := bytes.Repeat([]byte("A"), MaxPayloadBytes*2)
	enc, _, sha := classifyAndEncode(huge)
	if len(enc) > MaxPayloadBytes {
		t.Fatalf("encoded len=%d > MaxPayloadBytes=%d", len(enc), MaxPayloadBytes)
	}
	if len(sha) != 64 {
		t.Fatalf("sha len=%d", len(sha))
	}
}

func TestNew_RejectsBadBindAddr(t *testing.T) {
	l, err := New(Config{Ports: []PortConfig{{Addr: "127.0.0.1:0", Mode: ModeHTTP}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Start(); err != nil {
		t.Fatal(err)
	}
	// Second start MUST refuse.
	if err := l.Start(); err == nil {
		t.Fatal("double Start should fail")
	}
	_ = l.Stop()
}

func TestStop_IsIdempotentAndCloses(t *testing.T) {
	l, _, _ := startListener(t, []PortConfig{
		{Addr: "127.0.0.1:0", Mode: ModeHTTP},
		{Addr: "127.0.0.1:0", Mode: ModeTLS},
	})
	addrs := l.Addrs()
	if len(addrs) != 2 {
		t.Fatalf("expected 2 listeners, got %d", len(addrs))
	}
	_ = l.Stop()

	// After Stop, dialing the previous addr should fail (listener closed).
	_, err := net.DialTimeout("tcp", addrs[0].String(), 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected dial to fail after Stop")
	}
}

func TestLatencyInjection(t *testing.T) {
	log := &captureLogger{}
	called := make(chan time.Duration, 4)
	l, err := New(Config{
		Ports:      []PortConfig{{Addr: "127.0.0.1:0", Mode: ModeRaw}},
		LatencyMin: 100 * time.Millisecond,
		LatencyMax: 200 * time.Millisecond,
		Logger:     log,
		Rand:       rand.New(rand.NewSource(7)),
		Sleep: func(d time.Duration) {
			select {
			case called <- d:
			default:
			}
		},
		Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Start(); err != nil {
		t.Fatal(err)
	}
	defer l.Stop()

	addr := l.Addrs()[0].String()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("ping"))
	buf := make([]byte, 8)
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = c.Read(buf)
	c.Close()

	select {
	case d := <-called:
		if d < 100*time.Millisecond || d > 200*time.Millisecond {
			t.Fatalf("latency %v outside expected band", d)
		}
	case <-time.After(time.Second):
		t.Fatal("Sleep was never called")
	}
}

func TestRandDur_HandlesZeroSpan(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	if d := randDur(r, 10, 5); d != 10 {
		t.Fatalf("hi<=lo should return lo, got %v", d)
	}
	if d := randDur(r, 5, 5); d != 5 {
		t.Fatalf("equal bounds should return lo, got %v", d)
	}
}

// waitFor polls the logger up to 1s until an "end" record arrives.
// Connection handlers run in goroutines so the close record can lag
// the client-side Close().
func waitFor(t *testing.T, log *captureLogger, label string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		_, _, _, ends := log.snapshot()
		if len(ends) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s: no beacon_end record after 1s", label)
}

