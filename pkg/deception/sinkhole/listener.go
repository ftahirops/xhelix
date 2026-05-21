package sinkhole

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	mrand "math/rand"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"
)

// Mode identifies how the sinkhole speaks to a connection.
type Mode string

const (
	// ModeHTTP — sinkhole reads HTTP/1.1 requests, returns plausible
	// 200 OK responses with realistic headers. Default for port 80.
	ModeHTTP Mode = "http"
	// ModeTLS — sinkhole completes a TLS handshake with a self-signed
	// cert matched to the client's SNI, then speaks HTTP over the
	// secure channel. Default for ports 443/8443.
	ModeTLS Mode = "tls"
	// ModeRaw — sinkhole echoes after a randomised delay. Default
	// for non-HTTP ports (4444, 1337, custom C2).
	ModeRaw Mode = "raw"
)

// PortConfig binds one listen address to a Mode. Multiple PortConfigs
// per Listener — typical: 80→HTTP, 443→TLS, 4444→Raw.
type PortConfig struct {
	Addr string // e.g. "127.0.0.1:8081"
	Mode Mode
}

// Config tunes the listener.
type Config struct {
	Ports []PortConfig

	// LatencyMin / LatencyMax bound the per-response delay injected
	// before bytes are written. Defaults: 50ms / 500ms — see
	// PROTECTED_SERVICES_TRAP.md §4.6 cost-asymmetry budget.
	LatencyMin time.Duration
	LatencyMax time.Duration

	// MaxConnectionDuration caps how long any one connection can
	// hold. Defaults to 5min.
	MaxConnectionDuration time.Duration

	// MaxBytesPerConnection caps how many recv bytes we'll accept
	// before closing the connection. Defaults to 10 MiB.
	MaxBytesPerConnection int64

	// Logger receives forensic events.
	Logger Logger

	// Now / Sleep / Rand — test hooks.
	Now   func() time.Time
	Sleep func(time.Duration)
	Rand  *mrand.Rand
}

func (c *Config) defaulted() Config {
	d := *c
	if d.LatencyMin == 0 {
		d.LatencyMin = 50 * time.Millisecond
	}
	if d.LatencyMax == 0 {
		d.LatencyMax = 500 * time.Millisecond
	}
	if d.MaxConnectionDuration == 0 {
		d.MaxConnectionDuration = 5 * time.Minute
	}
	if d.MaxBytesPerConnection == 0 {
		d.MaxBytesPerConnection = 10 * 1024 * 1024
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Sleep == nil {
		d.Sleep = time.Sleep
	}
	if d.Rand == nil {
		d.Rand = mrand.New(mrand.NewSource(time.Now().UnixNano()))
	}
	if d.Logger == nil {
		d.Logger = noopLogger{}
	}
	return d
}

// Listener accepts forbidden-outbound connections that have been
// redirected here (typically by the eBPF socket-redirect program in
// P-PS.7b) and responds plausibly.
type Listener struct {
	cfg   Config
	cert  tls.Certificate
	tlsMu sync.Mutex // protects cert if we want to rotate later

	mu    sync.Mutex
	ln    []net.Listener
	wg    sync.WaitGroup
	doneC chan struct{}
}

// New returns a Listener ready to Start. cert generation happens at
// construction so we fail fast on crypto problems.
func New(c Config) (*Listener, error) {
	c = c.defaulted()
	cert, err := generateSelfSigned()
	if err != nil {
		return nil, fmt.Errorf("sinkhole: cert gen: %w", err)
	}
	return &Listener{cfg: c, cert: cert, doneC: make(chan struct{})}, nil
}

// Start binds every configured port and begins accepting. Returns
// when all listeners are bound (or any one fails to bind).
func (l *Listener) Start() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.ln) > 0 {
		return fmt.Errorf("sinkhole: already started")
	}
	for _, pc := range l.cfg.Ports {
		nl, err := net.Listen("tcp", pc.Addr)
		if err != nil {
			// Close anything already bound to keep state clean.
			for _, prev := range l.ln {
				_ = prev.Close()
			}
			l.ln = nil
			return fmt.Errorf("sinkhole: listen %s: %w", pc.Addr, err)
		}
		l.ln = append(l.ln, nl)
		l.wg.Add(1)
		go l.acceptLoop(nl, pc.Mode)
	}
	return nil
}

// Addrs returns the actual bound addresses (useful when ports are
// allocated dynamically via ":0").
func (l *Listener) Addrs() []net.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]net.Addr, len(l.ln))
	for i, nl := range l.ln {
		out[i] = nl.Addr()
	}
	return out
}

// Stop closes every listener and waits for in-flight connections to
// finish (or hit MaxConnectionDuration). Idempotent — safe to call
// multiple times (test cleanup may double-call).
func (l *Listener) Stop() error {
	l.mu.Lock()
	for _, nl := range l.ln {
		_ = nl.Close()
	}
	l.ln = nil
	select {
	case <-l.doneC:
		// already closed
	default:
		close(l.doneC)
	}
	l.mu.Unlock()
	l.wg.Wait()
	return nil
}

func (l *Listener) acceptLoop(nl net.Listener, mode Mode) {
	defer l.wg.Done()
	for {
		c, err := nl.Accept()
		if err != nil {
			// Listener closed → exit cleanly.
			select {
			case <-l.doneC:
				return
			default:
				return
			}
		}
		l.wg.Add(1)
		go func(conn net.Conn, m Mode) {
			defer l.wg.Done()
			l.handle(conn, m)
		}(c, mode)
	}
}

func (l *Listener) handle(c net.Conn, mode Mode) {
	defer c.Close()
	id := randBeaconID(l.cfg.Rand)
	start := l.cfg.Now()
	meta := BeaconMeta{
		BeaconID:  id,
		StartedAt: start,
		LocalAddr: remoteAddrToStr(c.LocalAddr()),
		PeerAddr:  remoteAddrToStr(c.RemoteAddr()),
		Protocol:  string(mode),
	}

	// Deadline so a stalled attacker connection doesn't hold a goroutine forever.
	_ = c.SetDeadline(start.Add(l.cfg.MaxConnectionDuration))

	switch mode {
	case ModeTLS:
		l.handleTLS(c, meta)
	case ModeHTTP:
		l.cfg.Logger.OnBeaconStart(meta)
		l.serveHTTP(c, meta, false)
	default:
		l.cfg.Logger.OnBeaconStart(meta)
		l.serveRaw(c, meta)
	}
}

func (l *Listener) handleTLS(raw net.Conn, meta BeaconMeta) {
	// Wrap in TLS. We use GetCertificate so the SNI lands in meta.
	tlsConf := &tls.Config{
		GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			meta.SNI = hi.ServerName
			if len(hi.SupportedProtos) > 0 {
				meta.ALPN = hi.SupportedProtos[0]
			}
			meta.JA3 = ja3Fingerprint(hi)
			meta.JA3Hash = ja3Hash(meta.JA3)
			return &l.cert, nil
		},
		NextProtos: []string{"http/1.1"},
		// MinVersion: TLS 1.0 — attackers using old malware should
		// still connect (we're optimising for capture, not security).
		MinVersion: tls.VersionTLS10,
	}
	tc := tls.Server(raw, tlsConf)
	hsCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(hsCtx); err != nil {
		// Emit a start record with the partial info we got.
		l.cfg.Logger.OnBeaconStart(meta)
		l.cfg.Logger.OnBeaconEnd(BeaconEnd{
			BeaconID: meta.BeaconID, EndedAt: l.cfg.Now(),
			Duration:    l.cfg.Now().Sub(meta.StartedAt),
			CloseReason: "tls_handshake_failed",
		})
		return
	}
	l.cfg.Logger.OnBeaconStart(meta)
	l.serveHTTP(tc, meta, true)
}

func (l *Listener) serveHTTP(c net.Conn, meta BeaconMeta, isTLS bool) {
	br := bufio.NewReader(io.LimitReader(c, l.cfg.MaxBytesPerConnection))
	var (
		rx, tx    int64
		exchanges int
		seqRx     int
		seqTx     int
	)
	end := func(reason string) {
		l.cfg.Logger.OnBeaconEnd(BeaconEnd{
			BeaconID: meta.BeaconID, EndedAt: l.cfg.Now(),
			Duration:    l.cfg.Now().Sub(meta.StartedAt),
			BytesRecv:   rx,
			BytesSent:   tx,
			Exchanges:   exchanges,
			CloseReason: reason,
		})
	}
	for {
		req, raw, err := parseHTTPRequest(br)
		if err != nil {
			if err == io.EOF {
				end("peer_closed")
			} else {
				end("parse_error:" + err.Error())
			}
			return
		}
		seqRx++
		rx += int64(len(raw))
		encoded, isText, sha := classifyAndEncode(raw)
		d := BeaconData{
			BeaconID: meta.BeaconID, At: l.cfg.Now(), Sequence: seqRx,
			Length: len(raw), Payload: encoded, IsText: isText, Sha256: sha,
		}
		d.HTTPMethod = req.Method
		d.HTTPHost = req.Host
		if req.URL != nil {
			d.HTTPPath = req.URL.Path
		}
		d.UserAgent = req.Header.Get("User-Agent")
		l.cfg.Logger.OnBeaconData(d)

		// Drain body for forensic capture; cap to keep memory bounded.
		_, _ = io.CopyN(io.Discard, req.Body, 64*1024)
		_ = req.Body.Close()

		// Latency injection — cost asymmetry.
		lat := randDur(l.cfg.Rand, l.cfg.LatencyMin, l.cfg.LatencyMax)
		l.cfg.Sleep(lat)

		wire, status := fakeHTTPResponse(req)
		if _, err := c.Write(wire); err != nil {
			end("write_error:" + err.Error())
			return
		}
		seqTx++
		tx += int64(len(wire))
		l.cfg.Logger.OnBeaconResponse(BeaconResponse{
			BeaconID: meta.BeaconID, At: l.cfg.Now(), Sequence: seqTx,
			Length: len(wire), Latency: lat, Status: status,
		})
		exchanges++

		// HTTP/1.1 keep-alive — loop until peer closes or hits caps.
		if req.Close {
			end("conn_close_header")
			return
		}
	}
}

func (l *Listener) serveRaw(c net.Conn, meta BeaconMeta) {
	buf := make([]byte, 16*1024)
	var (
		rx, tx    int64
		exchanges int
		seqRx     int
		seqTx     int
	)
	end := func(reason string) {
		l.cfg.Logger.OnBeaconEnd(BeaconEnd{
			BeaconID: meta.BeaconID, EndedAt: l.cfg.Now(),
			Duration:    l.cfg.Now().Sub(meta.StartedAt),
			BytesRecv:   rx,
			BytesSent:   tx,
			Exchanges:   exchanges,
			CloseReason: reason,
		})
	}
	for {
		n, err := c.Read(buf)
		if n > 0 {
			seqRx++
			rx += int64(n)
			payload := buf[:n]
			encoded, isText, sha := classifyAndEncode(payload)
			l.cfg.Logger.OnBeaconData(BeaconData{
				BeaconID: meta.BeaconID, At: l.cfg.Now(), Sequence: seqRx,
				Length: n, Payload: encoded, IsText: isText, Sha256: sha,
			})

			lat := randDur(l.cfg.Rand, l.cfg.LatencyMin, l.cfg.LatencyMax)
			l.cfg.Sleep(lat)

			// Echo a small ACK — keeps C2 framing happy.
			resp := buildRawAck(payload)
			wn, werr := c.Write(resp)
			if werr == nil {
				seqTx++
				tx += int64(wn)
				l.cfg.Logger.OnBeaconResponse(BeaconResponse{
					BeaconID: meta.BeaconID, At: l.cfg.Now(), Sequence: seqTx,
					Length: wn, Latency: lat,
				})
				exchanges++
			}
			if rx > l.cfg.MaxBytesPerConnection {
				end("max_bytes")
				return
			}
		}
		if err != nil {
			if err == io.EOF {
				end("peer_closed")
				return
			}
			end("read_error:" + err.Error())
			return
		}
	}
}

// buildRawAck returns a small ACK echo. Most custom C2 framing
// expects something back to acknowledge the message; mirroring the
// first 4 bytes is a cheap heuristic.
func buildRawAck(in []byte) []byte {
	if len(in) >= 4 {
		out := make([]byte, 4)
		copy(out, in[:4])
		return out
	}
	return []byte{0x00, 0x00}
}

// --- helpers ---

func randDur(r *mrand.Rand, lo, hi time.Duration) time.Duration {
	if hi <= lo {
		return lo
	}
	return lo + time.Duration(r.Int63n(int64(hi-lo)))
}

func randBeaconID(r *mrand.Rand) string {
	const alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
	if r == nil {
		r = mrand.New(mrand.NewSource(time.Now().UnixNano()))
	}
	b := make([]byte, 16)
	for i := range b {
		b[i] = alpha[r.Intn(len(alpha))]
	}
	return string(b)
}

// generateSelfSigned mints a self-signed cert. TLS handshake
// will succeed for any SNI — attacker malware that doesn't pin
// certs happily completes the handshake. Cert is in-memory only.
//
// P-RF.9g L3: CN + DNSName are randomized from a list of
// plausible cloud / CDN wildcards instead of the fixed "*" they
// used to be. Static "*" was a fingerprint a sophisticated
// attacker could use to identify the xhelix sinkhole; rotating
// among real-world-looking CNs blends into typical TLS noise.
func generateSelfSigned() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return tls.Certificate{}, err
	}
	cn := pickPlausibleCN()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, nil
}

// pickPlausibleCN returns a randomized cloud/CDN wildcard string.
// Each sinkhole instance picks one at startup so the cert blends
// in with typical TLS noise rather than being a fingerprint.
var plausibleCNs = []string{
	"*.cloudfront.net",
	"*.appspot.com",
	"*.amazonaws.com",
	"*.azureedge.net",
	"*.fastly.net",
	"*.akamaiedge.net",
	"*.cdn.cloudflare.net",
	"*.googleusercontent.com",
}

func pickPlausibleCN() string {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(plausibleCNs))))
	if err != nil {
		return plausibleCNs[0]
	}
	return plausibleCNs[n.Int64()]
}

// HTTP request reading helper kept short — uses the package-level
// parseHTTPRequest from responses.go.
var _ = http.MethodGet
