package dnspoison

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Logger receives forensic events. JSONLLogger satisfies it.
type Logger interface {
	OnPoisoned(e PoisonEvent)
	OnPassthrough(e PassthroughEvent)
}

// PoisonEvent — a query we resolved to the sinkhole IP.
type PoisonEvent struct {
	At        time.Time `json:"at"`
	Peer      string    `json:"peer"`
	Name      string    `json:"name"`
	QType     uint16    `json:"qtype"`
	Match     MatchKind `json:"match"`
	SinkIP    string    `json:"sink_ip"`
	BytesIn   int       `json:"bytes_in"`
	BytesOut  int       `json:"bytes_out"`
}

// PassthroughEvent — a query we forwarded upstream. Logged at INFO
// volume (~one per real DNS lookup) so callers may choose to drop
// these from the chain to save space.
type PassthroughEvent struct {
	At        time.Time     `json:"at"`
	Peer      string        `json:"peer"`
	Name      string        `json:"name"`
	QType     uint16        `json:"qtype"`
	BytesIn   int           `json:"bytes_in"`
	BytesOut  int           `json:"bytes_out"`
	Upstream  string        `json:"upstream"`
	Latency   time.Duration `json:"latency"`
	Forwarded bool          `json:"forwarded"`
}

// Config tunes the server.
type Config struct {
	UDPAddr  string // ":53" by default; tests use ":0"
	TCPAddr  string // TCP is optional; pass "" to skip
	Upstream string // upstream resolver "1.1.1.1:53"; pass "" to refuse pass-through

	// SinkIP is the address poisoned A queries resolve to. Defaults
	// to 127.0.0.1 — for production this should be the sinkhole
	// listener's bound IP.
	SinkIP net.IP

	// AnswerTTL — how long poisoned answers live in the client
	// resolver cache. Short by default (60s) so a list update
	// reaches victims quickly. Long enough to avoid hammering us.
	AnswerTTL uint32

	// LogPassthrough controls whether each forwarded query emits a
	// PassthroughEvent. Defaults false — most operators don't want
	// the volume.
	LogPassthrough bool

	Classifier *Classifier
	Logger     Logger

	// Test hooks.
	Now func() time.Time
}

func (c *Config) defaulted() Config {
	d := *c
	if d.UDPAddr == "" {
		d.UDPAddr = "127.0.0.1:53"
	}
	if d.SinkIP == nil {
		d.SinkIP = net.IPv4(127, 0, 0, 1)
	}
	if d.AnswerTTL == 0 {
		d.AnswerTTL = 60
	}
	if d.Classifier == nil {
		d.Classifier = NewClassifier()
	}
	if d.Logger == nil {
		d.Logger = noopLogger{}
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return d
}

// Server is the DNS shim.
type Server struct {
	cfg Config

	mu      sync.Mutex
	udpConn *net.UDPConn
	tcpLn   net.Listener
	doneC   chan struct{}
	wg      sync.WaitGroup
	sinkV4  [4]byte
}

// New returns a Server ready to Start.
func New(c Config) (*Server, error) {
	d := c.defaulted()
	ip4 := d.SinkIP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("dnspoison: SinkIP %v is not IPv4", d.SinkIP)
	}
	return &Server{
		cfg:    d,
		doneC:  make(chan struct{}),
		sinkV4: [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]},
	}, nil
}

// Start binds UDP (and TCP if configured) and begins serving.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.udpConn != nil {
		return errors.New("dnspoison: already started")
	}

	udpAddr, err := net.ResolveUDPAddr("udp", s.cfg.UDPAddr)
	if err != nil {
		return fmt.Errorf("dnspoison: resolve UDP %s: %w", s.cfg.UDPAddr, err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("dnspoison: listen UDP %s: %w", s.cfg.UDPAddr, err)
	}
	s.udpConn = conn
	s.wg.Add(1)
	go s.udpLoop(conn)

	if s.cfg.TCPAddr != "" {
		ln, err := net.Listen("tcp", s.cfg.TCPAddr)
		if err != nil {
			_ = conn.Close()
			s.udpConn = nil
			return fmt.Errorf("dnspoison: listen TCP %s: %w", s.cfg.TCPAddr, err)
		}
		s.tcpLn = ln
		s.wg.Add(1)
		go s.tcpLoop(ln)
	}
	return nil
}

// UDPAddr returns the actually-bound UDP address.
func (s *Server) UDPAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.udpConn == nil {
		return nil
	}
	return s.udpConn.LocalAddr()
}

// Stop closes listeners and waits for in-flight handlers. Idempotent.
func (s *Server) Stop() {
	s.mu.Lock()
	if s.udpConn != nil {
		_ = s.udpConn.Close()
		s.udpConn = nil
	}
	if s.tcpLn != nil {
		_ = s.tcpLn.Close()
		s.tcpLn = nil
	}
	select {
	case <-s.doneC:
	default:
		close(s.doneC)
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Server) udpLoop(conn *net.UDPConn) {
	defer s.wg.Done()
	buf := make([]byte, 1500) // standard MTU; DNS queries fit easily
	for {
		n, peer, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		q := make([]byte, n)
		copy(q, buf[:n])
		s.wg.Add(1)
		go func(query []byte, peer *net.UDPAddr) {
			defer s.wg.Done()
			s.handleUDP(conn, query, peer)
		}(q, peer)
	}
}

func (s *Server) handleUDP(conn *net.UDPConn, query []byte, peer *net.UDPAddr) {
	resp, ev, isPoison := s.respond(query, peer.String())
	if resp != nil {
		_, _ = conn.WriteToUDP(resp, peer)
	}
	s.emit(ev, isPoison)
}

func (s *Server) tcpLoop(ln net.Listener) {
	defer s.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer c.Close()
			s.handleTCP(c)
		}(c)
	}
}

func (s *Server) handleTCP(c net.Conn) {
	// TCP DNS: 2-byte length prefix, then the query.
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(c, lenBuf); err != nil {
		return
	}
	n := int(lenBuf[0])<<8 | int(lenBuf[1])
	if n == 0 || n > 65535 {
		return
	}
	query := make([]byte, n)
	if _, err := io.ReadFull(c, query); err != nil {
		return
	}
	resp, ev, isPoison := s.respond(query, c.RemoteAddr().String())
	if resp != nil {
		out := make([]byte, 2+len(resp))
		out[0] = byte(len(resp) >> 8)
		out[1] = byte(len(resp))
		copy(out[2:], resp)
		_, _ = c.Write(out)
	}
	s.emit(ev, isPoison)
}

// respond decides whether to poison or forward, builds the response,
// and returns the bytes + the forensic event.
func (s *Server) respond(query []byte, peer string) ([]byte, interface{}, bool) {
	msg, err := parseQuery(query)
	if err != nil {
		// Malformed query — emit NXDOMAIN-ish empty response when
		// possible, otherwise drop. No forensic event for malformed.
		return nil, nil, false
	}
	name := msg.question.String()

	kind := s.cfg.Classifier.Classify(name)
	if kind != MatchNone {
		return s.poison(query, name, msg, kind, peer)
	}
	return s.passthrough(query, name, msg, peer)
}

func (s *Server) poison(query []byte, name string, msg *message, kind MatchKind, peer string) ([]byte, interface{}, bool) {
	// We only synthesise A records. For AAAA / CNAME / TXT etc we
	// return NXDOMAIN — attacker's resolver falls back, retries the
	// A query, and we poison that. Net effect: attacker still ends
	// up on the sinkhole IP.
	var (
		resp []byte
		err  error
	)
	const qtypeA = 1
	if msg.qtype == qtypeA {
		resp, err = encodeAResponse(query, s.sinkV4, s.cfg.AnswerTTL)
	} else {
		resp, err = encodeNXDomain(query)
	}
	if err != nil {
		return nil, nil, false
	}
	ev := PoisonEvent{
		At:       s.cfg.Now(),
		Peer:     peer,
		Name:     name,
		QType:    msg.qtype,
		Match:    kind,
		SinkIP:   s.cfg.SinkIP.String(),
		BytesIn:  len(query),
		BytesOut: len(resp),
	}
	return resp, ev, true
}

func (s *Server) passthrough(query []byte, name string, msg *message, peer string) ([]byte, interface{}, bool) {
	if s.cfg.Upstream == "" {
		// No upstream configured — refuse rather than guess.
		resp, _ := encodeNXDomain(query)
		ev := PassthroughEvent{
			At:    s.cfg.Now(),
			Peer:  peer,
			Name:  name,
			QType: msg.qtype,
			BytesIn: len(query),
			BytesOut: len(resp),
			Forwarded: false,
		}
		return resp, ev, false
	}

	start := s.cfg.Now()
	resp, err := forwardUDP(s.cfg.Upstream, query)
	lat := s.cfg.Now().Sub(start)
	if err != nil {
		// Best-effort fallback: empty NXDOMAIN.
		resp, _ = encodeNXDomain(query)
	}
	ev := PassthroughEvent{
		At:        s.cfg.Now(),
		Peer:      peer,
		Name:      name,
		QType:     msg.qtype,
		BytesIn:   len(query),
		BytesOut:  len(resp),
		Upstream:  s.cfg.Upstream,
		Latency:   lat,
		Forwarded: err == nil,
	}
	if !s.cfg.LogPassthrough {
		// Sentinel — caller filters via the Logger interface.
		ev.Name = ""
	}
	return resp, ev, false
}

func (s *Server) emit(ev interface{}, isPoison bool) {
	if ev == nil {
		return
	}
	if isPoison {
		s.cfg.Logger.OnPoisoned(ev.(PoisonEvent))
		return
	}
	pe := ev.(PassthroughEvent)
	if pe.Name == "" {
		// LogPassthrough was off — drop.
		return
	}
	s.cfg.Logger.OnPassthrough(pe)
}

// forwardUDP relays a DNS query to an upstream resolver and returns
// the response bytes. Synchronous; deadline-bounded.
func forwardUDP(upstream string, query []byte) ([]byte, error) {
	c, err := net.Dial("udp", upstream)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out, nil
}

// --- logger helpers ---

type noopLogger struct{}

func (noopLogger) OnPoisoned(PoisonEvent)        {}
func (noopLogger) OnPassthrough(PassthroughEvent) {}

// JSONLLogger writes one JSON object per event to w.
type JSONLLogger struct {
	mu sync.Mutex
	w  io.Writer
}

func NewJSONLLogger(w io.Writer) *JSONLLogger { return &JSONLLogger{w: w} }

type wireRec struct {
	Type string      `json:"type"`
	Body interface{} `json:"body"`
}

func (l *JSONLLogger) emit(typ string, body interface{}) {
	b, err := json.Marshal(wireRec{Type: typ, Body: body})
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(append(b, '\n'))
}

func (l *JSONLLogger) OnPoisoned(e PoisonEvent)        { l.emit("dns_poison", e) }
func (l *JSONLLogger) OnPassthrough(e PassthroughEvent) { l.emit("dns_passthrough", e) }
