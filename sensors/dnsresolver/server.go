package dnsresolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Server is a transparent UDP DNS forwarder that observes every
// query and answer crossing it.
//
// Design constraints:
//   - net stdlib only (no miekg/dns dependency)
//   - never break the client: if upstream times out, we still emit
//     the Query observation (with no answers) so xhelix learns the
//     qname even on resolver failures
//   - pid attribution happens through the Collector — Server just
//     hands off Observation{Query, Answer} pairs to it
//
// The Server intentionally does not bind privileged port 53 by
// default. Operators that want full-host DNS interception point
// /etc/resolv.conf or systemd-resolved at the chosen Server.Addr
// (typically 127.0.0.53:53 with CAP_NET_BIND_SERVICE, or
// 127.0.0.1:5353 unprivileged).
type Server struct {
	// Addr is the UDP listen address, e.g. "127.0.0.53:53" or
	// "127.0.0.1:5353". Required.
	Addr string

	// Upstream is the forward target, e.g. "1.1.1.1:53". Required.
	Upstream string

	// Collector is invoked for every observed exchange.
	Collector *Collector

	// ReadTimeout caps client→server idle time. <=0 selects 5s.
	ReadTimeout time.Duration

	// UpstreamTimeout caps upstream→server response wait. <=0 selects 2s.
	UpstreamTimeout time.Duration

	conn     *net.UDPConn
	wg       sync.WaitGroup
	running  atomic.Bool
	queries  atomic.Uint64
	answers  atomic.Uint64
	dropped  atomic.Uint64 // upstream timeouts / errors
}

// Start binds the UDP socket and begins forwarding. Returns an
// error if bind fails. Stop releases the socket.
func (s *Server) Start(ctx context.Context) error {
	if s.Addr == "" || s.Upstream == "" {
		return errors.New("dnsresolver: Addr and Upstream required")
	}
	if s.Collector == nil {
		return errors.New("dnsresolver: Collector required")
	}
	addr, err := net.ResolveUDPAddr("udp", s.Addr)
	if err != nil {
		return fmt.Errorf("resolve addr: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.conn = conn
	s.running.Store(true)

	if s.ReadTimeout <= 0 {
		s.ReadTimeout = 5 * time.Second
	}
	if s.UpstreamTimeout <= 0 {
		s.UpstreamTimeout = 2 * time.Second
	}

	s.wg.Add(1)
	go s.serveLoop(ctx)
	return nil
}

// Stop closes the listening socket and waits for the serve
// goroutine to exit.
func (s *Server) Stop() error {
	if !s.running.CompareAndSwap(true, false) {
		return nil
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.wg.Wait()
	return nil
}

// Stats returns current operational counters.
func (s *Server) Stats() (queries, answers, dropped uint64) {
	return s.queries.Load(), s.answers.Load(), s.dropped.Load()
}

// LocalAddr returns the bound address. Useful for tests that bind :0.
func (s *Server) LocalAddr() *net.UDPAddr {
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr().(*net.UDPAddr)
}

func (s *Server) serveLoop(ctx context.Context) {
	defer s.wg.Done()
	buf := make([]byte, 64*1024) // max DNS UDP message
	for {
		if !s.running.Load() {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = s.conn.SetReadDeadline(time.Now().Add(s.ReadTimeout))
		n, clientAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return // socket closed
		}
		// Copy out — buf will be reused.
		q := make([]byte, n)
		copy(q, buf[:n])
		s.wg.Add(1)
		go func(query []byte, client *net.UDPAddr) {
			defer s.wg.Done()
			s.handleQuery(query, client)
		}(q, clientAddr)
	}
}

// handleQuery forwards one query to upstream, returns the response
// (or an empty body) to the client, and emits an Observation.
func (s *Server) handleQuery(query []byte, client *net.UDPAddr) {
	s.queries.Add(1)
	now := time.Now()

	// Parse query for the qname/qtype so we emit something even
	// if upstream fails.
	qInfo, _ := parseMessage(query)
	obs := Observation{
		Query: Query{
			At:       now,
			QName:    qInfo.QName,
			QType:    qInfo.QType,
			SrcPort:  uint16(client.Port),
			Upstream: s.Upstream,
		},
	}

	// Forward to upstream.
	resp, ok := s.askUpstream(query)
	if ok {
		s.answers.Add(1)
		respInfo, _ := parseMessage(resp)
		obs.Answer = Answer{
			IPs: respInfo.IPs,
			TTL: time.Duration(respInfo.TTL) * time.Second,
		}
		// Write response back to client. Best-effort.
		_, _ = s.conn.WriteToUDP(resp, client)
	} else {
		s.dropped.Add(1)
	}

	if s.Collector != nil {
		_ = s.Collector.Observe(obs)
	}
}

// askUpstream sends query to s.Upstream and returns the reply.
func (s *Server) askUpstream(query []byte) ([]byte, bool) {
	upConn, err := net.DialTimeout("udp", s.Upstream, s.UpstreamTimeout)
	if err != nil {
		return nil, false
	}
	defer upConn.Close()
	_ = upConn.SetDeadline(time.Now().Add(s.UpstreamTimeout))
	if _, err := upConn.Write(query); err != nil {
		return nil, false
	}
	buf := make([]byte, 64*1024)
	n, err := upConn.Read(buf)
	if err != nil {
		return nil, false
	}
	return buf[:n], true
}
