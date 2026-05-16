package decoy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/sensors"
)

// HoneyService is one fake TCP listener.
type HoneyService struct {
	Persona string // "redis" | "mysql" | "postgres" | "mongo" | "ssh-internal" | "http-admin"
	Bind    string // "127.0.0.1:6379" — localhost-only by default
}

// ServicesSensor stands up honey listeners for the duration of the
// agent's run. Every accepted connection produces a Critical event.
type ServicesSensor struct {
	services []HoneyService
	host     string

	mu      sync.Mutex
	out     chan<- model.Event
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	running atomic.Bool
	hits    map[string]uint64
	addrs   []string
}

// NewServicesSensor constructs a sensor.
func NewServicesSensor(svcs []HoneyService, host string) *ServicesSensor {
	return &ServicesSensor{services: svcs, host: host, hits: map[string]uint64{}}
}

// Name implements sensors.Sensor.
func (s *ServicesSensor) Name() string { return "decoy.services" }

// Start opens every listener; ports already in use are skipped with
// a warning event so configuration mistakes don't take the agent
// down.
func (s *ServicesSensor) Start(parent context.Context, out chan<- model.Event) error {
	if !s.running.CompareAndSwap(false, true) {
		return errors.New("services: already started")
	}
	s.mu.Lock()
	s.out = out
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	s.mu.Unlock()

	for _, svc := range s.services {
		ln, err := net.Listen("tcp", svc.Bind)
		if err != nil {
			s.emitConflict(svc, err)
			continue
		}
		s.mu.Lock()
		s.addrs = append(s.addrs, ln.Addr().String())
		s.mu.Unlock()

		s.wg.Add(1)
		go s.serve(ctx, ln, svc)
	}
	return nil
}

// Stop closes every listener and waits for accept loops.
func (s *ServicesSensor) Stop(ctx context.Context) error {
	if !s.running.CompareAndSwap(true, false) {
		return nil
	}
	if s.cancel != nil {
		s.cancel()
	}
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Health implements sensors.Sensor.
func (s *ServicesSensor) Health() sensors.Health {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sensors.Health{Healthy: s.running.Load()}
}

// Addrs returns the listener addresses, useful for tests that need
// to dial the sensor.
func (s *ServicesSensor) Addrs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.addrs))
	copy(out, s.addrs)
	return out
}

// Hits returns the per-persona connection counter.
func (s *ServicesSensor) Hits() map[string]uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]uint64, len(s.hits))
	for k, v := range s.hits {
		out[k] = v
	}
	return out
}

func (s *ServicesSensor) serve(ctx context.Context, ln net.Listener, svc HoneyService) {
	defer s.wg.Done()
	defer ln.Close()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c, svc)
	}
}

func (s *ServicesSensor) handle(c net.Conn, svc HoneyService) {
	defer c.Close()
	src := c.RemoteAddr().String()

	// Capture the first request bytes as a fingerprint, with a
	// short timeout so a slow/silent client doesn't pin a goroutine.
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, _ := c.Read(buf)

	s.mu.Lock()
	s.hits[svc.Persona]++
	s.mu.Unlock()

	ev := model.NewEvent("decoy", model.SeverityCritical)
	ev.Host = s.host
	ev.Tags["honey_service_connect"] = "true"
	ev.Tags["persona"] = svc.Persona
	ev.Tags["src"] = src
	ev.Tags["first_bytes"] = hex.EncodeToString(buf[:n])
	if s.out != nil {
		select {
		case s.out <- ev:
		case <-time.After(50 * time.Millisecond):
		}
	}

	_, _ = c.Write(banner(svc.Persona))
}

func (s *ServicesSensor) emitConflict(svc HoneyService, err error) {
	ev := model.NewEvent("decoy.services", model.SeverityWarn)
	ev.Host = s.host
	ev.Tags["error"] = err.Error()
	ev.Tags["persona"] = svc.Persona
	ev.Tags["bind"] = svc.Bind
	if s.out != nil {
		select {
		case s.out <- ev:
		default:
		}
	}
}

// banner returns a persona-specific first response.
func banner(persona string) []byte {
	switch persona {
	case "redis":
		return []byte("-NOAUTH Authentication required.\r\n")
	case "mysql":
		// Minimal MySQL handshake (5.7 emulation).
		return []byte("\x4a\x00\x00\x00\x0a5.7.42-honey\x00" +
			"\x01\x02\x03\x04abcdefgh\x00")
	case "postgres":
		return []byte("E\x00\x00\x00\x53FATAL\x00C28000\x00" +
			"Mauthentication failed for user \"unknown\"\x00\x00")
	case "mongo":
		return []byte{0x00, 0x00, 0x00, 0x00}
	case "ssh-internal":
		return []byte("SSH-2.0-OpenSSH_8.4p1 Honey-internal\r\n")
	case "http-admin":
		return []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
			"<html><body><h1>Internal admin</h1></body></html>")
	}
	return []byte("\r\n")
}

// NewID returns a fresh 16-byte hex token for canary-token use.
func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
