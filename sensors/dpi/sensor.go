// Package dpi (sensor) sniffs TLS handshakes off the host's network
// interfaces and attaches the SNI to the matching connstate flow.
//
// Implementation strategy: AF_PACKET RX-only socket on each
// non-loopback interface, with a kernel BPF filter that selects only
// TCP packets carrying a TLS handshake (record type 0x16) in the
// first byte of payload. Userspace parses the ClientHello and calls
// connstate.AttachSNI on the matching tuple.
//
// Linux-only. On other GOOS the package returns a no-op sensor.
// Requires CAP_NET_RAW at runtime. The Start path gracefully
// degrades to a no-op if AF_PACKET socket creation is denied.
package dpi

import (
	"context"
	"log/slog"

	"github.com/xhelix/xhelix/pkg/connstate"
)

// Config tunes the sensor.
type Config struct {
	// Interfaces lists names to listen on. Empty = pick all
	// non-loopback up-state interfaces at start.
	Interfaces []string

	// MaxBytes caps the slice passed to the parser. 1024 is plenty
	// for any sane ClientHello; larger wastes memory per packet.
	MaxBytes int

	Logger *slog.Logger
}

// Sensor is the public handle. Use New + Start + Stop.
type Sensor struct {
	cfg     Config
	connTab *connstate.Table
	impl    impl
}

// New returns a Sensor. The actual capture backend is wired in
// sniffer_<goos>.go; on non-Linux the backend is a no-op.
func New(cfg Config, tab *connstate.Table) *Sensor {
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = 1024
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Sensor{cfg: cfg, connTab: tab, impl: newImpl()}
}

// Name satisfies sensors.Sensor.
func (s *Sensor) Name() string { return "dpi" }

// Start opens the sniffer. If CAP_NET_RAW is missing or the kernel
// refuses, Start returns the error; callers should log-and-continue
// — xhelix never refuses to start over one optional sensor.
func (s *Sensor) Start(ctx context.Context) error {
	return s.impl.start(ctx, s.cfg, s.connTab)
}

// Stop halts the sniffer goroutines.
func (s *Sensor) Stop() error { return s.impl.stop() }

// Health returns nil when the sniffer is running.
func (s *Sensor) Health() error { return s.impl.health() }
