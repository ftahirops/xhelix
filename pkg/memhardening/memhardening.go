// Package memhardening applies Go-runtime memory hardening to the
// daemon: a memory ceiling (GOMEMLIMIT-equivalent) that triggers GC
// rather than OOM, an explicit GC target, and a SecretBytes wrapper
// that zeroes sensitive memory on release.
//
// Why this exists (Phase G.4):
//   hardened_malloc is a libc allocator delivered via LD_PRELOAD.
//   xhelix is CGO_ENABLED=0 — every allocation goes through Go's
//   runtime allocator, not libc malloc. LD_PRELOAD would do nothing
//   for us. The equivalent intent (cap blast radius of memory bugs +
//   wipe secrets) is delivered through the Go runtime knobs below.
//
// Honest non-promise: Go is already memory-safe in the use-after-
// free / heap-overflow sense. This package does not pretend to add
// hardened_malloc's guard-page semantics. What it gives you is a
// hard memory ceiling, an aggressive GC, and explicit secret-wipe
// for credential material we choose to wrap.
package memhardening

import (
	"log/slog"
	"runtime"
	"runtime/debug"
)

// Config is the operator-facing knob set.
type Config struct {
	// MemoryLimitMB is a Go soft memory limit (SetMemoryLimit). 0 = don't
	// set (recommended default).
	//
	// CRITICAL: it MUST sit comfortably ABOVE the live heap. With the geoip
	// table loaded (~1.1M CIDR entries) the live heap is ~600MB+, so a limit
	// at/below that pins the GC into continuous collection — SetMemoryLimit
	// makes the runtime GC ever harder chasing a limit it cannot reach,
	// burning ~90% CPU in gcBgMarkWorker (observed 2026-06-01: limit=512MB
	// vs live=591MB → ~3.5 cores, all GC; raising to 2048MB dropped it to
	// ~0.25 cores). If you set this at all, use >= 1536 or leave 0. See ERRORS.md.
	MemoryLimitMB int64 `yaml:"memory_limit_mb"`
	// GCPercent is the GOGC equivalent. 0 = leave default (100). Lower =
	// more frequent GC, less peak memory, MORE CPU. Do not set this low on a
	// daemon with a large stable live heap (geoip) — prefer 100-200 or 0.
	GCPercent int `yaml:"gc_percent"`
}

// Apply installs the runtime memory knobs. Safe to call once at
// daemon startup. Errors are logged but never fatal — these are
// hardening knobs, not invariants.
func Apply(cfg Config, log *slog.Logger) {
	if cfg.MemoryLimitMB > 0 {
		prev := debug.SetMemoryLimit(cfg.MemoryLimitMB * 1024 * 1024)
		if log != nil {
			log.Info("memhardening: SetMemoryLimit applied",
				"limit_mb", cfg.MemoryLimitMB,
				"previous_bytes", prev)
		}
	}
	if cfg.GCPercent > 0 {
		prev := debug.SetGCPercent(cfg.GCPercent)
		if log != nil {
			log.Info("memhardening: SetGCPercent applied",
				"gc_percent", cfg.GCPercent,
				"previous", prev)
		}
	}
}

// SecretBytes wraps a byte slice that holds secret material
// (private keys, passwords, session tokens). Call Wipe when done.
// A finalizer is registered so a leaked SecretBytes still gets
// zeroed before its memory is returned to the runtime.
//
// SecretBytes is NOT goroutine-safe; callers must serialize access.
type SecretBytes struct {
	buf []byte
}

// NewSecret allocates a SecretBytes of the given length.
func NewSecret(n int) *SecretBytes {
	s := &SecretBytes{buf: make([]byte, n)}
	runtime.SetFinalizer(s, func(s *SecretBytes) { s.Wipe() })
	return s
}

// FromBytes takes ownership of src — it COPIES into a fresh secret
// buffer and zeroes src. After return, src is all zeros.
func FromBytes(src []byte) *SecretBytes {
	s := NewSecret(len(src))
	copy(s.buf, src)
	for i := range src {
		src[i] = 0
	}
	return s
}

// Bytes returns the underlying buffer. Do NOT retain the slice past
// the SecretBytes lifetime — call Wipe before discarding.
func (s *SecretBytes) Bytes() []byte {
	if s == nil {
		return nil
	}
	return s.buf
}

// Len returns the secret length, 0 if nil or wiped.
func (s *SecretBytes) Len() int {
	if s == nil {
		return 0
	}
	return len(s.buf)
}

// Wipe zeroes the buffer in place and releases the slice header.
// Idempotent.
func (s *SecretBytes) Wipe() {
	if s == nil {
		return
	}
	for i := range s.buf {
		s.buf[i] = 0
	}
	s.buf = nil
}
