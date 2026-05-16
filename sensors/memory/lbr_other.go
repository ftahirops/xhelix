//go:build !linux

package memory

import "context"

// LBRSampler is a stub off Linux.
type LBRSampler struct{}

// LBRAnomaly cross-platform stub.
type LBRAnomaly struct {
	PID      uint32
	Branches uint64
	Reason   string
}

// NewLBRSampler returns a stub.
func NewLBRSampler(_ uint64) *LBRSampler { return &LBRSampler{} }

// Start is a no-op.
func (l *LBRSampler) Start(_ context.Context, _ func(LBRAnomaly)) error { return nil }

// Stop is a no-op.
func (l *LBRSampler) Stop(_ context.Context) error { return nil }

// SampleCount returns 0.
func (l *LBRSampler) SampleCount() uint64 { return 0 }

// Dropped returns 0.
func (l *LBRSampler) Dropped() uint64 { return 0 }

// LBRSupported reports false off Linux.
func LBRSupported() bool { return false }
