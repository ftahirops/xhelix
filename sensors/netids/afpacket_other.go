//go:build !linux

package netids

import (
	"context"
	"errors"
)

// AFPacketCapture is a no-op stub off Linux so the package still
// compiles for cross-builds.
type AFPacketCapture struct{}

// PacketFn is invoked per packet on supported platforms; here it is
// unused.
type PacketFn func(data []byte)

// NewAFPacket returns a stub.
func NewAFPacket(iface string) *AFPacketCapture { return &AFPacketCapture{} }

// Start always returns an error on non-Linux.
func (a *AFPacketCapture) Start(_ context.Context, _ PacketFn) error {
	return errors.New("afpacket: linux only")
}

// Stop is a no-op.
func (a *AFPacketCapture) Stop(_ context.Context) error { return nil }

// Stats type for cross-platform compile.
type Stats struct{ Frames, Bytes, Dropped uint64 }

func (a *AFPacketCapture) Stats() Stats { return Stats{} }
