//go:build !linux

package credbroker

import (
	"context"
	"errors"
)

// FanGate stub for non-Linux builds. Real impl in fangate_linux.go.
type FanGate struct{}

type FanGateStats struct {
	EventsRx uint64
	Allowed  uint64
	Denied   uint64
	Errors   uint64
}

func NewFanGate(_ *Broker, _ interface{ Warn(string, ...any) }) (*FanGate, error) {
	return nil, errors.New("fangate: linux only (fanotify required)")
}
func (g *FanGate) Mark(_ string) error                          { return errors.New("fangate: linux only") }
func (g *FanGate) MarkSealedFilesIn(_ string) (int, []error)    { return 0, nil }
func (g *FanGate) MarkedPaths() []string                        { return nil }
func (g *FanGate) Stats() FanGateStats                          { return FanGateStats{} }
func (g *FanGate) Start(_ context.Context) error                { return errors.New("fangate: linux only") }
func (g *FanGate) Stop()                                        {}
