// Package sensors defines the contract every observation source
// must satisfy, plus the Phase-0 reference heartbeat sensor.
//
// Phase-1+ sensors (eBPF, FIM, decoys, NetIDS, identity, memory) all
// implement Sensor and emit normalised model.Event values.
package sensors

import (
	"context"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

// Sensor is the interface every observation source implements.
//
// Start must be idempotent and return promptly; long-running work
// goes in a goroutine that exits when ctx is cancelled. Stop must
// also be idempotent and complete within a few seconds.
type Sensor interface {
	Name() string
	Start(ctx context.Context, out chan<- model.Event) error
	Stop(ctx context.Context) error
	Health() Health
}

// Health describes a sensor's current operational state.
type Health struct {
	Healthy   bool
	Reason    string
	DropCount uint64
	LastEvent time.Time
}
