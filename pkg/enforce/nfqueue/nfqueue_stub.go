//go:build !linux

package nfqueue

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"
)

type Proto uint8

const (
	ProtoUnknown Proto = 0
	ProtoTCP     Proto = 6
	ProtoUDP     Proto = 17
)

func (p Proto) String() string { return "unknown" }

type Packet struct{}
type Verdict uint8

const (
	VerdictAccept Verdict = 0
	VerdictDrop   Verdict = 1
	VerdictRepeat Verdict = 2
)

type VerdictFn func(ctx context.Context, p Packet) Verdict

type Config struct {
	QueueNum     uint16
	MaxPacketLen uint32
	Deadline     time.Duration
	Logger       *slog.Logger
}

type Stats struct {
	Enqueued, Accepted, Dropped, Failed, TimedOut, NotParsed atomic.Uint64
}

type Manager struct{}

func New(_ Config, _ VerdictFn) *Manager  { return &Manager{} }
func (*Manager) Start(_ context.Context) error { return errors.New("nfqueue: linux-only") }
func (*Manager) Stop()                       {}
func (*Manager) StatsSnapshot() map[string]uint64 { return map[string]uint64{} }
