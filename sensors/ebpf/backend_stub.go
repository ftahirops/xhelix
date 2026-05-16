//go:build !linux

package ebpf

import (
	"context"

	"github.com/xhelix/xhelix/pkg/model"
)

// stubBackend is the no-op backend used on non-Linux platforms.
type stubBackend struct{ cfg Config }

func newPlatformBackend(cfg Config) Backend { return &stubBackend{cfg: cfg} }

func (s *stubBackend) Start(ctx context.Context, out chan<- model.Event) error { return nil }
func (s *stubBackend) Stop(ctx context.Context) error                          { return nil }
func (s *stubBackend) Healthy() bool                                           { return true }
func (s *stubBackend) Drops() uint64                                           { return 0 }
