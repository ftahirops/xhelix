//go:build !linux

package bpflsm

import (
	"fmt"
	"log/slog"
)

// loadAndAttach is a no-op stub on non-Linux. xhelix doesn't run
// BPF-LSM on non-Linux at runtime; this keeps `go build` green.
func loadAndAttach(_ string, _ Mode, _ *slog.Logger) (*Loader, error) {
	return nil, fmt.Errorf("bpflsm: not supported on non-Linux")
}
