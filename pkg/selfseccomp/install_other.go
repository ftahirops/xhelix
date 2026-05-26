//go:build !linux

package selfseccomp

import (
	"fmt"
	"log/slog"
)

// installForHost is a no-op on non-Linux platforms. xhelix is
// Linux-only at runtime.
func installForHost(_ AllowList, _ *slog.Logger) error {
	return fmt.Errorf("selfseccomp: not supported on non-Linux")
}
