//go:build !linux

package dpi

import (
	"context"
	"errors"

	"github.com/xhelix/xhelix/pkg/connstate"
)

type impl struct{}

func newImpl() impl { return impl{} }

func (impl) start(_ context.Context, _ Config, _ *connstate.Table) error {
	return errors.New("dpi sensor: linux-only")
}

func (impl) stop() error    { return nil }
func (impl) health() error  { return errors.New("dpi sensor: linux-only") }
