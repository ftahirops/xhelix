//go:build !linux

package crashloop

import (
	"context"
	"errors"
)

// UnitWatch — see Linux build.
type UnitWatch struct {
	UnitName    string
	ServiceName string
	LineageID   uint64
}

// SystemdPoller stub for non-Linux builds.
type SystemdPoller struct {
	Units         []UnitWatch
	Interval      interface{} // unused
	Wire          *Wire
	SystemctlPath string
}

func (p *SystemdPoller) Start(_ context.Context) error {
	return errors.New("crashloop: SystemdPoller is Linux-only")
}

func (p *SystemdPoller) Stop() {}

// SystemctlHalter stub.
func SystemctlHalter(_ string) Halter {
	return HalterFunc(func(_, _ string, _ *Decision) error {
		return errors.New("crashloop: SystemctlHalter is Linux-only")
	})
}
