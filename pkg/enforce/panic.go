package enforce

import (
	"os"
	"path/filepath"
	"sync/atomic"
)

// PanicSwitch is the kill switch.
//
// Two states are surfaced:
//   - in-process atomic bool (read by every userspace enforcement
//     decision)
//   - on-disk file at PinPath (read by external operators when the
//     daemon is unhealthy; mirrored to the pinned BPF map by Phase 1+
//     loader so kernel-side enforcement also sees it)
//
// Setting the flag is one-way at runtime — operators who change
// their mind restart the agent with the file removed.
type PanicSwitch struct {
	PinPath string

	armed atomic.Bool
}

// NewPanicSwitch builds a switch backed by the given file path.
//
// pinPath == "" picks the design-doc default at
// /sys/fs/bpf/xhelix/xh_panic. On hosts without bpf-fs the path is
// just a regular file.
func NewPanicSwitch(pinPath string) *PanicSwitch {
	if pinPath == "" {
		pinPath = "/sys/fs/bpf/xhelix/xh_panic"
	}
	p := &PanicSwitch{PinPath: pinPath}
	if _, err := os.Stat(pinPath); err == nil {
		p.armed.Store(true)
	}
	return p
}

// Armed returns true when enforcement is suspended.
func (p *PanicSwitch) Armed() bool { return p.armed.Load() }

// Arm flips the switch — every enforcement decision short-circuits
// to "no action".
//
// The file write is best-effort; even if the bpf-fs is unavailable,
// the in-process bool flips immediately so userspace enforcement
// stops without delay. Kernel-side LSM hooks need the BPF map flag,
// which Phase 1 loader writes to PinPath when armed.
func (p *PanicSwitch) Arm() error {
	p.armed.Store(true)
	if err := os.MkdirAll(filepath.Dir(p.PinPath), 0o750); err != nil {
		return err
	}
	return os.WriteFile(p.PinPath, []byte{1}, 0o600)
}

// Disarm clears the switch. Operators normally do this only after a
// full restart with the underlying issue understood — but we expose
// it so it can be undone by mistake.
func (p *PanicSwitch) Disarm() error {
	p.armed.Store(false)
	if err := os.Remove(p.PinPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
