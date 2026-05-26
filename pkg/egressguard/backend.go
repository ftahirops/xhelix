package egressguard

import (
	"errors"
	"fmt"
	"time"
)

// Backend is the kernel enforcement plane abstraction.
//
// Implementations:
//
//	*nftBackend  — shell-out to `nft` (always available; lower granularity)
//	*ebpfBackend — cilium/ebpf cgroup_skb hook (kernel ≥ 5.15 + CAP_BPF)
//	*observeBackend — no-op (degradation mode)
//
// Push() installs a deny rule for (cgroupID, destination) with the
// given TTL. The backend is free to ignore lineageID if it doesn't
// support per-cgroup granularity (nftables can; observe cannot).
type Backend interface {
	Name() string
	Available() error
	Push(cgroupID uint64, dest string, ttl time.Duration) error
	Remove(cgroupID uint64, dest string) error
	Mode() Mode
	SetMode(Mode)
}

// SelectBackend picks the highest-fidelity available backend.
//
// Order:
//  1. eBPF cgroup/connect — preferred
//  2. nftables — fallback
//  3. observe-only — emergency degradation
//
// Returns the chosen backend + the chosen name for logging. Never
// returns a nil backend.
func SelectBackend(mode Mode) (Backend, string) {
	candidates := []Backend{
		newEBPFBackend(mode),
		newNFTBackend(mode),
		newObserveBackend(mode),
	}
	for _, c := range candidates {
		if err := c.Available(); err == nil {
			return c, c.Name()
		}
	}
	// observeBackend never returns error from Available, so the loop
	// always picks at least it. This branch is unreachable but kept
	// for safety.
	o := newObserveBackend(mode)
	return o, o.Name()
}

// ─────────────────────────────────────────────────────────────────
// observe-only backend (no-op; never fails Available)
// ─────────────────────────────────────────────────────────────────

type observeBackend struct {
	mode Mode
}

func newObserveBackend(mode Mode) *observeBackend {
	return &observeBackend{mode: mode}
}

func (o *observeBackend) Name() string       { return "observe" }
func (o *observeBackend) Available() error   { return nil }
func (o *observeBackend) Mode() Mode         { return o.mode }
func (o *observeBackend) SetMode(m Mode)     { o.mode = m }

func (o *observeBackend) Push(cgroup uint64, dest string, ttl time.Duration) error {
	// no-op
	return nil
}

func (o *observeBackend) Remove(cgroup uint64, dest string) error {
	return nil
}

// ─────────────────────────────────────────────────────────────────
// eBPF cgroup/connect-family backend
// ─────────────────────────────────────────────────────────────────
//
// Status (2026-05-26): SCAFFOLD ONLY. The C program + cilium/ebpf
// loader is multi-day kernel work (per Phase C.1 spec §3.3 "primary
// backend"). v0 of this package ships the scaffold + capability probe
// so the selector returns "unavailable" and falls back to nftables.
// The full implementation lands in a focused C.1 follow-on session.

type ebpfBackend struct {
	mode Mode
}

func newEBPFBackend(mode Mode) *ebpfBackend {
	return &ebpfBackend{mode: mode}
}

func (e *ebpfBackend) Name() string   { return "ebpf-cgroup-connect" }
func (e *ebpfBackend) Mode() Mode     { return e.mode }
func (e *ebpfBackend) SetMode(m Mode) { e.mode = m }

// Available probes for eBPF cgroup/connect capability. Returns an error
// describing why eBPF isn't usable on this host. Returns nil when ready.
//
// v0 always returns ErrEBPFNotImplemented — the C program loader is
// the multi-day follow-on. Capability probing (kernel version, CAP_BPF,
// cgroup_v2 mount) will be added when the loader lands.
func (e *ebpfBackend) Available() error {
	return ErrEBPFNotImplemented
}

func (e *ebpfBackend) Push(cgroup uint64, dest string, ttl time.Duration) error {
	return ErrEBPFNotImplemented
}

func (e *ebpfBackend) Remove(cgroup uint64, dest string) error {
	return ErrEBPFNotImplemented
}

// ErrEBPFNotImplemented is returned by the v0 eBPF backend probe. When
// the cilium/ebpf loader + C program land in a follow-on session, this
// error disappears and the eBPF path takes over from nftables.
var ErrEBPFNotImplemented = errors.New("egressguard: eBPF backend not yet implemented (cilium/ebpf cgroup_connect loader pending; nftables fallback active)")

// ─────────────────────────────────────────────────────────────────
// nftables backend (functional)
// ─────────────────────────────────────────────────────────────────
//
// Uses shell-out to `nft` binary (same pattern as pkg/netban). Creates
// a dedicated table + chain for egressguard so the rules don't collide
// with other xhelix nftables work.
//
// Table: inet xhelix_egress
// Chain: xhelix_egress_out (hook output priority 0 policy accept)
// Set:   xhelix_egress_deny_v4 (type ipv4_addr; flags timeout)
// Set:   xhelix_egress_deny_v6 (type ipv6_addr; flags timeout)
//
// Rule on chain: ip daddr @xhelix_egress_deny_v4 drop
//                ip6 daddr @xhelix_egress_deny_v6 drop
//
// Per-cgroup granularity is NOT implemented in v0 — denies are global
// per-host. A future enhancement can use `meta cgroup` matching with
// the cgroup numeric ID (Linux ≥ 4.10). Per-cgroup is documented as
// the next step.

type nftBackend struct {
	mode Mode
}

func newNFTBackend(mode Mode) *nftBackend {
	return &nftBackend{mode: mode}
}

func (n *nftBackend) Name() string   { return "nftables" }
func (n *nftBackend) Mode() Mode     { return n.mode }
func (n *nftBackend) SetMode(m Mode) { n.mode = m }

// Available probes for nft binary + ability to create the table. v0
// returns the binary-existence check; full provisioning happens when
// ensureNFTTable is called (separate from Available so the selector
// doesn't side-effect just by probing).
func (n *nftBackend) Available() error {
	if !nftBinaryAvailable() {
		return errors.New("egressguard nftables: nft binary not on PATH")
	}
	return nil
}

func (n *nftBackend) Push(cgroup uint64, dest string, ttl time.Duration) error {
	if n.mode == ModeObserve || n.mode == ModeShadow {
		// Don't touch kernel state in shadow mode; caller logs.
		return nil
	}
	// Ensure table+chain+set exist. Idempotent.
	if err := ensureNFTTable(); err != nil {
		return fmt.Errorf("egressguard nft ensure: %w", err)
	}
	return nftAddDeny(dest, ttl)
}

func (n *nftBackend) Remove(cgroup uint64, dest string) error {
	if n.mode == ModeObserve || n.mode == ModeShadow {
		return nil
	}
	return nftDelDeny(dest)
}
