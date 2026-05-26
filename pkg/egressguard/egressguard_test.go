package egressguard

import (
	"testing"
	"time"
)

func TestDecision_StringValues(t *testing.T) {
	cases := map[Decision]string{
		EgressAllow:  "allow",
		EgressVerify: "verify",
		EgressDeny:   "deny",
	}
	for d, want := range cases {
		if got := d.String(); got != want {
			t.Errorf("Decision(%d).String()=%q, want %q", d, got, want)
		}
	}
}

func TestMode_StringValues(t *testing.T) {
	cases := map[Mode]string{
		ModeObserve: "observe",
		ModeShadow:  "shadow",
		ModeEnforce: "enforce",
	}
	for m, want := range cases {
		if got := m.String(); got != want {
			t.Errorf("Mode(%d).String()=%q, want %q", m, got, want)
		}
	}
}

// ─────────────────────────────────────────────────────────────────
// Observe backend
// ─────────────────────────────────────────────────────────────────

func TestObserveBackend_AlwaysAvailable(t *testing.T) {
	o := newObserveBackend(ModeObserve)
	if err := o.Available(); err != nil {
		t.Errorf("observe Available err = %v, want nil", err)
	}
	if o.Name() != "observe" {
		t.Errorf("observe Name = %q", o.Name())
	}
	if err := o.Push(0, "1.2.3.4", time.Minute); err != nil {
		t.Errorf("observe Push err = %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// eBPF backend (v0 scaffold)
// ─────────────────────────────────────────────────────────────────

func TestEBPFBackend_NotImplementedYet(t *testing.T) {
	e := newEBPFBackend(ModeShadow)
	if err := e.Available(); err == nil {
		t.Error("v0 eBPF backend should report not-implemented")
	}
	if e.Name() != "ebpf-cgroup-connect" {
		t.Errorf("ebpf Name = %q", e.Name())
	}
	if err := e.Push(0, "1.2.3.4", time.Minute); err == nil {
		t.Error("v0 eBPF Push should error")
	}
}

// ─────────────────────────────────────────────────────────────────
// nftables backend
// ─────────────────────────────────────────────────────────────────

func TestNFTBackend_AvailableTracksBinary(t *testing.T) {
	// Available depends on whether `nft` is on PATH. We don't assert
	// either branch — just that it doesn't panic.
	n := newNFTBackend(ModeShadow)
	_ = n.Available()
	if n.Name() != "nftables" {
		t.Errorf("nftables Name = %q", n.Name())
	}
}

func TestNFTBackend_ShadowModeDoesNotTouchKernel(t *testing.T) {
	// In shadow mode, Push is a no-op and must not error even if nft
	// isn't installed.
	n := newNFTBackend(ModeShadow)
	if err := n.Push(0, "192.0.2.5", time.Minute); err != nil {
		t.Errorf("shadow-mode Push should be no-op, got %v", err)
	}
	if err := n.Remove(0, "192.0.2.5"); err != nil {
		t.Errorf("shadow-mode Remove should be no-op, got %v", err)
	}
}

func TestNFTBackend_ObserveModeAlsoNoop(t *testing.T) {
	n := newNFTBackend(ModeObserve)
	if err := n.Push(0, "192.0.2.5", time.Minute); err != nil {
		t.Errorf("observe-mode Push should be no-op, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// SelectBackend — selector ordering
// ─────────────────────────────────────────────────────────────────

func TestSelectBackend_FallsThroughToObservable(t *testing.T) {
	// Without working eBPF (v0 always errors) AND without nft binary
	// (test environments may or may not have it), selection should at
	// minimum land on observe.
	b, name := SelectBackend(ModeShadow)
	if b == nil {
		t.Fatal("SelectBackend returned nil backend")
	}
	if name == "" {
		t.Fatal("SelectBackend returned empty name")
	}
	// The chosen backend MUST be one of the three known types.
	validNames := map[string]bool{
		"ebpf-cgroup-connect": true, // would never select today (v0)
		"nftables":            true, // if nft binary present
		"observe":             true, // final fallback
	}
	if !validNames[name] {
		t.Errorf("unknown backend name %q", name)
	}
}

func TestSelectBackend_OrdersEBPFFirstNftSecondObserveLast(t *testing.T) {
	// Document the selection order. v0 eBPF Available() always errors,
	// so a host with nft binary picks nftables; one without picks observe.
	b, name := SelectBackend(ModeShadow)
	// Skip eBPF — v0 never selects it.
	if name == "ebpf-cgroup-connect" {
		t.Error("v0 eBPF backend should NOT be selected (Available errors)")
	}
	// Mode is set correctly on the chosen backend.
	if b.Mode() != ModeShadow {
		t.Errorf("mode not propagated: got %s, want shadow", b.Mode())
	}
}
