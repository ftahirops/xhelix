package baselinegate

import "testing"

func TestDecide_UnknownAlwaysFires(t *testing.T) {
	g := New(Policy{SuppressKnown: true})
	if g.Decide("any_rule", false) != ActionFire {
		t.Errorf("unknown baseline must fire")
	}
}

func TestDecide_NilGateFires(t *testing.T) {
	var g *Gate
	if g.Decide("x", true) != ActionFire {
		t.Errorf("nil gate must fire (no-op)")
	}
}

func TestDecide_KnownSuppressed(t *testing.T) {
	g := New(Policy{SuppressKnown: true})
	if g.Decide("memfd_run_pattern", true) != ActionSuppress {
		t.Errorf("known + SuppressKnown should suppress")
	}
}

func TestDecide_KnownDowngraded(t *testing.T) {
	g := New(Policy{SuppressKnown: false, DowngradeKnown: true})
	if g.Decide("memfd_run_pattern", true) != ActionDowngrade {
		t.Errorf("known + DowngradeKnown should downgrade")
	}
}

func TestDecide_AlwaysFire(t *testing.T) {
	g := New(Policy{SuppressKnown: true})
	// brp.hard_deny is on the default AlwaysFire list — should fire
	// even when baseline_known is true.
	if g.Decide("brp.hard_deny", true) != ActionFire {
		t.Errorf("AlwaysFire rule must fire regardless of baseline")
	}
	if g.Decide("revshell.detected", true) != ActionFire {
		t.Errorf("revshell.detected must always fire")
	}
	if g.Decide("metadata.access_by_unexpected", true) != ActionFire {
		t.Errorf("metadata access must always fire")
	}
}

func TestDecide_CustomAlwaysFire(t *testing.T) {
	g := New(Policy{
		SuppressKnown: true,
		AlwaysFire:    map[string]struct{}{"my_rule": {}},
	})
	if g.Decide("my_rule", true) != ActionFire {
		t.Errorf("custom AlwaysFire entry must fire")
	}
	// And other rules still get suppressed (default list is NOT used
	// when caller provides one).
	if g.Decide("brp.hard_deny", true) != ActionSuppress {
		t.Errorf("custom AlwaysFire replaces default; brp.hard_deny should suppress")
	}
}

func TestSnapshot_CountsIndependent(t *testing.T) {
	g := New(Policy{SuppressKnown: true})
	g.RecordSuppress("a")
	g.RecordSuppress("a")
	g.RecordSuppress("b")
	g.RecordDowngrade("c")
	snap := g.Snapshot()
	if snap.Suppressed["a"] != 2 || snap.Suppressed["b"] != 1 {
		t.Errorf("suppressed counts wrong: %+v", snap.Suppressed)
	}
	if snap.Downgraded["c"] != 1 {
		t.Errorf("downgraded counts wrong: %+v", snap.Downgraded)
	}
	// Snapshot is a copy — mutating it must not affect the gate.
	snap.Suppressed["a"] = 999
	snap2 := g.Snapshot()
	if snap2.Suppressed["a"] != 2 {
		t.Errorf("Snapshot was not a copy: %d", snap2.Suppressed["a"])
	}
}
