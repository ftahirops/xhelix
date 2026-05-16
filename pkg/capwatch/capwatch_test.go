package capwatch

import "testing"

func TestNoChangeReturnsNone(t *testing.T) {
	f := Classify(Change{EffectiveBefore: 0xff, EffectiveAfter: 0xff})
	if f.Severity != SeverityNone {
		t.Fatalf("severity = %s", f.Severity)
	}
}

func TestGainSysAdminIsCritical(t *testing.T) {
	f := Classify(Change{EffectiveAfter: 1 << CAP_SYS_ADMIN})
	if f.Severity != SeverityCritical {
		t.Fatalf("severity = %s", f.Severity)
	}
	if len(f.Gained) != 1 || f.Gained[0] != "CAP_SYS_ADMIN" {
		t.Fatalf("gained = %v", f.Gained)
	}
}

func TestGainBPFIsHigh(t *testing.T) {
	f := Classify(Change{EffectiveAfter: 1 << CAP_BPF})
	if f.Severity != SeverityHigh {
		t.Fatalf("severity = %s", f.Severity)
	}
}

func TestGainNetBindIsWarn(t *testing.T) {
	f := Classify(Change{EffectiveAfter: 1 << CAP_NET_BIND_SERVICE})
	if f.Severity != SeverityWarn {
		t.Fatalf("severity = %s", f.Severity)
	}
}

func TestDropOnlyNoSeverity(t *testing.T) {
	f := Classify(Change{
		EffectiveBefore: 1 << CAP_NET_ADMIN,
		EffectiveAfter:  0,
	})
	if f.Severity != SeverityNone {
		t.Fatalf("severity = %s; dropping caps should not raise", f.Severity)
	}
	if len(f.Dropped) != 1 || f.Dropped[0] != "CAP_NET_ADMIN" {
		t.Fatalf("dropped = %v", f.Dropped)
	}
}

func TestMixedGainAndDrop(t *testing.T) {
	f := Classify(Change{
		EffectiveBefore: 1 << CAP_NET_ADMIN,
		EffectiveAfter:  1 << CAP_SYS_ADMIN, // dropped NET_ADMIN, gained SYS_ADMIN
	})
	if f.Severity != SeverityCritical {
		t.Fatalf("severity = %s", f.Severity)
	}
	if len(f.Gained) != 1 || len(f.Dropped) != 1 {
		t.Fatalf("gained=%v dropped=%v", f.Gained, f.Dropped)
	}
}

func TestUnknownBitFormatted(t *testing.T) {
	// bit 62 — unlikely to exist; should appear as CAP_62.
	f := Classify(Change{EffectiveAfter: 1 << 62})
	if len(f.Gained) != 1 || f.Gained[0] != "CAP_62" {
		t.Fatalf("gained = %v", f.Gained)
	}
}

func TestWorstSeverityWinsAcrossManyCaps(t *testing.T) {
	mask := uint64(1)<<CAP_CHOWN | uint64(1)<<CAP_NET_ADMIN | uint64(1)<<CAP_SYS_ADMIN
	f := Classify(Change{EffectiveAfter: mask})
	if f.Severity != SeverityCritical {
		t.Fatalf("severity = %s", f.Severity)
	}
	if len(f.Gained) != 3 {
		t.Fatalf("gained count = %d", len(f.Gained))
	}
}

func TestHasHelper(t *testing.T) {
	m := uint64(1) << CAP_SYS_ADMIN
	if !Has(m, CAP_SYS_ADMIN) {
		t.Fatal("Has should be true")
	}
	if Has(m, CAP_BPF) {
		t.Fatal("Has should be false")
	}
}

func TestCapNamesStable(t *testing.T) {
	for b, want := range map[int]string{
		CAP_SYS_ADMIN: "CAP_SYS_ADMIN",
		CAP_BPF:       "CAP_BPF",
		CAP_CHOWN:     "CAP_CHOWN",
		CAP_NET_RAW:   "CAP_NET_RAW",
	} {
		if got := capName(b); got != want {
			t.Errorf("capName(%d) = %q, want %q", b, got, want)
		}
	}
}

func TestZeroToZeroEmpty(t *testing.T) {
	f := Classify(Change{})
	if f.Severity != SeverityNone || len(f.Gained) != 0 || len(f.Dropped) != 0 {
		t.Fatalf("expected fully empty Finding; got %+v", f)
	}
}
