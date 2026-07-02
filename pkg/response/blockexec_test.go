package response

import (
	"sync/atomic"
	"testing"

	"github.com/xhelix/xhelix/pkg/model"
)

func blockExecAlert() model.Alert {
	return model.Alert{
		RuleID: "dropped_binary_lifecycle",
		Event:  model.Event{PID: 4242, Image: "/tmp/loader"},
	}
}

// TestBlockExec_FiresWhenEnforced verifies ActionBlockExec calls the injected
// deny hook with the offending binary path.
func TestBlockExec_FiresWhenEnforced(t *testing.T) {
	var got atomic.Value // string
	e := New(Config{
		Policy:    Policy{"dropped_binary_lifecycle": ActionLog | ActionBlockExec},
		BlockExec: func(path string) error { got.Store(path); return nil },
	})
	e.OnAlert(blockExecAlert())
	if p, _ := got.Load().(string); p != "/tmp/loader" {
		t.Errorf("deny path = %q, want /tmp/loader", p)
	}
	if e.stats.blockExec.Load() != 1 {
		t.Errorf("blockExec stat = %d, want 1", e.stats.blockExec.Load())
	}
}

// TestBlockExec_StrippedInMonitorMode verifies the action is observe-only unless
// the rule is promoted via enforce_rules — the safe default on a live box.
func TestBlockExec_StrippedInMonitorMode(t *testing.T) {
	var called atomic.Bool
	e := New(Config{
		Policy:      Policy{"dropped_binary_lifecycle": ActionLog | ActionBlockExec},
		BlockExec:   func(string) error { called.Store(true); return nil },
		MonitorMode: true, // no enforce_rules → stripped
	})
	e.OnAlert(blockExecAlert())
	if called.Load() {
		t.Error("block-exec must be stripped in monitor mode without enforce_rules")
	}

	// Promote the rule → it fires even in monitor mode.
	called.Store(false)
	e2 := New(Config{
		Policy:       Policy{"dropped_binary_lifecycle": ActionLog | ActionBlockExec},
		BlockExec:    func(string) error { called.Store(true); return nil },
		MonitorMode:  true,
		EnforceRules: []string{"dropped_binary_lifecycle"},
	})
	e2.OnAlert(blockExecAlert())
	if !called.Load() {
		t.Error("promoted rule must fire block-exec even in monitor mode")
	}
}

// TestBlockExec_NoLoaderIsSafeNoop verifies a nil deny hook (BPF-LSM off) does
// not panic and counts as dropped.
func TestBlockExec_NoLoaderIsSafeNoop(t *testing.T) {
	e := New(Config{
		Policy: Policy{"dropped_binary_lifecycle": ActionLog | ActionBlockExec},
		// BlockExec nil
	})
	e.OnAlert(blockExecAlert()) // must not panic
	if e.stats.blockExec.Load() != 0 {
		t.Errorf("blockExec stat = %d, want 0 (no loader)", e.stats.blockExec.Load())
	}
}
