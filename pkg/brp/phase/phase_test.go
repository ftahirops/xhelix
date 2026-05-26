package phase

import (
	"testing"
	"time"
)

func TestTracker_BootstrapThenSteady(t *testing.T) {
	tr := NewTracker(0, 0, 0)
	t0 := time.Now()
	if got := tr.Observe(1234, t0); got != PhaseBootstrap {
		t.Errorf("first observe: got %s, want bootstrap", got)
	}
	if got := tr.Get(1234, t0.Add(30*time.Second)); got != PhaseBootstrap {
		t.Errorf("inside window: got %s, want bootstrap", got)
	}
	if got := tr.Get(1234, t0.Add(DefaultBootstrap+time.Second)); got != PhaseSteady {
		t.Errorf("after window: got %s, want steady", got)
	}
}

func TestTracker_UnknownPID(t *testing.T) {
	tr := NewTracker(0, 0, 0)
	if got := tr.Get(99, time.Now()); got != PhaseUnknown {
		t.Errorf("unknown pid: got %s, want unknown", got)
	}
	if got := tr.Observe(0, time.Now()); got != PhaseUnknown {
		t.Errorf("pid=0 must be unknown, got %s", got)
	}
}

func TestTracker_Reload(t *testing.T) {
	tr := NewTracker(0, 0, 0)
	t0 := time.Now()
	tr.Observe(7, t0)
	// Advance past bootstrap so the natural phase would be steady.
	tr.Reload(7, t0.Add(2*time.Minute))
	if got := tr.Get(7, t0.Add(2*time.Minute+1*time.Second)); got != PhaseReload {
		t.Errorf("during reload window: got %s, want reload", got)
	}
	// Past reload window → falls back to steady.
	if got := tr.Get(7, t0.Add(2*time.Minute+DefaultReloadWindow+time.Second)); got != PhaseSteady {
		t.Errorf("after reload window: got %s, want steady", got)
	}
}

func TestTracker_Degrade(t *testing.T) {
	tr := NewTracker(0, 0, 0)
	t0 := time.Now()
	tr.Observe(11, t0)
	tr.Degrade(11, t0.Add(time.Minute))
	if got := tr.Get(11, t0.Add(time.Minute+1*time.Second)); got != PhaseDegraded {
		t.Errorf("during degraded: got %s, want degraded", got)
	}
	if got := tr.Get(11, t0.Add(time.Minute+DefaultDegradedWindow+time.Second)); got != PhaseSteady {
		t.Errorf("after degraded window: got %s", got)
	}
}

func TestTracker_ReloadOnUnknownPID(t *testing.T) {
	tr := NewTracker(0, 0, 0)
	t0 := time.Now()
	tr.Reload(42, t0)
	if got := tr.Get(42, t0); got != PhaseReload {
		t.Errorf("reload on unknown pid: got %s, want reload", got)
	}
}

func TestTracker_ForgetAndSize(t *testing.T) {
	tr := NewTracker(0, 0, 0)
	t0 := time.Now()
	tr.Observe(1, t0)
	tr.Observe(2, t0)
	if tr.Size() != 2 {
		t.Errorf("size=%d, want 2", tr.Size())
	}
	tr.Forget(1)
	if tr.Size() != 1 {
		t.Errorf("after forget size=%d, want 1", tr.Size())
	}
}

func TestTracker_Sweep(t *testing.T) {
	tr := NewTracker(0, 0, 0)
	t0 := time.Now()
	tr.Observe(1, t0)
	tr.Observe(2, t0.Add(-30*time.Hour))
	tr.Observe(3, t0.Add(-10*time.Minute))
	reclaimed := tr.Sweep(t0, 24*time.Hour)
	if reclaimed != 1 {
		t.Errorf("sweep reclaimed %d, want 1", reclaimed)
	}
	if tr.Size() != 2 {
		t.Errorf("size after sweep=%d, want 2", tr.Size())
	}
}

func TestPhase_StringTokens(t *testing.T) {
	cases := []struct {
		p    Phase
		want string
	}{
		{PhaseBootstrap, "bootstrap"},
		{PhaseSteady, "steady"},
		{PhaseReload, "reload"},
		{PhaseDegraded, "degraded"},
		{PhaseUnknown, "unknown"},
	}
	for _, c := range cases {
		if got := c.p.String(); got != c.want {
			t.Errorf("Phase(%d).String()=%q, want %q", c.p, got, c.want)
		}
	}
}

func TestTracker_ObserveSignal_HUP(t *testing.T) {
	tr := NewTracker(0, 0, 0)
	t0 := time.Now()
	tr.Observe(11, t0)
	// Past bootstrap window — natural phase would be Steady.
	got := tr.ObserveSignal(11, "hup", t0.Add(2*time.Minute))
	if got != PhaseReload {
		t.Errorf("SIGHUP should transition to Reload, got %s", got)
	}
}

func TestTracker_ObserveSignal_SEGV(t *testing.T) {
	tr := NewTracker(0, 0, 0)
	t0 := time.Now()
	tr.Observe(12, t0)
	got := tr.ObserveSignal(12, "segv", t0.Add(2*time.Minute))
	if got != PhaseDegraded {
		t.Errorf("SIGSEGV should transition to Degraded, got %s", got)
	}
}

func TestTracker_ObserveSignal_Ignored(t *testing.T) {
	tr := NewTracker(0, 0, 0)
	t0 := time.Now()
	tr.Observe(13, t0)
	got := tr.ObserveSignal(13, "term", t0.Add(2*time.Minute))
	if got != PhaseSteady {
		t.Errorf("SIGTERM should not change phase, got %s", got)
	}
}

func TestTracker_ObserveRestart_WithinWindow(t *testing.T) {
	tr := NewTracker(0, 0, 0)
	t0 := time.Now()
	prevExit := t0
	newSpawn := t0.Add(5 * time.Second)
	tr.ObserveRestart(14, prevExit, newSpawn)
	if got := tr.Get(14, newSpawn.Add(time.Second)); got != PhaseDegraded {
		t.Errorf("restart within 30s should be Degraded, got %s", got)
	}
}

func TestTracker_ObserveRestart_OutsideWindow(t *testing.T) {
	tr := NewTracker(0, 0, 0)
	t0 := time.Now()
	prevExit := t0
	newSpawn := t0.Add(2 * time.Minute) // outside 30s window
	tr.ObserveRestart(15, prevExit, newSpawn)
	// No prior Observe → unknown
	if got := tr.Get(15, newSpawn); got != PhaseUnknown {
		t.Errorf("restart outside window with no prior observe: got %s", got)
	}
}

func TestTracker_CustomWindows(t *testing.T) {
	tr := NewTracker(10*time.Second, 2*time.Second, 30*time.Second)
	t0 := time.Now()
	tr.Observe(5, t0)
	if got := tr.Get(5, t0.Add(8*time.Second)); got != PhaseBootstrap {
		t.Errorf("custom bootstrap window: got %s", got)
	}
	if got := tr.Get(5, t0.Add(11*time.Second)); got != PhaseSteady {
		t.Errorf("after custom window: got %s", got)
	}
}
