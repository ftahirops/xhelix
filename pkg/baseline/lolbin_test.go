package baseline

import (
	"testing"
	"time"
)

func TestIsLOLBin(t *testing.T) {
	if !IsLOLBin("curl") {
		t.Error("curl should be a LOLBin")
	}
	if IsLOLBin("nginx") {
		t.Error("nginx should not be a LOLBin")
	}
}

func TestObserveDuringWarmupNeverAlerts(t *testing.T) {
	l := New(7)
	now := time.Now()
	if l.Observe("/usr/sbin/nginx", "bash", now) {
		t.Error("should not alert during warmup")
	}
	if l.Observe("/usr/sbin/nginx", "curl", now) {
		t.Error("should not alert during warmup")
	}
}

func TestObserveAfterWarmupFlagsFirstTime(t *testing.T) {
	l := New(7)
	now := time.Now()
	// Learn that nginx → bash is normal
	l.Observe("/usr/sbin/nginx", "bash", now)
	l.Observe("/usr/sbin/nginx", "bash", now.Add(time.Minute))

	l.SetWarmupComplete()

	// Already-known child: not anomalous
	if l.Observe("/usr/sbin/nginx", "bash", now.Add(time.Hour)) {
		t.Error("known child should not be anomalous")
	}
	// New child: anomalous
	if !l.Observe("/usr/sbin/nginx", "curl", now.Add(time.Hour)) {
		t.Error("first-seen child after warmup should be anomalous")
	}
	// Same new child a second time: now learned
	if l.Observe("/usr/sbin/nginx", "curl", now.Add(2*time.Hour)) {
		t.Error("second invocation should no longer be anomalous")
	}
}

func TestIsUnusualReportsWithoutMutating(t *testing.T) {
	l := New(7)
	l.SetWarmupComplete()

	if !l.IsUnusual("/usr/sbin/nginx", "bash") {
		t.Error("never-seen parent should be unusual")
	}
	// Calling IsUnusual must not record anything
	snap := l.Snapshot()
	if len(snap) != 0 {
		t.Errorf("snapshot len = %d, want 0", len(snap))
	}
}

func TestNonLOLBinNeverFlagged(t *testing.T) {
	l := New(7)
	l.SetWarmupComplete()
	if l.Observe("/usr/sbin/nginx", "nginx-worker", time.Now()) {
		t.Error("non-LOLBin should never be anomalous")
	}
}
