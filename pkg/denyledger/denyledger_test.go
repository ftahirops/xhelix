package denyledger

import (
	"testing"
	"time"
)

func TestLedger_RecordAndAppHealth(t *testing.T) {
	l := New()
	now := time.Now()

	// Nothing recorded yet — AppHealth returns nil.
	if l.AppHealth("wordpress") != nil {
		t.Error("expected nil for unknown app")
	}

	l.Record("wordpress", "/bin/sh", "redzone_exec_sh", "/system.slice/php-fpm.service", "web worker exec denied", now)
	l.Record("wordpress", "/usr/bin/curl", "redzone_exec_curl", "/system.slice/php-fpm.service", "web worker exec denied", now.Add(time.Second))
	l.Record("wordpress", "/bin/sh", "redzone_exec_sh", "/system.slice/php-fpm.service", "web worker exec denied", now.Add(2*time.Second))

	h := l.AppHealth("wordpress")
	if h == nil {
		t.Fatal("AppHealth returned nil after recording")
	}
	if h.TotalDenies != 3 {
		t.Errorf("TotalDenies = %d, want 3", h.TotalDenies)
	}
	if h.ByRule["redzone_exec_sh"] != 2 {
		t.Errorf("ByRule[redzone_exec_sh] = %d, want 2", h.ByRule["redzone_exec_sh"])
	}
	if h.ByRule["redzone_exec_curl"] != 1 {
		t.Errorf("ByRule[redzone_exec_curl] = %d, want 1", h.ByRule["redzone_exec_curl"])
	}
	if h.ByBinary["sh"] != 2 {
		t.Errorf("ByBinary[sh] = %d, want 2 (base name)", h.ByBinary["sh"])
	}
	if h.Status != "active" {
		t.Errorf("Status = %q, want active", h.Status)
	}
	// Recent: newest first
	if len(h.Recent) != 3 {
		t.Errorf("len(Recent) = %d, want 3", len(h.Recent))
	}
	if h.Recent[0].Binary != "sh" {
		t.Errorf("Recent[0].Binary = %q, want sh", h.Recent[0].Binary)
	}
}

func TestLedger_StatusClean(t *testing.T) {
	l := New()
	// No records → AppHealth nil, not clean status exposed
	h := l.AppHealth("app")
	if h != nil {
		t.Error("expected nil for never-seen app")
	}
}

func TestLedger_StatusNoisy(t *testing.T) {
	l := New()
	now := time.Now()
	for i := 0; i < 50; i++ {
		l.Record("myapp", "/bin/sh", "redzone_exec_sh", "/x", "denied", now)
	}
	h := l.AppHealth("myapp")
	if h.Status != "noisy" {
		t.Errorf("Status = %q, want noisy after 50 denies", h.Status)
	}
}

func TestLedger_RingCap(t *testing.T) {
	l := New()
	l.maxRecent = 5
	now := time.Now()
	for i := 0; i < 20; i++ {
		l.Record("app", "/bin/sh", "rule", "/x", "denied", now)
	}
	h := l.AppHealth("app")
	if len(h.Recent) != 5 {
		t.Errorf("ring cap: len(Recent) = %d, want 5", len(h.Recent))
	}
}

func TestLedger_UnknownApp(t *testing.T) {
	l := New()
	l.Record("", "/bin/sh", "rule", "/x", "denied", time.Now())
	h := l.AppHealth("_unknown")
	if h == nil || h.TotalDenies != 1 {
		t.Error("empty appName should land in _unknown bucket")
	}
}

func TestLedger_AllApps(t *testing.T) {
	l := New()
	now := time.Now()
	l.Record("app1", "/bin/sh", "r1", "", "denied", now)
	l.Record("app2", "/bin/sh", "r1", "", "denied", now)
	l.Record("app1", "/bin/sh", "r2", "", "denied", now)

	all := l.AllApps()
	counts := make(map[string]uint64)
	for _, s := range all {
		counts[s.AppName] = s.TotalDenies
	}
	if counts["app1"] != 2 {
		t.Errorf("app1 total = %d, want 2", counts["app1"])
	}
	if counts["app2"] != 1 {
		t.Errorf("app2 total = %d, want 1", counts["app2"])
	}
	// AllApps should not populate Recent (save allocations)
	for _, s := range all {
		if s.Recent != nil {
			t.Errorf("AllApps should return nil Recent, got %v for %s", s.Recent, s.AppName)
		}
	}
}

func TestBinaryBase(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/usr/sbin/php-fpm8.2", "php-fpm8.2"},
		{"/bin/sh", "sh"},
		{"node", "node"},
		{"", ""},
		{"/", ""},
	}
	for _, c := range cases {
		if got := binaryBase(c.in); got != c.want {
			t.Errorf("binaryBase(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
