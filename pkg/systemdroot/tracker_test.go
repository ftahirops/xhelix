package systemdroot

import "testing"

func TestTracker_GetPut(t *testing.T) {
	tr := New()
	if _, ok := tr.Get("mysql.service"); ok {
		t.Fatal("unseen unit must not be cached")
	}
	tr.Put("mysql.service", 42)
	id, ok := tr.Get("mysql.service")
	if !ok || id != 42 {
		t.Errorf("Get after Put = (%d,%v), want (42,true)", id, ok)
	}
	// distinct units are independent
	if _, ok := tr.Get("redis.service"); ok {
		t.Error("redis.service should be independent of mysql.service")
	}
}

func TestIsServiceUnit(t *testing.T) {
	cases := map[string]bool{
		"mysql.service":          true,
		"php8.2-fpm.service":     true,
		"snapd.service":          true,
		"":                       false,
		"user.slice":             false,
		"session-3.scope":        false,
		"user@1000.service":      false, // per-user manager = interactive/admin
		"run-r9f3.service":       false, // transient scaffolding
		"-.mount":                false,
		"system.slice":           false,
	}
	for unit, want := range cases {
		if got := IsServiceUnit(unit); got != want {
			t.Errorf("IsServiceUnit(%q) = %v, want %v", unit, got, want)
		}
	}
}
