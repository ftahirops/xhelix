package kintegrity

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"
)

func TestHashKallsyms(t *testing.T) {
	if _, err := os.Stat("/proc/kallsyms"); err != nil {
		t.Skip("no /proc/kallsyms")
	}
	h1, n1, err := hashKallsyms()
	if err != nil {
		t.Fatal(err)
	}
	if n1 == 0 {
		t.Error("got 0 symbols")
	}
	h2, n2, _ := hashKallsyms()
	if h1 != h2 || n1 != n2 {
		t.Error("hash not stable across reads")
	}
}

func TestModulesRead(t *testing.T) {
	if _, err := os.Stat("/proc/modules"); err != nil {
		t.Skip("no /proc/modules")
	}
	m, err := readModules()
	if err != nil {
		t.Fatal(err)
	}
	// Modules can be empty on some minimal kernels; just confirm no error.
	t.Logf("modules: %d", len(m))
}

func TestDiffStrings(t *testing.T) {
	a := []string{"a", "b", "c"}
	b := []string{"b", "c", "d"}
	added, removed := diffStrings(a, b)
	if len(added) != 1 || added[0] != "d" {
		t.Errorf("added = %v", added)
	}
	if len(removed) != 1 || removed[0] != "a" {
		t.Errorf("removed = %v", removed)
	}
}

func TestStartCaptureBaseline(t *testing.T) {
	if _, err := os.Stat("/proc/kallsyms"); err != nil {
		t.Skip("no /proc/kallsyms")
	}
	var mu sync.Mutex
	var fires int
	c := New(Config{
		Interval: 10 * time.Millisecond,
		OnAlert: func(_ string, _ map[string]string) {
			mu.Lock()
			fires++
			mu.Unlock()
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	time.Sleep(50 * time.Millisecond)
	// On a stable system there should be no drift.
	mu.Lock()
	defer mu.Unlock()
	if fires != 0 {
		t.Errorf("unexpected drift alerts: %d", fires)
	}
	st := c.Stats()
	if st.KallsymsCount == 0 {
		t.Error("baseline kallsyms count = 0")
	}
}
