package trustzone

import (
	"path/filepath"
	"sync"
	"testing"
)

func u32p(v uint32) *uint32 { return &v }

func TestLookup_DefaultLabel(t *testing.T) {
	m := New("/nonexistent", LabelTrusted)
	if got := m.Lookup(Subject{UID: 1000}); got != LabelTrusted {
		t.Fatalf("default label: got %q want %q", got, LabelTrusted)
	}
}

func TestLookup_Selectors(t *testing.T) {
	m := New("/nonexistent", LabelTrusted)
	m.assignments = []Assignment{
		{UID: u32p(1001), Label: LabelUntrusted},
		{CGroupUnit: "user@1000.service", Label: LabelRestricted},
		{CGroupClass: "container", Label: LabelRestricted},
		{Comm: "tor-browser", Label: LabelTorOnly},
	}
	cases := []struct {
		name string
		sub  Subject
		want Label
	}{
		{"uid match", Subject{UID: 1001}, LabelUntrusted},
		{"uid miss", Subject{UID: 1002}, LabelTrusted},
		{"cgroup_unit match", Subject{CGroupUnit: "user@1000.service"}, LabelRestricted},
		{"cgroup_class match", Subject{CGroupClass: "container"}, LabelRestricted},
		{"comm match", Subject{Comm: "tor-browser"}, LabelTorOnly},
		{"no match", Subject{UID: 7, Comm: "bash"}, LabelTrusted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := m.Lookup(c.sub); got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestLookup_FirstMatchWins(t *testing.T) {
	m := New("/nonexistent", LabelTrusted)
	m.assignments = []Assignment{
		{UID: u32p(1000), Label: LabelRestricted},
		{UID: u32p(1000), Label: LabelUntrusted},
	}
	if got := m.Lookup(Subject{UID: 1000}); got != LabelRestricted {
		t.Fatalf("first-match-wins: got %q want %q", got, LabelRestricted)
	}
}

func TestLookup_EmptyAssignmentNeverMatches(t *testing.T) {
	m := New("/nonexistent", LabelTrusted)
	m.assignments = []Assignment{
		{Label: LabelUntrusted}, // no selectors set
	}
	if got := m.Lookup(Subject{UID: 999}); got != LabelTrusted {
		t.Fatalf("empty-assignment must not match all: got %q", got)
	}
}

func TestPersistRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trustzones.yaml")
	m := New(path, LabelTrusted)
	if err := m.Add(Assignment{UID: u32p(1001), Label: LabelUntrusted, Comment: "untrusted dev account"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := m.Add(Assignment{Comm: "tor-browser", Label: LabelTorOnly}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := m.SetDefault(LabelRestricted); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}

	m2 := New(path, LabelTrusted)
	n, err := m2.Reload()
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if n != 2 {
		t.Fatalf("Reload count: got %d want 2", n)
	}
	if got := m2.Default(); got != LabelRestricted {
		t.Fatalf("default after reload: %q want %q", got, LabelRestricted)
	}
	all := m2.All()
	if all[0].UID == nil || *all[0].UID != 1001 {
		t.Fatalf("first assignment uid mismatch: %+v", all[0])
	}
	if all[1].Comm != "tor-browser" || all[1].Label != LabelTorOnly {
		t.Fatalf("second assignment mismatch: %+v", all[1])
	}
}

func TestRemove(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trustzones.yaml")
	m := New(path, LabelTrusted)
	_ = m.Add(Assignment{UID: u32p(1), Label: LabelUntrusted})
	_ = m.Add(Assignment{UID: u32p(2), Label: LabelRestricted})
	if err := m.Remove(0); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	all := m.All()
	if len(all) != 1 || all[0].UID == nil || *all[0].UID != 2 {
		t.Fatalf("after remove: %+v", all)
	}
	if err := m.Remove(5); err == nil {
		t.Fatalf("Remove out-of-range should error")
	}
}

func TestConcurrentLookupSafety(t *testing.T) {
	m := New("/nonexistent", LabelTrusted)
	m.assignments = []Assignment{
		{UID: u32p(1000), Label: LabelRestricted},
		{UID: u32p(1001), Label: LabelUntrusted},
	}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = m.Lookup(Subject{UID: uint32(1000 + (i % 3))})
		}(i)
	}
	wg.Wait()
}

func TestNilManagerLookup(t *testing.T) {
	var m *Manager
	if got := m.Lookup(Subject{UID: 1}); got != LabelTrusted {
		t.Fatalf("nil mgr lookup: %q", got)
	}
	if got := m.Default(); got != LabelTrusted {
		t.Fatalf("nil mgr default: %q", got)
	}
	if got := m.All(); got != nil {
		t.Fatalf("nil mgr All: %v", got)
	}
}
