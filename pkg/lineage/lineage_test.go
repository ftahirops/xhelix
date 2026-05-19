package lineage

import (
	"testing"
	"time"
)

func TestChain_Extend(t *testing.T) {
	parent := Chain{1, 2}
	child := parent.Extend(3)

	// Original chain must be unchanged.
	if len(parent) != 2 || parent[0] != 1 || parent[1] != 2 {
		t.Errorf("parent mutated: %v", parent)
	}
	// Child must be parent + new ID.
	want := Chain{1, 2, 3}
	if !child.Equal(want) {
		t.Errorf("child = %v, want %v", child, want)
	}
}

func TestChain_Accessors(t *testing.T) {
	empty := Chain{}
	if empty.Innermost() != 0 {
		t.Error("empty.Innermost() != 0")
	}
	if empty.Outermost() != 0 {
		t.Error("empty.Outermost() != 0")
	}

	single := Chain{42}
	if single.Innermost() != 42 || single.Outermost() != 42 {
		t.Errorf("single chain: in=%d out=%d, want both 42",
			single.Innermost(), single.Outermost())
	}

	three := Chain{10, 20, 30}
	if three.Outermost() != 10 {
		t.Errorf("outermost = %d, want 10", three.Outermost())
	}
	if three.Innermost() != 30 {
		t.Errorf("innermost = %d, want 30", three.Innermost())
	}
}

func TestChain_Contains(t *testing.T) {
	c := Chain{100, 200, 300}
	if !c.Contains(100) {
		t.Error("should contain 100")
	}
	if !c.Contains(200) {
		t.Error("should contain 200")
	}
	if c.Contains(999) {
		t.Error("should not contain 999")
	}
	if (Chain{}).Contains(1) {
		t.Error("empty chain contains nothing")
	}
}

func TestChain_MarshalRoundtrip(t *testing.T) {
	cases := []Chain{
		nil,
		{},
		{1},
		{100, 200, 300},
		{LineageID(^uint64(0)), 0, 42}, // edge: max value (0 in middle is legal)
	}
	for i, c := range cases {
		b := c.Marshal()
		got, err := UnmarshalChain(b)
		if err != nil {
			t.Errorf("case %d: %v", i, err)
			continue
		}
		// For nil and empty: both marshal to empty bytes; unmarshal returns nil.
		if len(c) == 0 && len(got) != 0 {
			t.Errorf("case %d: empty input produced %v", i, got)
			continue
		}
		if len(c) > 0 && !c.Equal(got) {
			t.Errorf("case %d: roundtrip %v → %v", i, c, got)
		}
	}
}

func TestChain_MarshalCorruption(t *testing.T) {
	// Bytes not a multiple of 8 must error.
	_, err := UnmarshalChain([]byte{1, 2, 3, 4, 5}) // 5 bytes
	if err == nil {
		t.Error("expected error for non-multiple-of-8 length")
	}
}

func TestChain_String(t *testing.T) {
	if (Chain{}).String() != "(none)" {
		t.Error("empty chain string")
	}
	if (Chain{1}).String() != "1" {
		t.Error("single chain string")
	}
	if (Chain{10, 20, 30}).String() != "10>20>30" {
		t.Error("multi chain string")
	}
}

func TestRootType_String(t *testing.T) {
	cases := map[RootType]string{
		RootSSH:       "ssh",
		RootPAM:       "pam",
		RootCron:      "cron",
		RootSystemd:   "systemd",
		RootContainer: "container",
		RootSudo:      "sudo",
		RootWeb:       "web",
		RootLocal:     "local",
		RootKernel:    "kernel",
		RootUnknown:   "unknown",
		RootType(255): "unknown",
	}
	for typ, want := range cases {
		if got := typ.String(); got != want {
			t.Errorf("RootType(%d).String() = %q, want %q", typ, got, want)
		}
	}
}

func TestMinter_UniqueAndMonotonic(t *testing.T) {
	m := NewMinter()
	seen := make(map[LineageID]bool, 1000)
	var last LineageID
	for i := 0; i < 1000; i++ {
		id := m.New()
		if id == 0 {
			t.Errorf("iteration %d: minted ID 0", i)
		}
		if seen[id] {
			t.Errorf("iteration %d: duplicate ID %d", i, id)
		}
		if i > 0 && id <= last {
			t.Errorf("iteration %d: ID %d not greater than previous %d", i, id, last)
		}
		seen[id] = true
		last = id
	}
}

func TestMinter_ConcurrentUnique(t *testing.T) {
	m := NewMinter()
	const goroutines = 16
	const each = 1000
	idsCh := make(chan LineageID, goroutines*each)
	done := make(chan struct{})

	for g := 0; g < goroutines; g++ {
		go func() {
			for i := 0; i < each; i++ {
				idsCh <- m.New()
			}
			done <- struct{}{}
		}()
	}
	for g := 0; g < goroutines; g++ {
		<-done
	}
	close(idsCh)

	seen := make(map[LineageID]bool)
	for id := range idsCh {
		if seen[id] {
			t.Fatalf("duplicate ID %d across concurrent goroutines", id)
		}
		seen[id] = true
	}
	if len(seen) != goroutines*each {
		t.Errorf("got %d unique IDs, want %d", len(seen), goroutines*each)
	}
}

func TestStore_PutGetResolve(t *testing.T) {
	s := NewStore()
	now := time.Now()
	o1 := Origin{ID: 100, Type: RootSSH, CreatedAt: now, UserName: "alice", SourceIP: "1.2.3.4"}
	o2 := Origin{ID: 200, Type: RootSudo, CreatedAt: now, UserName: "alice", EscalatedFromUID: 1000}
	s.Put(o1)
	s.Put(o2)

	if s.Size() != 2 {
		t.Errorf("size = %d, want 2", s.Size())
	}
	got, ok := s.Get(100)
	if !ok || got.UserName != "alice" {
		t.Errorf("Get(100) = %+v, ok=%v", got, ok)
	}
	_, ok = s.Get(999)
	if ok {
		t.Error("Get(unknown) should not be ok")
	}

	origins := s.Resolve(Chain{100, 200, 999})
	if len(origins) != 2 {
		t.Errorf("Resolve returned %d origins, want 2 (999 should be skipped)", len(origins))
	}
	if origins[0].Type != RootSSH || origins[1].Type != RootSudo {
		t.Errorf("Resolve order wrong: %v", origins)
	}
}

func TestStore_PutZeroIDIgnored(t *testing.T) {
	s := NewStore()
	s.Put(Origin{ID: 0, Type: RootSSH})
	if s.Size() != 0 {
		t.Error("zero-ID Origin should be silently dropped")
	}
}

func TestStore_SweepOlderThan(t *testing.T) {
	s := NewStore()
	old := time.Now().Add(-2 * time.Hour)
	recent := time.Now().Add(-1 * time.Minute)
	s.Put(Origin{ID: 1, Type: RootSSH, CreatedAt: old})
	s.Put(Origin{ID: 2, Type: RootSSH, CreatedAt: recent})
	s.Put(Origin{ID: 3, Type: RootSSH, CreatedAt: old})

	removed := s.SweepOlderThan(time.Now().Add(-1 * time.Hour))
	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}
	if s.Size() != 1 {
		t.Errorf("size after sweep = %d, want 1", s.Size())
	}
	if _, ok := s.Get(2); !ok {
		t.Error("recent origin should survive sweep")
	}
}

func TestStore_PutAssignsCreatedAtIfZero(t *testing.T) {
	s := NewStore()
	before := time.Now()
	s.Put(Origin{ID: 1, Type: RootSSH})
	got, _ := s.Get(1)
	if got.CreatedAt.Before(before) {
		t.Error("CreatedAt should be auto-assigned to now() when zero")
	}
}

func BenchmarkMinter_New(b *testing.B) {
	m := NewMinter()
	for i := 0; i < b.N; i++ {
		_ = m.New()
	}
}

func BenchmarkChain_Extend(b *testing.B) {
	base := Chain{100, 200}
	for i := 0; i < b.N; i++ {
		_ = base.Extend(LineageID(i))
	}
}
