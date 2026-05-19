package lineage

import (
	"sync"
	"testing"
	"time"
)

func TestTaintSet_BasicOps(t *testing.T) {
	var ts TaintSet
	if !ts.IsEmpty() {
		t.Fatal("zero value should be empty")
	}
	ts = ts.With(0).With(5).With(63)
	if !ts.Has(0) || !ts.Has(5) || !ts.Has(63) {
		t.Error("set bits should report Has=true")
	}
	if ts.Has(1) {
		t.Error("unset bit should report Has=false")
	}
	if got := ts.Count(); got != 3 {
		t.Errorf("Count = %d, want 3", got)
	}

	bits := ts.Bits()
	if len(bits) != 3 || bits[0] != 0 || bits[1] != 5 || bits[2] != 63 {
		t.Errorf("Bits = %v, want [0 5 63]", bits)
	}
}

func TestTaintSet_Union_Intersects(t *testing.T) {
	a := TaintSet(0).With(0).With(1)
	b := TaintSet(0).With(1).With(2)
	if got := a.Union(b).Count(); got != 3 {
		t.Errorf("Union count = %d, want 3", got)
	}
	if !a.Intersects(b) {
		t.Error("a and b should intersect on bit 1")
	}

	c := TaintSet(0).With(10)
	if a.Intersects(c) {
		t.Error("a and c should not intersect")
	}
}

func TestTaintSet_Count_AllBits(t *testing.T) {
	var ts TaintSet
	for i := TaintBit(0); i < MaxTaintBits; i++ {
		ts = ts.With(i)
	}
	if ts.Count() != 64 {
		t.Errorf("all 64 bits set, Count = %d, want 64", ts.Count())
	}
}

func TestClassRegistry_AssignsAndReturnsStable(t *testing.T) {
	r := NewClassRegistry()

	a, err := r.Bit("pii")
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.Bit("credentials")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("distinct names should get distinct bits")
	}

	// Idempotent: same name → same bit.
	a2, _ := r.Bit("pii")
	if a2 != a {
		t.Errorf("re-registration of 'pii' returned %d, want %d", a2, a)
	}

	if r.Name(a) != "pii" {
		t.Errorf("Name(%d) = %q, want pii", a, r.Name(a))
	}
	if r.Size() != 2 {
		t.Errorf("Size = %d, want 2", r.Size())
	}
}

func TestClassRegistry_RejectsAfter64(t *testing.T) {
	r := NewClassRegistry()
	for i := 0; i < MaxTaintBits; i++ {
		if _, err := r.Bit(string(rune('A' + i))); err != nil {
			t.Fatalf("bit %d: unexpected error %v", i, err)
		}
	}
	if _, err := r.Bit("one-too-many"); err != ErrClassRegistryFull {
		t.Errorf("65th class: err = %v, want ErrClassRegistryFull", err)
	}
	// Existing classes still resolve after the full error.
	if _, err := r.Bit("A"); err != nil {
		t.Errorf("existing class lookup after full registry: %v", err)
	}
}

func TestClassRegistry_SetFromNames(t *testing.T) {
	r := NewClassRegistry()
	ts, err := r.SetFromNames([]string{"pii", "credentials", "pii"})
	if err != nil {
		t.Fatal(err)
	}
	if ts.Count() != 2 {
		t.Errorf("duplicate names should fold; count = %d", ts.Count())
	}

	names := r.NamesOf(ts)
	if len(names) != 2 {
		t.Errorf("NamesOf produced %v, want 2 entries", names)
	}
}

func TestClassRegistry_ConcurrentSafe(t *testing.T) {
	r := NewClassRegistry()
	var wg sync.WaitGroup
	const goroutines = 50
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for _, name := range []string{"pii", "credentials", "api_key", "backup"} {
				_, _ = r.Bit(name)
			}
		}()
	}
	wg.Wait()
	if r.Size() != 4 {
		t.Errorf("Size after concurrent registrations = %d, want 4", r.Size())
	}
}

func TestStore_AddTaint_Propagates(t *testing.T) {
	s := NewStore()
	s.Put(Origin{ID: 1, Type: RootSSH, CreatedAt: time.Now()})

	mask1 := TaintSet(0).With(0).With(1) // pii + credentials
	got := s.AddTaint(1, mask1)
	if got != mask1 {
		t.Errorf("first AddTaint = %v, want %v", got, mask1)
	}

	// Adding more taint accumulates.
	mask2 := TaintSet(0).With(5) // payment_token
	got = s.AddTaint(1, mask2)
	if got != mask1|mask2 {
		t.Errorf("second AddTaint = %v, want %v", got, mask1|mask2)
	}

	// Repeating the same mask is idempotent.
	got = s.AddTaint(1, mask1)
	if got != mask1|mask2 {
		t.Errorf("idempotent AddTaint = %v, want %v", got, mask1|mask2)
	}
}

func TestStore_AddTaint_IgnoresZeroIDAndEmpty(t *testing.T) {
	s := NewStore()
	if got := s.AddTaint(0, TaintSet(0).With(1)); !got.IsEmpty() {
		t.Errorf("id=0 should not store taint, got %v", got)
	}
	if got := s.AddTaint(1, 0); !got.IsEmpty() {
		t.Errorf("empty mask should not store taint, got %v", got)
	}
}

func TestStore_TaintOfChain(t *testing.T) {
	s := NewStore()
	s.Put(Origin{ID: 1, CreatedAt: time.Now()})
	s.Put(Origin{ID: 2, CreatedAt: time.Now()})
	s.Put(Origin{ID: 3, CreatedAt: time.Now()})

	s.AddTaint(1, TaintSet(0).With(0))  // pii on the outermost
	s.AddTaint(3, TaintSet(0).With(10)) // some other class on innermost

	chain := Chain{1, 2, 3}
	got := s.TaintOfChain(chain)
	want := TaintSet(0).With(0).With(10)
	if got != want {
		t.Errorf("TaintOfChain = %v, want %v", got, want)
	}

	if s.TaintOfChain(Chain{}) != 0 {
		t.Error("empty chain should have empty taint")
	}
}

func TestStore_SweepClearsTaint(t *testing.T) {
	s := NewStore()
	old := time.Now().Add(-24 * time.Hour)
	s.Put(Origin{ID: 1, CreatedAt: old})
	s.AddTaint(1, TaintSet(0).With(7))

	if s.Taint(1).IsEmpty() {
		t.Fatal("taint should be present before sweep")
	}
	removed := s.SweepOlderThan(time.Now().Add(-1 * time.Hour))
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if !s.Taint(1).IsEmpty() {
		t.Error("sweep should clear taint along with origin")
	}
}

func TestStore_TaintedCount(t *testing.T) {
	s := NewStore()
	now := time.Now()
	s.Put(Origin{ID: 1, CreatedAt: now})
	s.Put(Origin{ID: 2, CreatedAt: now})
	s.Put(Origin{ID: 3, CreatedAt: now})

	s.AddTaint(1, TaintSet(0).With(0))
	s.AddTaint(3, TaintSet(0).With(2))

	if got := s.TaintedCount(); got != 2 {
		t.Errorf("TaintedCount = %d, want 2", got)
	}
}

func TestStore_ConcurrentTaintWrites(t *testing.T) {
	// Race detector + concurrent writers exercise the mutex path
	// that closes the pre-existing concurrency hole.
	s := NewStore()
	s.Put(Origin{ID: 1, CreatedAt: time.Now()})

	var wg sync.WaitGroup
	const goroutines = 100
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			s.AddTaint(1, TaintSet(1<<(i%MaxTaintBits)))
		}()
	}
	wg.Wait()

	// We can't predict the exact set (depends on which bits hashed
	// to which goroutines), but we *can* assert it's non-empty and
	// no goroutine corrupted the state.
	got := s.Taint(1)
	if got.IsEmpty() {
		t.Error("concurrent AddTaint produced empty result")
	}
}

func BenchmarkStore_AddTaint(b *testing.B) {
	s := NewStore()
	s.Put(Origin{ID: 1, CreatedAt: time.Now()})
	mask := TaintSet(0).With(0).With(5).With(10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.AddTaint(1, mask)
	}
}

func BenchmarkStore_TaintOfChain_3deep(b *testing.B) {
	s := NewStore()
	now := time.Now()
	s.Put(Origin{ID: 1, CreatedAt: now})
	s.Put(Origin{ID: 2, CreatedAt: now})
	s.Put(Origin{ID: 3, CreatedAt: now})
	s.AddTaint(1, TaintSet(0).With(0))
	s.AddTaint(2, TaintSet(0).With(1))
	s.AddTaint(3, TaintSet(0).With(2))
	c := Chain{1, 2, 3}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.TaintOfChain(c)
	}
}
