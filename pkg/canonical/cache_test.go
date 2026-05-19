package canonical

import (
	"os"
	"sync"
	"testing"
	"time"
)

func TestCache_PutGet(t *testing.T) {
	c := NewProcKeyCache(CacheOptions{})
	pk := ProcKey{PID: 100, StartTicks: 12345}
	c.Put(pk)

	got, ok := c.Get(100)
	if !ok {
		t.Fatal("expected hit after Put")
	}
	if got != pk {
		t.Errorf("got %v, want %v", got, pk)
	}
	if c.HitRatio() != 1.0 {
		t.Errorf("HitRatio = %v, want 1.0", c.HitRatio())
	}
}

func TestCache_MissOnAbsent(t *testing.T) {
	c := NewProcKeyCache(CacheOptions{})
	if _, ok := c.Get(999); ok {
		t.Error("absent key should miss")
	}
	s := c.Stats()
	if s.Misses != 1 || s.Hits != 0 {
		t.Errorf("stats = %+v, want misses=1 hits=0", s)
	}
}

func TestCache_TTLExpiry(t *testing.T) {
	c := NewProcKeyCache(CacheOptions{TTL: 30 * time.Millisecond})
	c.Put(ProcKey{PID: 7, StartTicks: 1})

	if _, ok := c.Get(7); !ok {
		t.Fatal("fresh entry should hit")
	}
	time.Sleep(50 * time.Millisecond)
	if _, ok := c.Get(7); ok {
		t.Error("expired entry should miss")
	}
}

func TestCache_BoundedSizeEvicts(t *testing.T) {
	c := NewProcKeyCache(CacheOptions{MaxSize: 3})

	for i := uint32(1); i <= 5; i++ {
		c.Put(ProcKey{PID: i, StartTicks: uint64(i * 100)})
	}
	if c.Size() != 3 {
		t.Errorf("size = %d, want 3 (bounded)", c.Size())
	}
	if c.Stats().Evicts == 0 {
		t.Error("expected at least one eviction")
	}
}

func TestCache_Invalidate(t *testing.T) {
	c := NewProcKeyCache(CacheOptions{})
	c.Put(ProcKey{PID: 42, StartTicks: 1})

	if _, ok := c.Get(42); !ok {
		t.Fatal("entry should be present")
	}
	c.Invalidate(42)
	if _, ok := c.Get(42); ok {
		t.Error("invalidated entry should miss")
	}
	if c.Stats().Evicts != 1 {
		t.Errorf("evicts = %d, want 1", c.Stats().Evicts)
	}

	// Invalidate of absent pid is a no-op (no extra evict count).
	c.Invalidate(99)
	if c.Stats().Evicts != 1 {
		t.Errorf("evicts after no-op invalidate = %d, want 1", c.Stats().Evicts)
	}
}

func TestCache_Resolve_HitsAfterFirstCall(t *testing.T) {
	c := NewProcKeyCache(CacheOptions{})
	self := uint32(os.Getpid())

	pk1, err := c.Resolve(self)
	if err != nil {
		t.Fatal(err)
	}
	if pk1.PID != self {
		t.Errorf("first resolve PID = %d, want %d", pk1.PID, self)
	}

	pk2, err := c.Resolve(self)
	if err != nil {
		t.Fatal(err)
	}
	if pk2 != pk1 {
		t.Errorf("second resolve mismatch: %v vs %v", pk1, pk2)
	}

	s := c.Stats()
	if s.Hits != 1 || s.Misses != 1 {
		t.Errorf("expected 1 hit + 1 miss, got %+v", s)
	}
}

func TestCache_Resolve_ErrorsOnBadPID(t *testing.T) {
	c := NewProcKeyCache(CacheOptions{})
	_, err := c.Resolve(99999999) // very unlikely to exist
	if err == nil {
		t.Error("Resolve of nonexistent PID should error")
	}
}

func TestCache_PutZeroPIDIgnored(t *testing.T) {
	c := NewProcKeyCache(CacheOptions{})
	c.Put(ProcKey{PID: 0, StartTicks: 1})
	if c.Size() != 0 {
		t.Error("pid 0 should not be cached")
	}
}

func TestCache_ConcurrentSafe(t *testing.T) {
	c := NewProcKeyCache(CacheOptions{MaxSize: 100})
	var wg sync.WaitGroup
	const goroutines = 50

	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				pid := uint32((g*500 + i) % 200)
				c.Put(ProcKey{PID: pid, StartTicks: uint64(i)})
				_, _ = c.Get(pid)
			}
		}()
	}
	wg.Wait()

	if c.Size() > 100 {
		t.Errorf("size = %d > maxSize=100, eviction broken", c.Size())
	}
	s := c.Stats()
	if s.Hits == 0 || s.Misses == 0 {
		t.Errorf("expected nonzero hits and misses, got %+v", s)
	}
}

func BenchmarkCache_Hit(b *testing.B) {
	c := NewProcKeyCache(CacheOptions{})
	c.Put(ProcKey{PID: 1, StartTicks: 12345})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Get(1)
	}
}

func BenchmarkCache_Miss(b *testing.B) {
	c := NewProcKeyCache(CacheOptions{})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Get(uint32(i))
	}
}

func BenchmarkCache_ResolveWarm(b *testing.B) {
	c := NewProcKeyCache(CacheOptions{})
	self := uint32(os.Getpid())
	_, _ = c.Resolve(self) // prime
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.Resolve(self)
	}
}

func BenchmarkCache_ResolveCold_NoCache(b *testing.B) {
	// Reference: cost of always reading /proc, no cache.
	self := uint32(os.Getpid())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ReadProcKey(self)
	}
}
