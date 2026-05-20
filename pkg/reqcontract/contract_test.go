package reqcontract

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

func newStore(t testing.TB, maxSize int) *Store {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(key, maxSize)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNewStore_RejectsShortKey(t *testing.T) {
	if _, err := NewStore([]byte("too-short"), 0); err == nil {
		t.Error("short key should be rejected")
	}
}

func TestIssue_RequiresRoute(t *testing.T) {
	s := newStore(t, 100)
	if _, err := s.Issue(IssueParams{}); err == nil {
		t.Error("empty route should error")
	}
}

func TestIssue_ClampsTTL(t *testing.T) {
	s := newStore(t, 100)

	c1, _ := s.Issue(IssueParams{Route: "/x", TTL: 0})
	if d := c1.ExpiresAt.Sub(c1.IssuedAt); d != DefaultTTL {
		t.Errorf("zero TTL → DefaultTTL: got %v", d)
	}

	c2, _ := s.Issue(IssueParams{Route: "/x", TTL: 1 * time.Hour})
	if d := c2.ExpiresAt.Sub(c2.IssuedAt); d != MaxTTL {
		t.Errorf("over-max TTL → MaxTTL: got %v", d)
	}
}

func TestIssue_VerifyRoundTrip(t *testing.T) {
	s := newStore(t, 100)
	c, err := s.Issue(IssueParams{
		Route:   "/admin/export",
		Account: "user_91",
		Session: "sess_abc",
		JA3:     "abc123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(c); err != nil {
		t.Errorf("Verify on fresh contract: %v", err)
	}
}

func TestVerify_RejectsTampered(t *testing.T) {
	s := newStore(t, 100)
	c, _ := s.Issue(IssueParams{Route: "/x", Account: "a"})
	c.Account = "different"
	if err := s.Verify(c); err == nil {
		t.Error("tampered Account should fail verify")
	}
}

func TestVerify_RejectsExpired(t *testing.T) {
	s := newStore(t, 100)
	c, _ := s.Issue(IssueParams{Route: "/x", TTL: 50 * time.Millisecond})
	time.Sleep(80 * time.Millisecond)
	if err := s.Verify(c); err == nil {
		t.Error("expired contract should fail verify")
	}
}

func TestLookup_HitAndMiss(t *testing.T) {
	s := newStore(t, 100)
	c, _ := s.Issue(IssueParams{Route: "/x"})

	got, ok := s.Lookup(c.ID)
	if !ok {
		t.Fatal("Lookup of fresh contract should succeed")
	}
	if got.ID != c.ID {
		t.Errorf("ID mismatch")
	}

	if _, ok := s.Lookup("never-issued"); ok {
		t.Error("Lookup of unknown id should miss")
	}
}

func TestLookup_LazyExpires(t *testing.T) {
	s := newStore(t, 100)
	c, _ := s.Issue(IssueParams{Route: "/x", TTL: 30 * time.Millisecond})
	time.Sleep(60 * time.Millisecond)
	if _, ok := s.Lookup(c.ID); ok {
		t.Error("expired contract should miss on lookup")
	}
	// And was lazy-deleted.
	if s.Size() != 0 {
		t.Errorf("lazy-delete should have removed expired entry; size=%d", s.Size())
	}
}

func TestSweep_RemovesExpired(t *testing.T) {
	s := newStore(t, 100)
	s.Issue(IssueParams{Route: "/x", TTL: 30 * time.Millisecond})
	s.Issue(IssueParams{Route: "/y", TTL: 30 * time.Millisecond})
	s.Issue(IssueParams{Route: "/z"}) // long-lived

	time.Sleep(60 * time.Millisecond)
	n := s.Sweep(time.Now().UTC())
	if n != 2 {
		t.Errorf("swept %d, want 2", n)
	}
	if s.Size() != 1 {
		t.Errorf("after sweep size = %d, want 1", s.Size())
	}
}

func TestStore_CapacityEvictsOldest(t *testing.T) {
	s := newStore(t, 3)
	for i := 0; i < 5; i++ {
		s.Issue(IssueParams{Route: "/x"})
	}
	if s.Size() != 3 {
		t.Errorf("size = %d, want 3", s.Size())
	}
	if s.Stats().Evicted == 0 {
		t.Error("expected at least one eviction")
	}
}

func TestContract_IsValid(t *testing.T) {
	c := &Contract{ID: "abc", Route: "/x", ExpiresAt: time.Now().Add(time.Minute)}
	if !c.IsValid(time.Now()) {
		t.Error("fresh contract should be valid")
	}
	c.ExpiresAt = time.Now().Add(-time.Minute)
	if c.IsValid(time.Now()) {
		t.Error("expired contract should be invalid")
	}

	if (*Contract)(nil).IsValid(time.Now()) {
		t.Error("nil should be invalid")
	}
}

func TestStore_ConcurrentIssueLookup(t *testing.T) {
	s := newStore(t, 1000)
	var wg sync.WaitGroup
	const goroutines = 20
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				c, err := s.Issue(IssueParams{Route: "/x"})
				if err != nil {
					t.Error(err)
					return
				}
				if _, ok := s.Lookup(c.ID); !ok {
					t.Error("lookup of just-issued contract missed")
					return
				}
			}
		}()
	}
	wg.Wait()
	if s.Stats().Issued != 2000 {
		t.Errorf("Issued = %d, want 2000", s.Stats().Issued)
	}
}

func TestSignDeterministic(t *testing.T) {
	// Two stores with the same key should produce the same signature
	// for the same contract content.
	key := bytes.Repeat([]byte{0xAB}, 32)
	s1, _ := NewStore(key, 10)
	s2, _ := NewStore(key, 10)

	now := time.Now().UTC()
	c := &Contract{
		Version:   1,
		ID:        "deadbeef",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Second),
		Route:     "/x",
	}
	if s1.sign(c) != s2.sign(c) {
		t.Error("HMAC signatures should match across stores with same key")
	}
}

func BenchmarkIssue(b *testing.B) {
	s := newStore(b, 10_000_000)
	p := IssueParams{Route: "/api/v1/orders", Account: "u_91"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Issue(p)
	}
}

func BenchmarkLookup_Hit(b *testing.B) {
	s := newStore(b, 10_000)
	c, _ := s.Issue(IssueParams{Route: "/x"})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Lookup(c.ID)
	}
}

func BenchmarkLookup_Miss(b *testing.B) {
	s := newStore(b, 10_000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Lookup("never-issued-xxxxxxxxxxxxxxxxxxx")
	}
}

func BenchmarkVerify(b *testing.B) {
	s := newStore(b, 10_000)
	c, _ := s.Issue(IssueParams{Route: "/x", Account: "u_91"})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Verify(c)
	}
}
