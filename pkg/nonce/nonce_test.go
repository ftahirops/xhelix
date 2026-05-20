package nonce

import (
	"sync"
	"testing"
	"time"
)

func newStore(t testing.TB) *Store {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(k, 0)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNewStore_RejectsShortKey(t *testing.T) {
	if _, err := NewStore([]byte("short"), 0); err == nil {
		t.Error("short key should be rejected")
	}
}

func TestIssue_RequiresScope(t *testing.T) {
	s := newStore(t)
	if _, err := s.Issue("", 0); err == nil {
		t.Error("empty scope should error")
	}
}

func TestConsume_HappyPath(t *testing.T) {
	s := newStore(t)
	n, err := s.Issue("/admin/export", 0)
	if err != nil {
		t.Fatal(err)
	}
	if r := s.Consume(n, "/admin/export"); r != ConsumeOK {
		t.Errorf("first consume = %v, want OK", r)
	}
}

func TestConsume_ReplayDetected(t *testing.T) {
	s := newStore(t)
	n, _ := s.Issue("/x", 0)

	if r := s.Consume(n, "/x"); r != ConsumeOK {
		t.Fatalf("first consume = %v, want OK", r)
	}
	if r := s.Consume(n, "/x"); r != ConsumeReplayed {
		t.Errorf("second consume = %v, want Replayed", r)
	}
	// Third attempt still flagged.
	if r := s.Consume(n, "/x"); r != ConsumeReplayed {
		t.Errorf("third consume = %v, want Replayed", r)
	}
	if s.Stats().Replayed != 2 {
		t.Errorf("Replayed counter = %d, want 2", s.Stats().Replayed)
	}
}

func TestConsume_WrongScope(t *testing.T) {
	s := newStore(t)
	n, _ := s.Issue("/admin/export", 0)
	if r := s.Consume(n, "/user/profile"); r != ConsumeInvalidScope {
		t.Errorf("wrong scope consume = %v, want InvalidScope", r)
	}
	// The nonce wasn't burned — original scope still works.
	if r := s.Consume(n, "/admin/export"); r != ConsumeOK {
		t.Errorf("after wrong-scope, original-scope consume = %v, want OK", r)
	}
}

func TestConsume_Expired(t *testing.T) {
	s := newStore(t)
	n, _ := s.Issue("/x", 50*time.Millisecond)
	time.Sleep(80 * time.Millisecond)
	if r := s.Consume(n, "/x"); r != ConsumeExpired {
		t.Errorf("expired consume = %v, want Expired", r)
	}
}

func TestConsume_TamperedSignature(t *testing.T) {
	s := newStore(t)
	n, _ := s.Issue("/x", 0)
	n.Signature = "deadbeef"
	if r := s.Consume(n, "/x"); r != ConsumeBadSignature {
		t.Errorf("tampered consume = %v, want BadSignature", r)
	}
}

func TestConsume_ForeignKey(t *testing.T) {
	s1 := newStore(t)
	s2 := newStore(t)
	n, _ := s1.Issue("/x", 0)
	if r := s2.Consume(n, "/x"); r != ConsumeBadSignature {
		t.Errorf("nonce from other store = %v, want BadSignature", r)
	}
}

func TestConsume_NilAndZeroVersion(t *testing.T) {
	s := newStore(t)
	if r := s.Consume(nil, "/x"); r != ConsumeBadSignature {
		t.Errorf("nil = %v, want BadSignature", r)
	}
	if r := s.Consume(&Nonce{Version: 0, ID: "abc"}, "/x"); r != ConsumeBadSignature {
		t.Errorf("v0 = %v, want BadSignature", r)
	}
}

func TestSweep_RemovesExpired(t *testing.T) {
	s := newStore(t)
	s.Issue("/x", 30*time.Millisecond)
	s.Issue("/y", 30*time.Millisecond)
	s.Issue("/z", 0) // long-lived

	time.Sleep(60 * time.Millisecond)
	n := s.Sweep(time.Now().UTC())
	if n != 2 {
		t.Errorf("swept %d, want 2", n)
	}
	if s.Stats().Issued != 1 {
		t.Errorf("Issued outstanding = %d, want 1", s.Stats().Issued)
	}
}

func TestStore_ConcurrentIssueConsume(t *testing.T) {
	s := newStore(t)
	var wg sync.WaitGroup
	const goroutines = 20
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				n, err := s.Issue("/x", 0)
				if err != nil {
					t.Error(err)
					return
				}
				if r := s.Consume(n, "/x"); r != ConsumeOK {
					t.Errorf("concurrent consume = %v", r)
					return
				}
			}
		}()
	}
	wg.Wait()
	st := s.Stats()
	if st.OK != 2000 {
		t.Errorf("OK = %d, want 2000", st.OK)
	}
	if st.Replayed != 0 {
		t.Errorf("Replayed = %d in clean run, want 0", st.Replayed)
	}
}

func TestCapacity_Evicts(t *testing.T) {
	k, _ := GenerateKey()
	s, _ := NewStore(k, 3)
	for i := 0; i < 5; i++ {
		s.Issue("/x", time.Hour)
	}
	st := s.Stats()
	if st.Issued+st.Consumed > 3 {
		t.Errorf("total > maxSize: issued=%d consumed=%d", st.Issued, st.Consumed)
	}
}

func TestResult_String(t *testing.T) {
	for _, r := range []ConsumeResult{
		ConsumeOK, ConsumeReplayed, ConsumeExpired, ConsumeInvalidScope,
		ConsumeBadSignature, ConsumeNotIssued,
	} {
		if r.String() == "unknown" {
			t.Errorf("ConsumeResult(%d).String() == unknown", r)
		}
	}
}

func BenchmarkIssue(b *testing.B) {
	s := newStore(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Issue("/x", 0)
	}
}

func BenchmarkConsume_OK(b *testing.B) {
	s := newStore(b)
	// Pre-issue b.N nonces.
	ns := make([]*Nonce, b.N)
	for i := range ns {
		n, _ := s.Issue("/x", time.Hour)
		ns[i] = n
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Consume(ns[i], "/x")
	}
}

func BenchmarkConsume_Replayed(b *testing.B) {
	s := newStore(b)
	n, _ := s.Issue("/x", time.Hour)
	s.Consume(n, "/x") // burn it
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Consume(n, "/x") // all replayed
	}
}
