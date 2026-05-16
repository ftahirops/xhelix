package suppression

import (
	"testing"
	"time"
)

func TestAddAndSuppressed(t *testing.T) {
	s := NewStore()
	k := DefaultKey("rule1", "shaA", "1.2.3.4")
	s.Add(k, "benign cdn", time.Hour, "tahir")
	e, ok := s.Suppressed(k)
	if !ok {
		t.Fatal("expected suppressed")
	}
	if e.Reason != "benign cdn" {
		t.Errorf("reason = %q", e.Reason)
	}
	if e.Operator != "tahir" {
		t.Errorf("operator = %q", e.Operator)
	}
}

func TestSuppressedUnknownKey(t *testing.T) {
	s := NewStore()
	if _, ok := s.Suppressed(DefaultKey("x", "y", "z")); ok {
		t.Fatal("unknown key should not be suppressed")
	}
}

func TestExpiry(t *testing.T) {
	s := NewStore()
	t0 := time.Unix(1000, 0)
	s.now = func() time.Time { return t0 }
	k := DefaultKey("r", "e", "d")
	s.Add(k, "", time.Second, "op")
	if _, ok := s.Suppressed(k); !ok {
		t.Fatal("immediate Suppressed should be true")
	}
	s.now = func() time.Time { return t0.Add(2 * time.Second) }
	if _, ok := s.Suppressed(k); ok {
		t.Fatal("expired entry should not be suppressed")
	}
}

func TestNoExpiryOnZeroTTL(t *testing.T) {
	s := NewStore()
	t0 := time.Unix(1000, 0)
	s.now = func() time.Time { return t0 }
	k := DefaultKey("r", "e", "d")
	s.Add(k, "", 0, "op")
	s.now = func() time.Time { return t0.Add(10 * 365 * 24 * time.Hour) }
	if _, ok := s.Suppressed(k); !ok {
		t.Fatal("TTL=0 should never expire")
	}
}

func TestRemove(t *testing.T) {
	s := NewStore()
	k := DefaultKey("r", "e", "d")
	s.Add(k, "", time.Hour, "op")
	if !s.Remove(k) {
		t.Fatal("Remove should report success")
	}
	if _, ok := s.Suppressed(k); ok {
		t.Fatal("entry should be gone")
	}
	if s.Remove(k) {
		t.Fatal("second Remove should report nothing removed")
	}
}

func TestListSortedAndExcludesExpired(t *testing.T) {
	s := NewStore()
	t0 := time.Unix(1000, 0)
	s.now = func() time.Time { return t0 }
	s.Add("b", "", time.Hour, "")
	s.Add("a", "", time.Hour, "")
	s.Add("c", "", time.Second, "")
	s.now = func() time.Time { return t0.Add(5 * time.Second) }
	got := s.List()
	if len(got) != 2 || got[0].Key != "a" || got[1].Key != "b" {
		t.Fatalf("got %+v", got)
	}
}

func TestSweep(t *testing.T) {
	s := NewStore()
	t0 := time.Unix(1000, 0)
	s.now = func() time.Time { return t0 }
	s.Add("a", "", time.Second, "")
	s.Add("b", "", time.Hour, "")
	s.now = func() time.Time { return t0.Add(5 * time.Second) }
	if n := s.Sweep(); n != 1 {
		t.Fatalf("swept %d, want 1", n)
	}
	if s.Len() != 1 {
		t.Fatalf("len after sweep = %d", s.Len())
	}
}

func TestSnapshotLoadRoundTrip(t *testing.T) {
	s := NewStore()
	s.Add("a", "ra", time.Hour, "op1")
	s.Add("b", "rb", 0, "op2")
	snap := s.Snapshot()
	s2 := NewStore()
	s2.Load(snap)
	if s2.Len() != 2 {
		t.Fatalf("len after Load = %d", s2.Len())
	}
	if _, ok := s2.Suppressed("a"); !ok {
		t.Fatal("a missing after Load")
	}
}

func TestReset(t *testing.T) {
	s := NewStore()
	s.Add("a", "", time.Hour, "")
	s.Reset()
	if s.Len() != 0 {
		t.Fatal("Reset did not clear")
	}
}

func TestDefaultKey(t *testing.T) {
	cases := []struct {
		rule, exe, dst string
		want           Key
	}{
		{"r", "e", "d", "r|e|d"},
		{"", "e", "d", "*|e|d"},
		{"r", "", "d", "r|*|d"},
		{"r", "e", "", "r|e|*"},
	}
	for _, c := range cases {
		if got := DefaultKey(c.rule, c.exe, c.dst); got != c.want {
			t.Errorf("DefaultKey(%q,%q,%q) = %q, want %q", c.rule, c.exe, c.dst, got, c.want)
		}
	}
}

func TestEmptyKeyRejected(t *testing.T) {
	s := NewStore()
	if e := s.Add("", "", time.Hour, ""); e.Key != "" {
		t.Fatal("empty key should be rejected")
	}
	if s.Len() != 0 {
		t.Fatal("empty key should not increase Len")
	}
}
