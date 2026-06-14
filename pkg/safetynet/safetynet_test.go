package safetynet

import (
	"net"
	"testing"
)

func TestAllowAlways_ExactAndCIDR(t *testing.T) {
	s, err := New([]string{"10.0.0.5/32", "192.168.0.0/24"}, nil, 16)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !s.AllowAlways(net.ParseIP("10.0.0.5")) {
		t.Error("expected /32 exact match")
	}
	if !s.AllowAlways(net.ParseIP("192.168.0.77")) {
		t.Error("expected /24 prefix match")
	}
	if s.AllowAlways(net.ParseIP("8.8.8.8")) {
		t.Error("expected miss on 8.8.8.8")
	}
}

func TestIsBlocked(t *testing.T) {
	s, err := New(nil, []string{"203.0.113.0/24"}, 16)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !s.IsBlocked(net.ParseIP("203.0.113.99")) {
		t.Error("expected match")
	}
	if s.IsBlocked(net.ParseIP("10.0.0.1")) {
		t.Error("expected miss")
	}
}

func TestAddRemove(t *testing.T) {
	s, _ := New(nil, nil, 16)
	if err := s.AddAllow("1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if !s.AllowAlways(net.ParseIP("1.1.1.1")) {
		t.Error("AddAllow didn't take")
	}
	if err := s.RemoveAllow("1.1.1.1/32"); err != nil {
		t.Fatal(err)
	}
	if s.AllowAlways(net.ParseIP("1.1.1.1")) {
		t.Error("RemoveAllow didn't take")
	}

	if err := s.AddBlock("9.9.9.0/24"); err != nil {
		t.Fatal(err)
	}
	if !s.IsBlocked(net.ParseIP("9.9.9.1")) {
		t.Error("AddBlock didn't take")
	}
	if err := s.RemoveBlock("9.9.9.0/24"); err != nil {
		t.Fatal(err)
	}
	if s.IsBlocked(net.ParseIP("9.9.9.1")) {
		t.Error("RemoveBlock didn't take")
	}
}

func TestMalformedCIDR(t *testing.T) {
	if _, err := New([]string{"not-a-cidr"}, nil, 16); err == nil {
		t.Error("expected error on malformed allow")
	}
	if _, err := New(nil, []string{"not-a-cidr"}, 16); err == nil {
		t.Error("expected error on malformed block")
	}
	s, _ := New(nil, nil, 16)
	if err := s.AddAllow("garbage/64"); err == nil {
		t.Error("expected error from AddAllow garbage")
	}
}

func TestIPv6BlockRejected(t *testing.T) {
	if _, err := New(nil, []string{"2001:db8::/32"}, 16); err == nil {
		t.Error("expected v6 block to be rejected")
	}
	s, _ := New(nil, nil, 16)
	if err := s.AddBlock("2001:db8::/32"); err == nil {
		t.Error("expected v6 AddBlock to be rejected")
	}
}

func TestRecordAndRecentAttempts(t *testing.T) {
	s, _ := New(nil, nil, 4)
	s.RecordAttempt(Attempt{SrcIP: "a"})
	s.RecordAttempt(Attempt{SrcIP: "b"})
	s.RecordAttempt(Attempt{SrcIP: "c"})
	recent := s.RecentAttempts(10)
	if len(recent) != 3 {
		t.Fatalf("want 3 got %d", len(recent))
	}
	if recent[0].SrcIP != "c" || recent[2].SrcIP != "a" {
		t.Errorf("wrong order: %+v", recent)
	}
	// Overflow ring.
	s.RecordAttempt(Attempt{SrcIP: "d"})
	s.RecordAttempt(Attempt{SrcIP: "e"})
	recent = s.RecentAttempts(10)
	if len(recent) != 4 {
		t.Fatalf("want 4 got %d", len(recent))
	}
	if recent[0].SrcIP != "e" {
		t.Errorf("newest should be e, got %s", recent[0].SrcIP)
	}
}

func TestStats(t *testing.T) {
	s, _ := New([]string{"1.2.3.4/32"}, []string{"5.6.7.0/24"}, 16)
	s.AllowAlways(net.ParseIP("1.2.3.4"))
	s.AllowAlways(net.ParseIP("9.9.9.9"))
	s.IsBlocked(net.ParseIP("5.6.7.8"))
	st := s.Stats()
	if st.AllowChecks != 2 || st.AllowHits != 1 {
		t.Errorf("allow counters: %+v", st)
	}
	if st.BlockChecks != 1 || st.BlockHits != 1 {
		t.Errorf("block counters: %+v", st)
	}
	if st.AllowCount != 1 || st.BlockCount != 1 {
		t.Errorf("sizes: %+v", st)
	}
}

func TestNilSafe(t *testing.T) {
	var s *SafetyNet
	if s.AllowAlways(net.ParseIP("1.2.3.4")) {
		t.Error("nil should not match")
	}
	if s.IsBlocked(net.ParseIP("1.2.3.4")) {
		t.Error("nil should not match")
	}
	s.RecordAttempt(Attempt{SrcIP: "x"})
	if got := s.RecentAttempts(5); got != nil {
		t.Errorf("nil RecentAttempts want nil got %v", got)
	}
	if got := s.AllowList(); got != nil {
		t.Errorf("nil AllowList want nil got %v", got)
	}
	if got := s.Stats(); got.AllowChecks != 0 {
		t.Errorf("nil Stats want zero, got %+v", got)
	}
}
