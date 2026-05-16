package connstate

import (
	"net/netip"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/cgroupclass"
)

func mkTuple(srcIP string, srcPort uint16, dstIP string, dstPort uint16) Tuple {
	return Tuple{
		Proto:   ProtoTCP,
		SrcAddr: netip.MustParseAddr(srcIP),
		SrcPort: srcPort,
		DstAddr: netip.MustParseAddr(dstIP),
		DstPort: dstPort,
	}
}

func TestOnConnectInsertsAndIndexes(t *testing.T) {
	tab := New(0)
	tup := mkTuple("10.0.0.5", 49152, "1.1.1.1", 443)
	tab.OnConnect(ConnectEvent{
		Time:        time.Unix(100, 0),
		PID:         42,
		Comm:        "curl",
		Exe:         "/usr/bin/curl",
		CGroupClass: cgroupclass.ClassUser,
		Unit:        "session-1.scope",
		UserID:      "1000",
		Tuple:       tup,
	})

	c, ok := tab.Lookup(tup)
	if !ok {
		t.Fatal("conn not in table")
	}
	if c.State != StateNew {
		t.Errorf("state = %s, want new", c.State)
	}
	if c.Direction != DirOutbound {
		t.Errorf("dir = %s, want outbound", c.Direction)
	}
	if c.PID != 42 || c.Comm != "curl" {
		t.Errorf("attribution wrong: %+v", c)
	}
	if c.CGroupClass != cgroupclass.ClassUser {
		t.Errorf("class = %s", c.CGroupClass)
	}

	byPID := tab.SnapshotByPID(42)
	if len(byPID) != 1 || byPID[0].Tuple != tup {
		t.Errorf("byPID index wrong: %+v", byPID)
	}
}

func TestStateTransitions(t *testing.T) {
	tab := New(0)
	tup := mkTuple("10.0.0.5", 49152, "1.1.1.1", 443)
	t0 := time.Unix(100, 0)
	tab.OnConnect(ConnectEvent{Time: t0, PID: 1, Tuple: tup})

	tab.OnEstablished(tup, t0.Add(time.Millisecond))
	if c, _ := tab.Lookup(tup); c.State != StateEstablished {
		t.Fatalf("state after OnEstablished = %s", c.State)
	}

	tab.OnClose(tup, t0.Add(time.Second))
	if c, _ := tab.Lookup(tup); c.State != StateClosed {
		t.Fatalf("state after OnClose = %s", c.State)
	}
	if tab.Stats().Closed != 1 {
		t.Fatalf("Stats.Closed = %d", tab.Stats().Closed)
	}
}

func TestOnReset(t *testing.T) {
	tab := New(0)
	tup := mkTuple("10.0.0.5", 1234, "8.8.8.8", 53)
	tab.OnConnect(ConnectEvent{PID: 7, Tuple: tup})
	tab.OnReset(tup, time.Unix(200, 0))
	c, _ := tab.Lookup(tup)
	if c.State != StateReset {
		t.Fatalf("state = %s, want reset", c.State)
	}
}

func TestSnapshotByClass(t *testing.T) {
	tab := New(0)
	tab.OnConnect(ConnectEvent{
		PID: 1, CGroupClass: cgroupclass.ClassUser,
		Tuple: mkTuple("10.0.0.5", 1, "1.1.1.1", 443),
	})
	tab.OnConnect(ConnectEvent{
		PID: 2, CGroupClass: cgroupclass.ClassSystem,
		Tuple: mkTuple("10.0.0.5", 2, "2.2.2.2", 443),
	})
	tab.OnConnect(ConnectEvent{
		PID: 3, CGroupClass: cgroupclass.ClassContainer,
		Tuple: mkTuple("10.0.0.5", 3, "3.3.3.3", 443),
	})
	if got := len(tab.SnapshotByClass(cgroupclass.ClassUser)); got != 1 {
		t.Errorf("user = %d", got)
	}
	if got := len(tab.SnapshotByClass(cgroupclass.ClassSystem)); got != 1 {
		t.Errorf("system = %d", got)
	}
	if got := len(tab.SnapshotByClass(cgroupclass.ClassContainer)); got != 1 {
		t.Errorf("container = %d", got)
	}
}

func TestLateAttributionUpdatesIndex(t *testing.T) {
	tab := New(0)
	tup := mkTuple("10.0.0.5", 5555, "1.1.1.1", 443)
	// First sighting: no pid yet (rare race — eBPF dropped it,
	// conntrack saw the flow first).
	tab.OnConnect(ConnectEvent{Tuple: tup})
	if len(tab.SnapshotByPID(99)) != 0 {
		t.Fatal("byPID populated before pid known")
	}
	// Second sighting fills in the pid.
	tab.OnConnect(ConnectEvent{PID: 99, Comm: "later", Tuple: tup})
	got := tab.SnapshotByPID(99)
	if len(got) != 1 {
		t.Fatalf("byPID after late attribution = %d", len(got))
	}
}

func TestSweepRemovesOldClosed(t *testing.T) {
	tab := New(0)
	tup := mkTuple("10.0.0.5", 7777, "1.1.1.1", 80)
	t0 := time.Unix(1000, 0)
	tab.OnConnect(ConnectEvent{Time: t0, PID: 1, Tuple: tup})
	tab.OnClose(tup, t0)

	if n := tab.Sweep(t0.Add(30*time.Second), time.Minute, 0); n != 0 {
		t.Fatalf("early sweep removed %d, want 0", n)
	}
	if n := tab.Sweep(t0.Add(2*time.Minute), time.Minute, 0); n != 1 {
		t.Fatalf("late sweep removed %d, want 1", n)
	}
	if _, ok := tab.Lookup(tup); ok {
		t.Fatal("conn still present after sweep")
	}
}

func TestCapEvictsClosedFirst(t *testing.T) {
	tab := New(2)
	a := mkTuple("10.0.0.5", 1, "1.1.1.1", 443)
	b := mkTuple("10.0.0.5", 2, "2.2.2.2", 443)
	c := mkTuple("10.0.0.5", 3, "3.3.3.3", 443)

	tab.OnConnect(ConnectEvent{PID: 1, Tuple: a})
	tab.OnConnect(ConnectEvent{PID: 2, Tuple: b})
	tab.OnClose(a, time.Unix(50, 0))
	tab.OnConnect(ConnectEvent{PID: 3, Tuple: c})

	if _, ok := tab.Lookup(a); ok {
		t.Fatal("closed conn a should have been evicted")
	}
	if _, ok := tab.Lookup(b); !ok {
		t.Fatal("conn b should still be live")
	}
	if _, ok := tab.Lookup(c); !ok {
		t.Fatal("new conn c should be present")
	}
}

func TestStats(t *testing.T) {
	tab := New(0)
	tab.OnConnect(ConnectEvent{
		PID: 1, CGroupClass: cgroupclass.ClassUser,
		Tuple: mkTuple("10.0.0.5", 1, "1.1.1.1", 443),
	})
	tab.OnConnect(ConnectEvent{
		PID: 2, CGroupClass: cgroupclass.ClassSystem,
		Tuple: mkTuple("10.0.0.5", 2, "2.2.2.2", 443),
	})
	s := tab.Stats()
	if s.Live != 2 {
		t.Fatalf("live = %d", s.Live)
	}
	if s.ByState[StateNew] != 2 {
		t.Fatalf("byState[new] = %d", s.ByState[StateNew])
	}
	if s.ByClass[cgroupclass.ClassUser] != 1 || s.ByClass[cgroupclass.ClassSystem] != 1 {
		t.Fatalf("byClass = %+v", s.ByClass)
	}
}

func TestRecordDNSEnrichesNextConnect(t *testing.T) {
	tab := New(0)
	// DNS observation arrives first: pid 42 resolved example.com -> 1.2.3.4
	tab.RecordDNS(42, "example.com", []string{"1.2.3.4", "5.6.7.8"})

	// Now a connect from pid 42 to 1.2.3.4 should pick up the qname.
	tup := mkTuple("10.0.0.5", 49152, "1.2.3.4", 443)
	tab.OnConnect(ConnectEvent{
		PID:   42,
		Tuple: tup,
	})
	c, ok := tab.Lookup(tup)
	if !ok {
		t.Fatal("conn missing")
	}
	if c.DNSName != "example.com" {
		t.Fatalf("dns_name = %q, want example.com", c.DNSName)
	}

	// Different pid hitting same IP must NOT get the qname.
	tup2 := mkTuple("10.0.0.5", 49153, "1.2.3.4", 443)
	tab.OnConnect(ConnectEvent{PID: 99, Tuple: tup2})
	c2, _ := tab.Lookup(tup2)
	if c2.DNSName != "" {
		t.Fatalf("dns_name leaked across pids: %q", c2.DNSName)
	}
}

func TestRecordDNSIgnoresEmpty(t *testing.T) {
	tab := New(0)
	tab.RecordDNS(0, "x", []string{"1.2.3.4"})        // pid 0
	tab.RecordDNS(1, "", []string{"1.2.3.4"})         // empty qname
	tab.RecordDNS(1, "x", nil)                         // no IPs

	tab.OnConnect(ConnectEvent{PID: 1, Tuple: mkTuple("10.0.0.5", 1, "1.2.3.4", 443)})
	c, _ := tab.Lookup(mkTuple("10.0.0.5", 1, "1.2.3.4", 443))
	if c.DNSName != "" {
		t.Fatalf("dns_name = %q, want empty", c.DNSName)
	}
}

func TestAttachDNS(t *testing.T) {
	tab := New(0)
	tup := mkTuple("10.0.0.5", 33333, "1.2.3.4", 443)
	tab.OnConnect(ConnectEvent{PID: 1, Tuple: tup})
	tab.AttachDNS(tup, "example.com")
	if c, _ := tab.Lookup(tup); c.DNSName != "example.com" {
		t.Fatalf("dns = %q", c.DNSName)
	}
	// Second AttachDNS does not overwrite.
	tab.AttachDNS(tup, "evil.example")
	if c, _ := tab.Lookup(tup); c.DNSName != "example.com" {
		t.Fatalf("dns overwritten: %q", c.DNSName)
	}
}
