package dnsresolver

import (
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeResolver struct {
	pidByPort map[uint16]uint32
	exeByPort map[uint16]string
}

func (f *fakeResolver) PIDForUDPPort(port uint16) (uint32, string, bool) {
	pid, ok := f.pidByPort[port]
	if !ok {
		return 0, "", false
	}
	return pid, f.exeByPort[port], true
}

type capturingSink struct {
	mu  sync.Mutex
	obs []Observation
}

func (c *capturingSink) Sink() Sink {
	return func(o Observation) {
		c.mu.Lock()
		c.obs = append(c.obs, o)
		c.mu.Unlock()
	}
}

func (c *capturingSink) snapshot() []Observation {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Observation, len(c.obs))
	copy(out, c.obs)
	return out
}

func TestObserveAttributesByPort(t *testing.T) {
	res := &fakeResolver{
		pidByPort: map[uint16]uint32{49152: 42},
		exeByPort: map[uint16]string{49152: "/usr/bin/firefox"},
	}
	cap := &capturingSink{}
	c := NewCollector(res, cap.Sink())

	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }

	ok := c.Observe(Observation{
		Query: Query{At: now, QName: "example.com", QType: "A", SrcPort: 49152},
		Answer: Answer{IPs: []string{"1.2.3.4"}, TTL: 30 * time.Second},
	})
	if !ok {
		t.Fatal("Observe returned false")
	}
	got := cap.snapshot()
	if len(got) != 1 {
		t.Fatalf("sink got %d, want 1", len(got))
	}
	if got[0].PID != 42 || got[0].Exe != "/usr/bin/firefox" {
		t.Fatalf("attribution wrong: %+v", got[0])
	}
}

func TestObserveSkipsUnresolved(t *testing.T) {
	res := &fakeResolver{pidByPort: map[uint16]uint32{}}
	cap := &capturingSink{}
	c := NewCollector(res, cap.Sink())

	ok := c.Observe(Observation{
		Query: Query{At: time.Unix(1, 0), QName: "x", QType: "A", SrcPort: 99},
	})
	if !ok {
		t.Fatal("Observe should still forward when unattributed")
	}
	got := cap.snapshot()
	if len(got) != 1 || got[0].PID != 0 {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestDedupeWithinWindow(t *testing.T) {
	cap := &capturingSink{}
	c := NewCollector(&fakeResolver{}, cap.Sink())
	c.DedupeWindow = time.Second

	t0 := time.Unix(1000, 0)
	q := Observation{Query: Query{At: t0, QName: "example.com", QType: "A"}, PID: 1}
	q2 := Observation{Query: Query{At: t0.Add(500 * time.Millisecond), QName: "example.com", QType: "A"}, PID: 1}
	q3 := Observation{Query: Query{At: t0.Add(2 * time.Second), QName: "example.com", QType: "A"}, PID: 1}

	if !c.Observe(q) {
		t.Fatal("first should be forwarded")
	}
	if c.Observe(q2) {
		t.Fatal("dup within window should be suppressed")
	}
	if !c.Observe(q3) {
		t.Fatal("out-of-window should be forwarded")
	}
	if got := cap.snapshot(); len(got) != 2 {
		t.Fatalf("sink got %d, want 2", len(got))
	}
}

func TestDedupeDistinctQNames(t *testing.T) {
	cap := &capturingSink{}
	c := NewCollector(&fakeResolver{}, cap.Sink())
	t0 := time.Unix(1000, 0)

	a := Observation{Query: Query{At: t0, QName: "a.example", QType: "A"}, PID: 1}
	b := Observation{Query: Query{At: t0, QName: "b.example", QType: "A"}, PID: 1}
	if !c.Observe(a) || !c.Observe(b) {
		t.Fatal("different qnames should not dedupe")
	}
	if got := cap.snapshot(); len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
}

func TestDedupeAcrossPIDsIsIndependent(t *testing.T) {
	cap := &capturingSink{}
	c := NewCollector(&fakeResolver{}, cap.Sink())
	t0 := time.Unix(1000, 0)

	a := Observation{Query: Query{At: t0, QName: "x", QType: "A"}, PID: 1}
	b := Observation{Query: Query{At: t0, QName: "x", QType: "A"}, PID: 2}
	if !c.Observe(a) || !c.Observe(b) {
		t.Fatal("different pids should not dedupe")
	}
}

func TestObserveFillsAtIfZero(t *testing.T) {
	cap := &capturingSink{}
	c := NewCollector(&fakeResolver{}, cap.Sink())
	fixed := time.Unix(7777, 0)
	c.now = func() time.Time { return fixed }

	c.Observe(Observation{Query: Query{QName: "x", QType: "A"}, PID: 1})
	got := cap.snapshot()
	if !got[0].At.Equal(fixed) {
		t.Fatalf("At = %v, want %v", got[0].At, fixed)
	}
}

func TestNoSinkSilentlyDrops(t *testing.T) {
	c := NewCollector(&fakeResolver{}, nil)
	if c.Observe(Observation{Query: Query{QName: "x"}}) {
		t.Fatal("expected false when Sink unset")
	}
}

func TestSweepRemovesOldEntries(t *testing.T) {
	cap := &capturingSink{}
	c := NewCollector(&fakeResolver{}, cap.Sink())
	c.DedupeWindow = time.Second

	t0 := time.Unix(1000, 0)
	c.Observe(Observation{Query: Query{At: t0, QName: "x", QType: "A"}, PID: 1})

	if removed := c.Sweep(t0); removed != 0 {
		t.Errorf("immediate sweep removed %d, want 0", removed)
	}
	if removed := c.Sweep(t0.Add(5 * time.Second)); removed != 1 {
		t.Errorf("delayed sweep removed %d, want 1", removed)
	}
}

func TestScanProcNetUDP(t *testing.T) {
	// Real /proc/net/udp format. Port 49152 is 0xC000 in hex.
	content := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
    0: 00000000:C000 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 12345 2 ffff 0
    1: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 67890 2 ffff 0
`
	got, ok := scanProcNetUDP(strings.NewReader(content), 49152)
	if !ok || got != "12345" {
		t.Fatalf("scanProcNetUDP(49152) = %q,%v, want 12345,true", got, ok)
	}
	got, ok = scanProcNetUDP(strings.NewReader(content), 53)
	if !ok || got != "67890" {
		t.Fatalf("scanProcNetUDP(53) = %q,%v, want 67890,true", got, ok)
	}
	_, ok = scanProcNetUDP(strings.NewReader(content), 9999)
	if ok {
		t.Fatal("scanProcNetUDP(9999) should miss")
	}
}

func TestItoa(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{{0, "0"}, {1, "1"}, {42, "42"}, {-7, "-7"}, {12345, "12345"}}
	for _, c := range cases {
		if got := itoa(c.in); got != c.want {
			t.Errorf("itoa(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}
