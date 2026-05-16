package activity

import (
	"testing"
	"time"
)

func base(t int64) time.Time { return time.Unix(t, 0) }

func TestSingleFlowOneActivityOnFlush(t *testing.T) {
	c := New(30 * time.Second)
	closed := c.Add(Flow{
		ProcessID: 1, Proto: "tcp", DstIP: "1.2.3.4", DstPort: 443,
		DNSQName: "example.com", OpenedAt: base(100), Verdict: VerdictGreen,
		BytesIn: 1000,
	})
	if len(closed) != 0 {
		t.Fatalf("no closure on first flow; got %+v", closed)
	}
	out := c.Flush(time.Time{})
	if len(out) != 1 {
		t.Fatalf("flush count = %d", len(out))
	}
	a := out[0]
	if a.PrimaryHost != "example.com" || a.PrimaryIP != "1.2.3.4" {
		t.Fatalf("primary wrong: %+v", a)
	}
	if a.FlowCount != 1 || a.Verdict != VerdictGreen {
		t.Fatalf("metadata wrong: %+v", a)
	}
}

func TestPageLoadClustersByRegistrableRoot(t *testing.T) {
	c := New(30 * time.Second)
	// Simulating a google.com page load: main + 3 sub-fetches to
	// the same gstatic.com / googleapis.com roots.
	flows := []Flow{
		{ProcessID: 1, DstIP: "142.250.1.1", DNSQName: "google.com",
			OpenedAt: base(100), BytesIn: 100000, Verdict: VerdictGreen, ASN: "AS15169"},
		{ProcessID: 1, DstIP: "142.250.2.2", DNSQName: "www.gstatic.com",
			OpenedAt: base(101), BytesIn: 30000, Verdict: VerdictGreen, ASN: "AS15169"},
		{ProcessID: 1, DstIP: "142.250.3.3", DNSQName: "fonts.gstatic.com",
			OpenedAt: base(102), BytesIn: 20000, Verdict: VerdictGreen, ASN: "AS15169"},
		{ProcessID: 1, DstIP: "172.217.4.4", DNSQName: "apis.google.com",
			OpenedAt: base(103), BytesIn: 5000, Verdict: VerdictGreen, ASN: "AS15169"},
	}
	for _, f := range flows {
		c.Add(f)
	}
	out := c.Flush(time.Time{})
	if len(out) != 1 {
		t.Fatalf("expected 1 cluster, got %d: %+v", len(out), out)
	}
	a := out[0]
	if a.FlowCount != 4 {
		t.Fatalf("flow_count = %d, want 4", a.FlowCount)
	}
	if a.PrimaryHost != "google.com" {
		t.Fatalf("primary_host = %q, want google.com (largest bytes_in)", a.PrimaryHost)
	}
	wantRelated := 3
	if len(a.RelatedHosts) != wantRelated {
		t.Fatalf("related_hosts = %v, want %d entries", a.RelatedHosts, wantRelated)
	}
}

func TestDifferentProcessesDoNotCluster(t *testing.T) {
	c := New(30 * time.Second)
	c.Add(Flow{ProcessID: 1, DstIP: "1.1.1.1", DNSQName: "a.example", OpenedAt: base(100), Verdict: VerdictGreen})
	c.Add(Flow{ProcessID: 2, DstIP: "1.1.1.1", DNSQName: "a.example", OpenedAt: base(100), Verdict: VerdictGreen})
	out := c.Flush(time.Time{})
	if len(out) != 2 {
		t.Fatalf("expected 2 activities (one per pid); got %d", len(out))
	}
}

func TestGapBeyondWindowClosesActivity(t *testing.T) {
	c := New(10 * time.Second)
	c.Add(Flow{ProcessID: 1, DstIP: "1.1.1.1", DNSQName: "a.example", OpenedAt: base(100), Verdict: VerdictGreen})
	// 20s later — beyond gap window. Should close the first and start a new one.
	closed := c.Add(Flow{ProcessID: 1, DstIP: "2.2.2.2", DNSQName: "a.example", OpenedAt: base(120), Verdict: VerdictGreen})
	if len(closed) != 1 {
		t.Fatalf("expected 1 closure on gap; got %+v", closed)
	}
	out := c.Flush(time.Time{})
	if len(out) != 1 {
		t.Fatalf("flush yielded %d, want 1 (the second activity)", len(out))
	}
}

func TestWorstVerdictWins(t *testing.T) {
	c := New(30 * time.Second)
	c.Add(Flow{ProcessID: 1, DstIP: "1.1.1.1", DNSQName: "a.example",
		OpenedAt: base(100), Verdict: VerdictGreen})
	closed := c.Add(Flow{ProcessID: 1, DstIP: "1.1.1.2", DNSQName: "b.example",
		OpenedAt: base(101), Verdict: VerdictRed, Reasons: []string{"intel_hit"}, ASN: ""})
	// Different roots, different ASN → the first one closes when
	// the second arrives. Total activities = 1 (from Add) + 1 (from Flush).
	total := len(closed)
	out := c.Flush(time.Time{})
	total += len(out)
	if total != 2 {
		t.Fatalf("expected 2 separate activities; got %d (closed=%v flush=%v)", total, closed, out)
	}

	// Same root, mixed verdicts — worst wins.
	c2 := New(30 * time.Second)
	c2.Add(Flow{ProcessID: 1, DNSQName: "a.example.com",
		OpenedAt: base(100), Verdict: VerdictGreen, BytesIn: 100})
	c2.Add(Flow{ProcessID: 1, DNSQName: "b.example.com",
		OpenedAt: base(101), Verdict: VerdictAmber, BytesIn: 50,
		Reasons: []string{"baseline_deviation"}})
	out = c2.Flush(time.Time{})
	if len(out) != 1 || out[0].Verdict != VerdictAmber {
		t.Fatalf("expected single amber cluster; got %+v", out)
	}
}

func TestFlushRespectsAge(t *testing.T) {
	c := New(30 * time.Second)
	c.Add(Flow{ProcessID: 1, DstIP: "1.1.1.1", DNSQName: "a.example",
		OpenedAt: base(100), Verdict: VerdictGreen})

	// Now is 110 — within GapWindow (30s). Flush with that "now"
	// should NOT close.
	out := c.Flush(base(110))
	if len(out) != 0 {
		t.Fatalf("expected 0 closures at now=110; got %d", len(out))
	}

	// Now is 200 — well past gap. Should close.
	out = c.Flush(base(200))
	if len(out) != 1 {
		t.Fatalf("expected 1 closure at now=200; got %d", len(out))
	}
}

func TestProtocolsCollected(t *testing.T) {
	c := New(30 * time.Second)
	c.Add(Flow{ProcessID: 1, Proto: "tcp", DNSQName: "a.example", OpenedAt: base(100), Verdict: VerdictGreen})
	c.Add(Flow{ProcessID: 1, Proto: "udp", DNSQName: "a.example", OpenedAt: base(101), Verdict: VerdictGreen})
	out := c.Flush(time.Time{})
	if len(out) != 1 {
		t.Fatalf("count = %d", len(out))
	}
	if out[0].Protocols != "tcp,udp" {
		t.Fatalf("protocols = %q", out[0].Protocols)
	}
}

func TestCountriesAndASNsDeduped(t *testing.T) {
	c := New(30 * time.Second)
	c.Add(Flow{ProcessID: 1, DNSQName: "a.example", Country: "US", ASN: "AS1", OpenedAt: base(100), Verdict: VerdictGreen})
	c.Add(Flow{ProcessID: 1, DNSQName: "b.a.example", Country: "US", ASN: "AS1", OpenedAt: base(101), Verdict: VerdictGreen})
	c.Add(Flow{ProcessID: 1, DNSQName: "c.a.example", Country: "DE", ASN: "AS2", OpenedAt: base(102), Verdict: VerdictGreen})
	out := c.Flush(time.Time{})
	if len(out) != 1 {
		t.Fatalf("expected single cluster; got %d", len(out))
	}
	a := out[0]
	if len(a.Countries) != 2 {
		t.Fatalf("countries = %v, want 2 distinct", a.Countries)
	}
	if len(a.ASNs) != 2 {
		t.Fatalf("asns = %v, want 2 distinct", a.ASNs)
	}
}

func TestRegistrableRoot(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"example.com", "example.com"},
		{"www.example.com", "example.com"},
		{"a.b.c.example.com", "example.com"},
		{"fonts.gstatic.com", "gstatic.com"},
		{"localhost", "localhost"},
		{"", ""},
	}
	for _, c := range cases {
		if got := registrableRoot(c.in); got != c.want {
			t.Errorf("registrableRoot(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestOpenCount(t *testing.T) {
	c := New(30 * time.Second)
	if c.OpenCount() != 0 {
		t.Fatal("initial open != 0")
	}
	c.Add(Flow{ProcessID: 1, DNSQName: "a.example", OpenedAt: base(100), Verdict: VerdictGreen})
	c.Add(Flow{ProcessID: 2, DNSQName: "b.example", OpenedAt: base(100), Verdict: VerdictGreen})
	if c.OpenCount() != 2 {
		t.Fatalf("open = %d, want 2", c.OpenCount())
	}
	c.Flush(time.Time{})
	if c.OpenCount() != 0 {
		t.Fatalf("open after flush = %d", c.OpenCount())
	}
}

func TestNoProcessIDSkipped(t *testing.T) {
	c := New(30 * time.Second)
	closed := c.Add(Flow{ProcessID: 0, DNSQName: "x", OpenedAt: base(100)})
	if len(closed) != 0 {
		t.Fatalf("zero-pid flow should be ignored; got %+v", closed)
	}
	if c.OpenCount() != 0 {
		t.Fatalf("open = %d, want 0", c.OpenCount())
	}
}

func TestVerdictScoreSet(t *testing.T) {
	c := New(30 * time.Second)
	c.Add(Flow{ProcessID: 1, DNSQName: "a.example", OpenedAt: base(100), Verdict: VerdictGreen})
	out := c.Flush(time.Time{})
	if out[0].VerdictScore != 95 {
		t.Fatalf("score = %v, want 95 for green", out[0].VerdictScore)
	}

	c2 := New(30 * time.Second)
	c2.Add(Flow{ProcessID: 1, DNSQName: "a.example", OpenedAt: base(100), Verdict: VerdictRed})
	out = c2.Flush(time.Time{})
	if out[0].VerdictScore != 10 {
		t.Fatalf("score = %v, want 10 for red", out[0].VerdictScore)
	}
}
