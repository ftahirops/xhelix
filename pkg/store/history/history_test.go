package history

import (
	"context"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpenAndSchemaIdempotent(t *testing.T) {
	s := newTestStore(t)
	// Re-applying schema must not error
	if err := applySchema(s.db); err != nil {
		t.Fatalf("re-apply schema: %v", err)
	}
}

func TestInsertSessionAndProcessAndActivityAndFlowAndDNS(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	t0 := time.Unix(1000, 0)
	sessID, err := s.InsertSession(ctx, Session{
		Kind: "login", Subject: "alice", CGroupClass: "user", StartedAt: t0,
	})
	if err != nil || sessID == 0 {
		t.Fatalf("insert session: %v, id=%d", err, sessID)
	}

	procID, err := s.InsertProcess(ctx, Process{
		SessionID: sessID,
		PID:       42, PPID: 1,
		Comm: "firefox", Exe: "/usr/bin/firefox", ExeSHA: "abc",
		CGroupClass: "user", Unit: "firefox.service", UserID: "1000",
		StartedAt: t0,
	})
	if err != nil || procID == 0 {
		t.Fatalf("insert process: %v, id=%d", err, procID)
	}

	actID, err := s.InsertActivity(ctx, Activity{
		ProcessID:    procID,
		StartedAt:    t0,
		EndedAt:      t0.Add(time.Minute),
		PrimaryHost:  "example.com",
		RelatedHosts: []string{"fonts.gstatic.com", "ajax.googleapis.com"},
		PrimaryIP:    "1.2.3.4",
		RelatedIPs:   []string{"5.6.7.8"},
		Countries:    []string{"US"},
		ASNs:         []string{"AS15169"},
		BytesIn:      4 * 1024 * 1024,
		BytesOut:     12 * 1024,
		FlowCount:    14,
		Verdict:      "green",
		VerdictScore: 92.0,
		Reasons:      []string{"all_intel_clean", "baseline_match"},
		Protocols:    "tcp",
	})
	if err != nil || actID == 0 {
		t.Fatalf("insert activity: %v, id=%d", err, actID)
	}

	flowID, err := s.InsertFlow(ctx, Flow{
		ActivityID: actID, ProcessID: procID,
		Proto: "tcp", SrcIP: "10.0.0.5", SrcPort: 49152,
		DstIP: "1.2.3.4", DstPort: 443, State: "established",
		OpenedAt: t0, BytesIn: 100000, BytesOut: 2000,
		DNSQName: "example.com", Country: "US", ASN: "AS15169",
	})
	if err != nil || flowID == 0 {
		t.Fatalf("insert flow: %v, id=%d", err, flowID)
	}

	dnsID, err := s.InsertDNSQuery(ctx, DNSQuery{
		ProcessID: procID, AskedAt: t0,
		QName: "example.com", QType: "A",
		Answers: []string{"1.2.3.4"}, Upstream: "127.0.0.53",
	})
	if err != nil || dnsID == 0 {
		t.Fatalf("insert dns: %v, id=%d", err, dnsID)
	}

	c, err := s.Counts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c.Sessions != 1 || c.Processes != 1 || c.Activities != 1 ||
		c.Flows != 1 || c.DNSQueries != 1 {
		t.Fatalf("counts = %+v", c)
	}
}

func TestEndSessionAndProcess(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	t0 := time.Unix(1000, 0)
	sid, _ := s.InsertSession(ctx, Session{Kind: "login", Subject: "x", StartedAt: t0})
	pid, _ := s.InsertProcess(ctx, Process{PID: 1, StartedAt: t0, SessionID: sid})

	end := t0.Add(time.Hour)
	if err := s.EndSession(ctx, sid, end); err != nil {
		t.Fatal(err)
	}
	if err := s.EndProcess(ctx, pid, end); err != nil {
		t.Fatal(err)
	}

	var got int64
	_ = s.db.QueryRow(`SELECT ended_at FROM sessions WHERE id=?`, sid).Scan(&got)
	if got != end.Unix() {
		t.Fatalf("session ended_at = %d, want %d", got, end.Unix())
	}
	_ = s.db.QueryRow(`SELECT ended_at FROM processes WHERE id=?`, pid).Scan(&got)
	if got != end.Unix() {
		t.Fatalf("process ended_at = %d, want %d", got, end.Unix())
	}
}

func TestPruneRespectsRetention(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	old := time.Unix(1000, 0)
	mid := time.Unix(2000, 0)
	now := time.Unix(3000, 0)

	sid, _ := s.InsertSession(ctx, Session{Kind: "login", Subject: "x", StartedAt: old})
	pid, _ := s.InsertProcess(ctx, Process{SessionID: sid, PID: 1, StartedAt: old})

	// Old flow + DNS, mid activity. Both should be expired by short retention.
	_, _ = s.InsertFlow(ctx, Flow{ProcessID: pid, Proto: "tcp", DstIP: "1.1.1.1",
		OpenedAt: old})
	_, _ = s.InsertFlow(ctx, Flow{ProcessID: pid, Proto: "tcp", DstIP: "2.2.2.2",
		OpenedAt: now}) // current
	_, _ = s.InsertDNSQuery(ctx, DNSQuery{ProcessID: pid, AskedAt: old, QName: "a"})
	_, _ = s.InsertDNSQuery(ctx, DNSQuery{ProcessID: pid, AskedAt: now, QName: "b"})
	_, _ = s.InsertActivity(ctx, Activity{ProcessID: pid, StartedAt: old, EndedAt: old, Verdict: "green"})
	_, _ = s.InsertActivity(ctx, Activity{ProcessID: pid, StartedAt: mid, EndedAt: mid, Verdict: "green"})

	r := Retention{
		Flows:      time.Second,           // very short
		DNS:        time.Second,
		Activities: time.Second,
		Processes:  time.Hour,
		Sessions:   time.Hour,
	}
	res, err := s.Prune(ctx, r, now)
	if err != nil {
		t.Fatal(err)
	}
	// 1 old flow, 1 old dns, 2 old activities pruned (mid is older than 1s before now=3000)
	if res.Flows != 1 {
		t.Errorf("pruned flows = %d, want 1", res.Flows)
	}
	if res.DNSQueries != 1 {
		t.Errorf("pruned dns = %d, want 1", res.DNSQueries)
	}
	if res.Activities != 2 {
		t.Errorf("pruned activities = %d, want 2", res.Activities)
	}
}

func TestDefaultRetention(t *testing.T) {
	r := DefaultRetention()
	if r.Flows != 7*24*time.Hour {
		t.Errorf("flows = %v", r.Flows)
	}
	if r.DNS != 14*24*time.Hour {
		t.Errorf("dns = %v", r.DNS)
	}
	if r.Activities != 90*24*time.Hour {
		t.Errorf("activities = %v", r.Activities)
	}
}

func TestFlowWithoutActivity(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	pid, _ := s.InsertProcess(ctx, Process{PID: 1, StartedAt: time.Unix(100, 0)})

	// ActivityID = 0 → NULL in DB
	fid, err := s.InsertFlow(ctx, Flow{
		ProcessID: pid, Proto: "tcp", DstIP: "1.1.1.1", OpenedAt: time.Unix(100, 0),
	})
	if err != nil || fid == 0 {
		t.Fatalf("insert flow: %v, id=%d", err, fid)
	}
	var actID *int64
	_ = s.db.QueryRow(`SELECT activity_id FROM flows WHERE id=?`, fid).Scan(&actID)
	if actID != nil {
		t.Fatalf("activity_id should be NULL, got %v", *actID)
	}
}

func TestActivityJSONArraysRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	pid, _ := s.InsertProcess(ctx, Process{PID: 1, StartedAt: time.Unix(100, 0)})

	in := Activity{
		ProcessID:    pid,
		StartedAt:    time.Unix(100, 0),
		EndedAt:      time.Unix(160, 0),
		RelatedHosts: []string{"a.example", "b.example"},
		Countries:    []string{"US", "DE"},
		ASNs:         []string{"AS1", "AS2"},
		Reasons:      []string{"r1", "r2"},
	}
	aid, err := s.InsertActivity(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	var rh, cn, an, rs string
	err = s.db.QueryRow(
		`SELECT related_hosts, countries, asns, reasons FROM activities WHERE id=?`,
		aid).Scan(&rh, &cn, &an, &rs)
	if err != nil {
		t.Fatal(err)
	}
	if rh != `["a.example","b.example"]` {
		t.Errorf("related_hosts = %s", rh)
	}
	if cn != `["US","DE"]` {
		t.Errorf("countries = %s", cn)
	}
	if an != `["AS1","AS2"]` {
		t.Errorf("asns = %s", an)
	}
	if rs != `["r1","r2"]` {
		t.Errorf("reasons = %s", rs)
	}
}

func TestEmptyCounts(t *testing.T) {
	s := newTestStore(t)
	c, err := s.Counts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c.Sessions != 0 || c.Processes != 0 || c.Activities != 0 ||
		c.Flows != 0 || c.DNSQueries != 0 {
		t.Fatalf("non-zero on empty store: %+v", c)
	}
}
