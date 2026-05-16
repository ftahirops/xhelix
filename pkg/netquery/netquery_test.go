package netquery

import (
	"context"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/store/history"
)

func seedStore(t *testing.T) (*history.Store, time.Time) {
	t.Helper()
	s, err := history.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	t0 := time.Unix(1000, 0)

	pidFF, _ := s.InsertProcess(ctx, history.Process{
		PID: 100, Comm: "firefox", Exe: "/usr/bin/firefox",
		CGroupClass: "user", StartedAt: t0,
	})
	pidSnap, _ := s.InsertProcess(ctx, history.Process{
		PID: 200, Comm: "snapd", Exe: "/usr/bin/snapd",
		CGroupClass: "system", StartedAt: t0,
	})

	// Flows: firefox makes 3 connects (US), snapd 2 (NL), and one
	// orphan unattributed flow.
	mk := func(procID int64, ip, country string, in, out uint64, secs int64) history.Flow {
		return history.Flow{
			ProcessID: procID, Proto: "tcp",
			DstIP: ip, DstPort: 443, OpenedAt: t0.Add(time.Duration(secs) * time.Second),
			BytesIn: in, BytesOut: out, Country: country, ASN: "AS-X",
			DNSQName: "qname-" + ip,
		}
	}
	_, _ = s.InsertFlow(ctx, mk(pidFF, "1.1.1.1", "US", 1000000, 50000, 1))
	_, _ = s.InsertFlow(ctx, mk(pidFF, "2.2.2.2", "US", 500000, 20000, 5))
	_, _ = s.InsertFlow(ctx, mk(pidFF, "1.1.1.1", "US", 200000, 5000, 10))
	_, _ = s.InsertFlow(ctx, mk(pidSnap, "3.3.3.3", "NL", 100000, 6000000, 15))
	_, _ = s.InsertFlow(ctx, mk(pidSnap, "3.3.3.3", "NL", 50000, 500000, 20))
	_, _ = s.InsertFlow(ctx, mk(0, "9.9.9.9", "CN", 5000, 3000, 25))
	return s, t0
}

func TestTopApps(t *testing.T) {
	s, _ := seedStore(t)
	got, err := TopApps(context.Background(), s.DB(), Filter{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	// firefox: 1.7M+, snapd: 6.6M+, unknown: 8K
	if len(got) < 2 {
		t.Fatalf("got %d rows", len(got))
	}
	// Order should be snapd first by bytes
	if got[0].Exe != "/usr/bin/snapd" {
		t.Errorf("top app = %q, want snapd", got[0].Exe)
	}
}

func TestTopHosts(t *testing.T) {
	s, _ := seedStore(t)
	got, err := TopHosts(context.Background(), s.DB(), Filter{}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("no rows")
	}
	if got[0].DstIP != "3.3.3.3" { // largest bytes
		t.Errorf("top host = %q, want 3.3.3.3", got[0].DstIP)
	}
}

func TestTopCountries(t *testing.T) {
	s, _ := seedStore(t)
	got, err := TopCountries(context.Background(), s.DB(), Filter{}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 3 {
		t.Fatalf("got %d countries, want at least 3", len(got))
	}
}

func TestByProcess(t *testing.T) {
	s, _ := seedStore(t)
	got, err := ByProcess(context.Background(), s.DB(), Filter{})
	if err != nil {
		t.Fatal(err)
	}
	// firefox(100), snapd(200), and the unattributed flow (pid=0/null).
	if len(got) < 2 {
		t.Fatalf("got %d, want ≥2 attributed", len(got))
	}
	for _, p := range got {
		if p.Exe == "/usr/bin/firefox" && p.Connections != 3 {
			t.Errorf("firefox conns = %d, want 3", p.Connections)
		}
		if p.Exe == "/usr/bin/firefox" && p.Hosts != 2 {
			t.Errorf("firefox distinct hosts = %d, want 2", p.Hosts)
		}
	}
}

func TestUnknownTrafficFiltersAttributed(t *testing.T) {
	s, _ := seedStore(t)
	got, err := UnknownTraffic(context.Background(), s.DB(), Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d unknown rows, want 1", len(got))
	}
	if got[0].DstIP != "9.9.9.9" {
		t.Errorf("unknown dst = %q, want 9.9.9.9", got[0].DstIP)
	}
}

func TestFilterByCountry(t *testing.T) {
	s, _ := seedStore(t)
	got, _ := TopHosts(context.Background(), s.DB(), Filter{Country: "CN"}, 10)
	if len(got) != 1 || got[0].DstIP != "9.9.9.9" {
		t.Fatalf("CN-filter = %+v", got)
	}
}

func TestFilterByCGroupClass(t *testing.T) {
	s, _ := seedStore(t)
	got, _ := TopApps(context.Background(), s.DB(), Filter{CGroupClass: "user"}, 10)
	if len(got) != 1 || got[0].Exe != "/usr/bin/firefox" {
		t.Fatalf("user-class filter = %+v", got)
	}
}

func TestFilterBySinceUntil(t *testing.T) {
	s, t0 := seedStore(t)
	// Only the first two flows (at +1s and +5s).
	got, _ := TopHosts(context.Background(),
		s.DB(),
		Filter{Since: t0, Until: t0.Add(7 * time.Second)},
		10,
	)
	// Should not include 3.3.3.3 (at +15s/+20s) or 9.9.9.9 (+25s)
	for _, h := range got {
		if h.DstIP == "3.3.3.3" || h.DstIP == "9.9.9.9" {
			t.Errorf("late flow leaked into window: %+v", h)
		}
	}
}

func TestTimeSeries(t *testing.T) {
	s, _ := seedStore(t)
	got, err := TimeSeries(context.Background(), s.DB(), Filter{}, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("no buckets")
	}
	var total int64
	for _, p := range got {
		total += p.Flows
	}
	if total != 6 {
		t.Fatalf("flow count across buckets = %d, want 6", total)
	}
}
