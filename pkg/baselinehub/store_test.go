package baselinehub

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/baseline"
)

func TestIngestAndComputeRare(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	t0 := time.Now().UTC().Truncate(time.Hour)

	// 10 hosts in fleet — 9 of them connect nginx → 10.0.0.0/16:443.
	// 1 host (web-rogue) connects nginx → 203.0.113.0/16:443. That
	// endpoint should be RARE.
	for i := 0; i < 9; i++ {
		host := "web-" + string(rune('0'+i))
		err := st.IngestUpload(Upload{
			HostTag: host, RoleTag: "web",
			Windows: []*baseline.Window{{
				Binary:    "/usr/sbin/nginx",
				Hour:      t0,
				Events:    100,
				Endpoints: map[string]uint64{"10.0.0.0/16:443": 50},
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	err = st.IngestUpload(Upload{
		HostTag: "web-rogue", RoleTag: "web",
		Windows: []*baseline.Window{{
			Binary:    "/usr/sbin/nginx",
			Hour:      t0,
			Events:    100,
			Endpoints: map[string]uint64{
				"10.0.0.0/16:443":    50,
				"203.0.113.0/16:443": 1, // unique to this host
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	rare, err := st.ComputeRare("/usr/sbin/nginx", 30, 0.8)
	if err != nil {
		t.Fatal(err)
	}
	if rare.TotalHosts != 10 {
		t.Errorf("total hosts = %d", rare.TotalHosts)
	}
	if len(rare.Rare) == 0 {
		t.Fatal("expected at least one rare endpoint")
	}
	// 203.0.113.0/16:443 seen on 1/10 hosts = rarity 0.9
	found := false
	for _, e := range rare.Rare {
		if e.Endpoint == "203.0.113.0/16:443" {
			found = true
			if e.HostsSeen != 1 || e.TotalHosts != 10 {
				t.Errorf("counts = %d/%d", e.HostsSeen, e.TotalHosts)
			}
			if e.Rarity < 0.85 || e.Rarity > 0.95 {
				t.Errorf("rarity = %f", e.Rarity)
			}
		}
	}
	if !found {
		t.Errorf("rogue endpoint not flagged: %+v", rare.Rare)
	}
	// 10.0.0.0/16:443 seen on 10/10 hosts = NOT rare
	for _, e := range rare.Rare {
		if e.Endpoint == "10.0.0.0/16:443" {
			t.Errorf("common endpoint should not be in rare list: %+v", e)
		}
	}
}

func TestComputeRareFiltered_ExcludesUntrustedHosts(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	t0 := time.Now().UTC().Truncate(time.Hour)

	seed := func(host string, ep string) {
		t.Helper()
		if err := st.IngestUpload(Upload{
			HostTag: host, RoleTag: "web",
			Windows: []*baseline.Window{{
				Binary:    "/usr/sbin/nginx",
				Hour:      t0,
				Events:    100,
				Endpoints: map[string]uint64{ep: 50},
			}},
		}); err != nil {
			t.Fatal(err)
		}
	}

	// hostA, hostB talk only to the common endpoint; hostEvil is the
	// ONLY host talking to the rare endpoint.
	seed("hostA", "1.1.0.0/16:443")
	seed("hostB", "1.1.0.0/16:443")
	seed("hostEvil", "9.9.0.0/16:443")

	// Unfiltered: 3 hosts, evil's endpoint is rare (1/3, rarity .67).
	all, err := st.ComputeRare("/usr/sbin/nginx", 7, 0.5)
	if err != nil {
		t.Fatal(err)
	}
	if all.TotalHosts != 3 {
		t.Fatalf("unfiltered TotalHosts: got %d want 3", all.TotalHosts)
	}
	if !containsEndpoint(all.Rare, "9.9.0.0/16:443") {
		t.Fatalf("unfiltered: evil endpoint should be rare: %+v", all.Rare)
	}

	// Filtered to exclude hostEvil: 2 hosts, evil's endpoint gone
	// entirely (its only host was pruned).
	trusted := func(h string) bool { return h != "hostEvil" }
	filt, err := st.ComputeRareFiltered("/usr/sbin/nginx", 7, 0.5, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if filt.TotalHosts != 2 {
		t.Fatalf("filtered TotalHosts: got %d want 2", filt.TotalHosts)
	}
	if containsEndpoint(filt.Rare, "9.9.0.0/16:443") {
		t.Fatalf("filtered: evil endpoint must be excluded entirely: %+v", filt.Rare)
	}

	// nil predicate == ComputeRare (no-op): all 3 hosts.
	nilf, err := st.ComputeRareFiltered("/usr/sbin/nginx", 7, 0.5, nil)
	if err != nil {
		t.Fatal(err)
	}
	if nilf.TotalHosts != 3 {
		t.Fatalf("nil predicate must include all: got %d want 3", nilf.TotalHosts)
	}
	if !containsEndpoint(nilf.Rare, "9.9.0.0/16:443") {
		t.Fatalf("nil predicate: evil endpoint should be rare: %+v", nilf.Rare)
	}
}

func containsEndpoint(rare []RareEndpoint, ep string) bool {
	for _, r := range rare {
		if r.Endpoint == ep {
			return true
		}
	}
	return false
}

func TestStoreSanitize(t *testing.T) {
	cases := map[string]string{
		"web-01":           "web-01",
		"web/01":           "web_01",
		"":                 "_",
		"WebServer.prod":   "WebServer.prod",
		"with spaces":      "with_spaces",
	}
	for in, want := range cases {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFileBaseDay(t *testing.T) {
	got := fileBaseDay(filepath.Join("/var/lib/xhub/feed/2026-05-04/web-01.jsonl"))
	if got != "2026-05-04" {
		t.Errorf("got %q", got)
	}
}
