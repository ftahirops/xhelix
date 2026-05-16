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
