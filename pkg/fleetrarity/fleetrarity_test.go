package fleetrarity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func fakeHub(totalHosts int, rareEndpoints []string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type rareEndpoint struct {
			Endpoint   string `json:"endpoint"`
			Hosts      int    `json:"hosts"`
			TotalHosts int    `json:"total_hosts"`
		}
		type rareList struct {
			Binary     string         `json:"binary"`
			TotalHosts int            `json:"total_hosts"`
			Rare       []rareEndpoint `json:"rare"`
		}
		out := rareList{Binary: r.URL.Query().Get("binary"), TotalHosts: totalHosts}
		for _, e := range rareEndpoints {
			out.Rare = append(out.Rare, rareEndpoint{Endpoint: e, Hosts: 1, TotalHosts: totalHosts})
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
}

func TestClient_RareEndpoint(t *testing.T) {
	hub := fakeHub(50, []string{"1.2.3.4:443"})
	defer hub.Close()
	c := NewClient(Config{HubURL: hub.URL, MinCohort: 5, CacheTTL: time.Minute})
	r := c.Lookup("nginx", "1.2.3.4:443")
	if !r.Known || !r.Rare {
		t.Fatalf("rare endpoint, cohort 50 → Known+Rare, got %+v", r)
	}
	if r.CohortSize != 50 {
		t.Fatalf("cohort: got %d want 50", r.CohortSize)
	}
}

func TestClient_CommonEndpoint(t *testing.T) {
	hub := fakeHub(50, []string{"1.2.3.4:443"})
	defer hub.Close()
	c := NewClient(Config{HubURL: hub.URL, MinCohort: 5, CacheTTL: time.Minute})
	r := c.Lookup("nginx", "9.9.9.9:443")
	if !r.Known {
		t.Fatal("successful hub response → Known")
	}
	if r.Rare {
		t.Fatal("endpoint not in rare list → common")
	}
}

func TestClient_SmallCohort_Unknown(t *testing.T) {
	hub := fakeHub(3, []string{"1.2.3.4:443"})
	defer hub.Close()
	c := NewClient(Config{HubURL: hub.URL, MinCohort: 5, CacheTTL: time.Minute})
	if r := c.Lookup("nginx", "1.2.3.4:443"); r.Known {
		t.Fatalf("cohort 3 < min 5 → Unknown, got %+v", r)
	}
}

func TestClient_HubDown_Unknown(t *testing.T) {
	c := NewClient(Config{HubURL: "http://127.0.0.1:1", MinCohort: 5, CacheTTL: time.Minute, Timeout: 500 * time.Millisecond})
	if r := c.Lookup("nginx", "1.2.3.4:443"); r.Known {
		t.Fatal("unreachable hub → Unknown")
	}
}

func TestClient_Caches(t *testing.T) {
	var hits int
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"binary":"nginx","total_hosts":50,"rare":[{"endpoint":"1.2.3.4:443","hosts":1,"total_hosts":50}]}`))
	}))
	defer hub.Close()
	c := NewClient(Config{HubURL: hub.URL, MinCohort: 5, CacheTTL: time.Minute})
	c.Lookup("nginx", "1.2.3.4:443")
	c.Lookup("nginx", "5.6.7.8:443") // same binary → cache hit
	if hits != 1 {
		t.Fatalf("second same-binary lookup must hit cache, got %d HTTP calls", hits)
	}
}

func TestClient_ImplementsProvider(t *testing.T) {
	var _ Provider = NewClient(Config{HubURL: "http://x"})
}
