package destclass

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseAWS(t *testing.T) {
	body := []byte(`{
  "prefixes": [
    {"ip_prefix": "3.5.140.0/22", "region": "ap-northeast-2"},
    {"ip_prefix": "13.32.4.0/22", "region": "GLOBAL"}
  ],
  "ipv6_prefixes": [
    {"ipv6_prefix": "2600:1f00:1000::/40", "region": "us-west-2"}
  ]
}`)
	got, err := parseAWS(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Errorf("want 3 CIDRs, got %d: %v", len(got), got)
	}
}

func TestParseLineList(t *testing.T) {
	body := []byte(`# Cloudflare IPv4
103.21.244.0/22
103.22.200.0/22

# comment
104.16.0.0/13
`)
	got, err := parseLineList(body)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"103.21.244.0/22", "103.22.200.0/22", "104.16.0.0/13"}
	if len(got) != len(want) {
		t.Fatalf("count: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d]: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestSyncOnceUpdatesClassifier(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/aws":
			w.Write([]byte(`{"prefixes":[{"ip_prefix":"203.0.113.0/24"}],"ipv6_prefixes":[]}`))
		case "/cf":
			w.Write([]byte("198.51.100.0/24\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	c := New()
	feeds := []Feed{
		{Name: "aws", Class: ClassCloudProvider, URL: server.URL + "/aws", Parse: parseAWS},
		{Name: "cf", Class: ClassCDN, URL: server.URL + "/cf", Parse: parseLineList},
	}
	errs := SyncOnce(context.Background(), c, feeds, server.Client())
	if len(errs) > 0 {
		t.Fatalf("unexpected errs: %v", errs)
	}
	// IP from AWS feed.
	d := c.Classify(net.ParseIP("203.0.113.5"), "", 443)
	if d.Class != ClassCloudProvider {
		t.Errorf("post-sync AWS classify: got %s want cloud_provider", d.Class)
	}
	// IP from CF feed.
	d = c.Classify(net.ParseIP("198.51.100.10"), "", 443)
	if d.Class != ClassCDN {
		t.Errorf("post-sync CF classify: got %s want cdn", d.Class)
	}
}

func TestSyncOncePerFeedErrorIsolated(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("198.51.100.0/24\n"))
	}))
	defer good.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", 500)
	}))
	defer bad.Close()
	c := New()
	feeds := []Feed{
		{Name: "bad", Class: ClassCDN, URL: bad.URL, Parse: parseLineList},
		{Name: "good", Class: ClassCDN, URL: good.URL, Parse: parseLineList},
	}
	errs := SyncOnce(context.Background(), c, feeds, good.Client())
	if len(errs) != 1 {
		t.Errorf("want 1 error (bad feed only), got %d: %v", len(errs), errs)
	}
	// Good feed should still have updated the classifier.
	d := c.Classify(net.ParseIP("198.51.100.10"), "", 443)
	if d.Class != ClassCDN {
		t.Errorf("good feed should apply: got %s", d.Class)
	}
}
