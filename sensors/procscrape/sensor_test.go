package procscrape

import (
	"os"
	"testing"

	"github.com/xhelix/xhelix/pkg/model"
)

func newScrapeEvent(readerPID uint32, comm, image, targetPID string) *model.Event {
	ev := model.NewEvent("ebpf.procscrape", model.SeverityNotice)
	ev.PID = readerPID
	ev.Comm = comm
	ev.Image = image
	ev.Tags["kind"] = "proc_scrape"
	ev.Tags["target_pid"] = targetPID
	ev.Tags["scrape_kind"] = "environ"
	return &ev
}

func TestEnrich_SelfReadAllowed(t *testing.T) {
	s := NewSensor(Default())
	ev := newScrapeEvent(1234, "weird-binary", "/tmp/x", "1234")
	s.Enrich(ev)
	if ev.Tags["allowlisted_reader"] != "true" {
		t.Fatalf("self-read not allowlisted: %#v", ev.Tags)
	}
	if ev.Tags["cred_proc_scrape"] == "true" {
		t.Fatalf("self-read should not flag cred_proc_scrape")
	}
}

func TestEnrich_AllowedComm(t *testing.T) {
	s := NewSensor(Default())
	ev := newScrapeEvent(100, "htop", "/usr/bin/htop", "200")
	s.Enrich(ev)
	if ev.Tags["allowlisted_reader"] != "true" {
		t.Fatalf("htop must be allowlisted: %#v", ev.Tags)
	}
}

func TestEnrich_FlagsUnknownReader(t *testing.T) {
	s := NewSensor(Default())
	ev := newScrapeEvent(100, "wp-cli", "/tmp/exfil", "200")
	s.Enrich(ev)
	if ev.Tags["cred_proc_scrape"] != "true" {
		t.Fatalf("expected cred_proc_scrape=true, got %#v", ev.Tags)
	}
	if ev.Severity < model.SeverityWarn {
		t.Fatalf("severity not raised: %v", ev.Severity)
	}
	if got, _, _ := s.Stats(); got != 1 {
		t.Fatalf("seen counter: %d", got)
	}
}

func TestEnrich_NonScrapeEventIgnored(t *testing.T) {
	s := NewSensor(Default())
	ev := model.NewEvent("ebpf.net", model.SeverityNotice)
	ev.Tags["kind"] = "net_connect"
	before := ev.Severity
	s.Enrich(&ev)
	if ev.Severity != before {
		t.Fatalf("non-scrape event modified")
	}
	if _, ok := ev.Tags["cred_proc_scrape"]; ok {
		t.Fatalf("non-scrape event tagged")
	}
}

func TestAllowlist_LoadFile(t *testing.T) {
	a := Default()
	before := a.Size()
	tmp := t.TempDir() + "/allow"
	if err := writeFile(tmp, "# comment\ncomm: custom-agent\nimage: /opt/x/y\nglob: /opt/sec/*\n"); err != nil {
		t.Fatal(err)
	}
	if err := a.LoadFile(tmp); err != nil {
		t.Fatal(err)
	}
	if a.Size() != before+3 {
		t.Fatalf("size %d want %d", a.Size(), before+3)
	}
	if !a.IsAllowed("custom-agent", "") {
		t.Fatal("comm not loaded")
	}
	if !a.IsAllowed("", "/opt/x/y") {
		t.Fatal("image not loaded")
	}
	if !a.IsAllowed("", "/opt/sec/scanner") {
		t.Fatal("glob not loaded")
	}
}

func writeFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}

// TestEnrichSelfReadViaProcSelfSymlink guards the 2026-06-15 FP fix:
// reading /proc/self/maps (literal "self", no numeric target_pid) must
// be treated as a self-read, not cred_proc_scrape. ip/node/runc hit this.
func TestEnrichSelfReadViaProcSelfSymlink(t *testing.T) {
	s := NewSensor(Default())
	for _, p := range []string{"/proc/self/maps", "/proc/self/environ", "/proc/thread-self/maps"} {
		ev := &model.Event{PID: 4242, Comm: "ip", Image: "/usr/bin/ip",
			Tags: map[string]string{"kind": "proc_scrape", "path": p, "scrape_kind": "maps"}}
		s.Enrich(ev)
		if ev.Tags["cred_proc_scrape"] == "true" {
			t.Errorf("path %s: self-read flagged as cred_proc_scrape (FP)", p)
		}
		if ev.Tags["allowlist_reason"] != "self-read-symlink" {
			t.Errorf("path %s: expected self-read-symlink, got %q", p, ev.Tags["allowlist_reason"])
		}
	}
	// Sanity: reading ANOTHER pid's maps is still flagged.
	ev := &model.Event{PID: 4242, Comm: "evil", Image: "/tmp/evil",
		Tags: map[string]string{"kind": "proc_scrape", "path": "/proc/999/maps", "target_pid": "999", "scrape_kind": "maps"}}
	s.Enrich(ev)
	if ev.Tags["cred_proc_scrape"] != "true" {
		t.Error("reading another pid's maps must still flag cred_proc_scrape")
	}
}
