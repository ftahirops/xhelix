package procscrape

import (
	"os"
	"testing"
)

// Locks in the 2026-06-05 prod FP-tuning: the benign system actors that
// were tripping cred_proc_scrape must now be allowlisted, while an
// unknown scraper must STILL fire (detection preserved, not silenced).
func TestAllowlistBenignProcReaders(t *testing.T) {
	a := Default()

	allowed := []struct{ comm, image string }{
		{"needrestart", ""},
		{"cloud-id", ""},
		{"sw-engine", ""},      // Plesk
		{"filwrpr", ""},        // Plesk filemng wrapper
		{"imunify-notifie", ""}, // ImunifyAV (16-char truncated)
		{"timed-trigger", ""},
		{"systemctl", ""},
		{"systemd-detect-", ""},                                              // prefix family
		{"systemd-fstab-g", ""},                                              // prefix family
		{"", "/usr/lib/systemd/system-generators/systemd-fstab-generator"},   // nested glob
		{"", "/lib/systemd/system-generators/systemd-getty-generator"},       // nested glob
	}
	for _, c := range allowed {
		if !a.IsAllowed(c.comm, c.image) {
			t.Errorf("expected ALLOWED (benign): comm=%q image=%q", c.comm, c.image)
		}
	}

	// Detection preserved: an unknown process scraping /proc must still fire.
	denied := []struct{ comm, image string }{
		{"evilscraper", "/tmp/x"},
		{"php-fpm", "/opt/plesk/php/8.3/sbin/php-fpm"}, // a web worker reading other procs' environ IS suspicious
		{"systemdd", ""},                              // typosquat must NOT match the "systemd-" prefix
		{"notsystemd-x", ""},                          // prefix must be leading
	}
	for _, c := range denied {
		if a.IsAllowed(c.comm, c.image) {
			t.Errorf("expected NOT allowed (must still fire): comm=%q image=%q", c.comm, c.image)
		}
	}
}

// comm_prefix: directive in an operator allowlist file must work.
func TestAllowlistCommPrefixFromFile(t *testing.T) {
	a := &Allowlist{Comms: map[string]struct{}{}, Images: map[string]struct{}{}}
	dir := t.TempDir()
	f := dir + "/allow.conf"
	if err := os.WriteFile(f, []byte("comm_prefix: myagent-\ncomm: solo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.LoadFile(f); err != nil {
		t.Fatal(err)
	}
	if !a.IsAllowed("myagent-worker", "") {
		t.Error("comm_prefix from file should allow myagent-worker")
	}
	if !a.IsAllowed("solo", "") {
		t.Error("comm from file should allow solo")
	}
	if a.IsAllowed("other", "") {
		t.Error("unrelated comm must not be allowed")
	}
}
