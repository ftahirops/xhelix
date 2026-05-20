package wizard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stub creates a controlled test tree under t.TempDir and returns its root.
func stub(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	// WordPress install
	wp := filepath.Join(root, "var", "www", "site")
	mustMkdirAll(t, wp)
	mustWrite(t, filepath.Join(wp, "wp-config.php"),
		"<?php define('DB_PASSWORD', 'secret'); ?>")

	// dotenv at app root
	app := filepath.Join(root, "srv", "myapp")
	mustMkdirAll(t, app)
	mustWrite(t, filepath.Join(app, ".env"), "DB_URL=postgres://...")
	mustWrite(t, filepath.Join(app, ".env.example"), "DB_URL=") // public template — skip

	// SSH keys
	ssh := filepath.Join(root, "root", ".ssh")
	mustMkdirAll(t, ssh)
	mustWrite(t, filepath.Join(ssh, "id_rsa"), "-----BEGIN OPENSSH PRIVATE KEY-----")
	mustWrite(t, filepath.Join(ssh, "id_rsa.pub"), "ssh-rsa AAAA...")
	mustWrite(t, filepath.Join(ssh, "authorized_keys"), "ssh-rsa AAAA...")
	mustWrite(t, filepath.Join(ssh, "known_hosts"), "github.com ssh-rsa ...")
	mustWrite(t, filepath.Join(ssh, "config"), "Host *")

	// TLS keys
	ssl := filepath.Join(root, "etc", "ssl", "private")
	mustMkdirAll(t, ssl)
	mustWrite(t, filepath.Join(ssl, "tls.key"), "-----BEGIN PRIVATE KEY-----")

	// Backups
	bk := filepath.Join(root, "srv", "backups")
	mustMkdirAll(t, bk)
	mustWrite(t, filepath.Join(bk, "2026-05-19.tar.gz"), "fake-archive")
	mustWrite(t, filepath.Join(bk, "dump.sql.gz"), "fake-sql-dump")

	// Cloud creds
	aws := filepath.Join(root, "root", ".aws")
	mustMkdirAll(t, aws)
	mustWrite(t, filepath.Join(aws, "credentials"),
		"[default]\naws_access_key_id = AKIA...\n")

	// kubectl config
	kube := filepath.Join(root, "root", ".kube")
	mustMkdirAll(t, kube)
	mustWrite(t, filepath.Join(kube, "config"), "apiVersion: v1")

	// .git tree (only .git/config should be flagged; internals ignored)
	git := filepath.Join(wp, ".git")
	mustMkdirAll(t, filepath.Join(git, "objects", "pack"))
	mustWrite(t, filepath.Join(git, "config"), "[core]\n")
	mustWrite(t, filepath.Join(git, "objects", "pack", "pack-abc.idx"), "binary")

	return root
}

func mustMkdirAll(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func findingPaths(fs []Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Path
	}
	return out
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if strings.HasSuffix(x, want) {
			return true
		}
	}
	return false
}

func TestScanner_FindsWPConfigEnvSSHTLSAWSKube(t *testing.T) {
	root := stub(t)
	s := New(Options{Roots: []string{root}})

	fs, err := s.Scan()
	if err != nil {
		t.Fatal(err)
	}
	paths := findingPaths(fs)

	mustFind := []string{
		"/wp-config.php",
		"/.env",
		"/.ssh/id_rsa",
		"/etc/ssl/private/tls.key",
		"/srv/backups/2026-05-19.tar.gz",
		"/srv/backups/dump.sql.gz",
		"/.aws/credentials",
		"/.kube/config",
	}
	for _, want := range mustFind {
		if !contains(paths, want) {
			t.Errorf("expected finding for path ending %q, got %v", want, paths)
		}
	}
}

func TestScanner_SkipsExamplePublicAndKnownFiles(t *testing.T) {
	root := stub(t)
	s := New(Options{Roots: []string{root}})
	fs, _ := s.Scan()
	paths := findingPaths(fs)

	mustNotFind := []string{
		"/.env.example",
		"/id_rsa.pub",
		"/authorized_keys",
		"/known_hosts",
		"/.ssh/config",
		"/.git/objects/pack/pack-abc.idx",
	}
	for _, x := range mustNotFind {
		for _, p := range paths {
			if strings.HasSuffix(p, x) {
				t.Errorf("should NOT have flagged %q (was %q)", x, p)
			}
		}
	}
}

func TestScanner_SortByConfidenceDescending(t *testing.T) {
	root := stub(t)
	s := New(Options{Roots: []string{root}})
	fs, _ := s.Scan()
	last := ConfidenceHigh
	for _, f := range fs {
		if f.Confidence > last {
			t.Errorf("findings out of order: %s before higher %s", last, f.Confidence)
		}
		last = f.Confidence
	}
}

func TestScanner_StopsAtMaxFindings(t *testing.T) {
	root := stub(t)
	s := New(Options{Roots: []string{root}, MaxFindings: 3})
	fs, _ := s.Scan()
	if len(fs) > 3 {
		t.Errorf("got %d findings, max was 3", len(fs))
	}
}

func TestScanner_SkipsPathsInSkipList(t *testing.T) {
	root := stub(t)
	// Pretend /etc is a skip prefix; the TLS key should disappear.
	s := New(Options{
		Roots:     []string{root},
		SkipPaths: append(DefaultSkipPaths(), filepath.Join(root, "etc")),
	})
	fs, _ := s.Scan()
	paths := findingPaths(fs)
	for _, p := range paths {
		if strings.Contains(p, "/etc/ssl/private/tls.key") {
			t.Errorf("scanner entered a skip-listed path: %s", p)
		}
	}
}

func TestProposedYAML_RoundtripShape(t *testing.T) {
	root := stub(t)
	s := New(Options{Roots: []string{root}})
	fs, _ := s.Scan()
	y := ProposedYAML(fs)

	if !strings.Contains(y, "paths:") {
		t.Error("expected paths: section")
	}
	if !strings.Contains(y, "wp-config.php") {
		t.Error("expected wp-config in YAML")
	}
	if !strings.Contains(y, "confidence: high") {
		t.Error("expected confidence comment in YAML")
	}
}

func TestProposedYAML_EmptyResultMessages(t *testing.T) {
	y := ProposedYAML(nil)
	if !strings.Contains(y, "No findings") {
		t.Errorf("empty result should explain itself, got:\n%s", y)
	}
}

func TestKindAndConfidence_StringStable(t *testing.T) {
	if Kind(99).String() != "unknown" {
		t.Error("unknown kind should stringify safely")
	}
	if ConfidenceLow.String() != "low" || ConfidenceMedium.String() != "medium" || ConfidenceHigh.String() != "high" {
		t.Error("confidence string mismatch")
	}
}
