package credbroker

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAppContractLoadAndMatch(t *testing.T) {
	dir := t.TempDir()
	yaml := `
binary: /opt/myapp/bin/server
allowed_credentials:
  - /etc/myapp/db.sealed
  - /etc/myapp/aws.sealed
purpose: db_query
max_opens_per_min: 0
`
	if err := os.WriteFile(filepath.Join(dir, "myapp.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	set, errs := LoadAppContractsDir(dir)
	if len(errs) > 0 {
		t.Fatalf("load errors: %v", errs)
	}
	if got := len(set.Contracts()); got != 1 {
		t.Fatalf("want 1 contract, got %d", got)
	}
	if !set.HasContractFor("/etc/myapp/db.sealed") {
		t.Fatal("HasContractFor should report true for declared path")
	}
	if set.HasContractFor("/etc/other/x.sealed") {
		t.Fatal("HasContractFor should report false for undeclared path")
	}

	now := time.Now()
	// Authentic binary, declared path → match.
	lineage := []LineageNode{{PID: 100, Image: "/opt/myapp/bin/server"}}
	res := set.Match(lineage, "/etc/myapp/db.sealed", now)
	if !res.Matched {
		t.Errorf("authentic match should succeed: %s", res.Reason)
	}
	// Wrong binary → no match.
	lineage[0].Image = "/usr/bin/curl"
	res = set.Match(lineage, "/etc/myapp/db.sealed", now)
	if res.Matched {
		t.Errorf("unauthentic binary should not match")
	}
	// Right binary, undeclared path → no match.
	lineage[0].Image = "/opt/myapp/bin/server"
	res = set.Match(lineage, "/etc/other/x.sealed", now)
	if res.Matched {
		t.Errorf("undeclared path should not match")
	}
}

func TestAppContractRateLimit(t *testing.T) {
	dir := t.TempDir()
	yaml := `
binary: /opt/myapp/bin/server
allowed_credentials:
  - /etc/myapp/db.sealed
max_opens_per_min: 3
`
	if err := os.WriteFile(filepath.Join(dir, "ratecap.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	set, errs := LoadAppContractsDir(dir)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	now := time.Now()
	lineage := []LineageNode{{PID: 100, Image: "/opt/myapp/bin/server"}}
	for i := 0; i < 3; i++ {
		if !set.Match(lineage, "/etc/myapp/db.sealed", now).Matched {
			t.Fatalf("open %d should be allowed under cap", i+1)
		}
	}
	// 4th in same minute → denied by cap.
	if set.Match(lineage, "/etc/myapp/db.sealed", now).Matched {
		t.Error("4th open in same minute should be rate-capped")
	}
	// Advance >60s → cap window slides, allowed again.
	if !set.Match(lineage, "/etc/myapp/db.sealed", now.Add(61*time.Second)).Matched {
		t.Error("after 60s window the cap should reset")
	}
}

func TestAppContractMissingDirIsNotError(t *testing.T) {
	set, errs := LoadAppContractsDir("/nonexistent/path/here")
	if errs != nil {
		t.Errorf("missing dir should be silent, got: %v", errs)
	}
	if set == nil {
		t.Error("missing dir should yield empty set, not nil")
	}
	if len(set.Contracts()) != 0 {
		t.Errorf("empty set expected, got %d", len(set.Contracts()))
	}
}

func TestAppContractValidationFailures(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"empty_binary.yaml": `
allowed_credentials: [/etc/x.sealed]
`,
		"no_creds.yaml": `
binary: /opt/x
allowed_credentials: []
`,
		"malformed.yaml": "::: not yaml :::",
	}
	for name, body := range cases {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, errs := LoadAppContractsDir(dir)
	if len(errs) != len(cases) {
		t.Errorf("want %d load errors, got %d: %v", len(cases), len(errs), errs)
	}
}
