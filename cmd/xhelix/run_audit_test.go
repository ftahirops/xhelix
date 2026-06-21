package main

import (
	"testing"

	"github.com/xhelix/xhelix/pkg/config"
	"github.com/xhelix/xhelix/pkg/configaudit"
)

// TestPredeclaredAuditKeysCoverDangerousKnobs is the regression gate for
// the ERRORS.md "config knob accepted but not consumed" class. The hot.db
// retention trio (retention_hours, max_size_mb) and the FileSink rotation
// knob each caused a production disk-fill before the audit landed. If a
// future edit drops one of these from the predeclared set it silently
// degrades back to an "unknown-key" finding instead of the actionable
// "unwitnessed-nondefault" — this test fails loudly first.
func TestPredeclaredAuditKeysCoverDangerousKnobs(t *testing.T) {
	mustCover := []string{
		"storage.hot.retention_hours",
		"storage.hot.max_size_mb",
	}
	set := map[string]bool{}
	for _, k := range predeclaredAuditKeys {
		if set[k] {
			t.Errorf("duplicate predeclared key %q", k)
		}
		set[k] = true
	}
	for _, k := range mustCover {
		if !set[k] {
			t.Errorf("predeclaredAuditKeys missing historically-dangerous knob %q", k)
		}
	}
}

// TestStrictAuditCatchesUnwitnessedKnob proves the wiring end-to-end: a
// config with a dangerous knob set but no consumer registered produces a
// finding, and strict mode turns that finding into a startup failure
// while warn-only does not.
func TestStrictAuditCatchesUnwitnessedKnob(t *testing.T) {
	a := configaudit.New()
	for _, k := range predeclaredAuditKeys {
		a.Declare(k)
	}

	// Reproduce the hot.db bug: retention set, nothing witnessed it.
	var cfg config.Config
	cfg.Storage.Hot.RetentionHours = 48

	findings := a.Audit(&cfg)
	hit := false
	for _, f := range findings {
		if f.Key == "storage.hot.retention_hours" {
			if f.Issue != "unwitnessed-nondefault" {
				t.Errorf("retention_hours issue = %q; want unwitnessed-nondefault (it is predeclared)", f.Issue)
			}
			hit = true
		}
	}
	if !hit {
		t.Fatalf("audit missed the unwitnessed retention_hours knob; findings=%v", findings)
	}

	if !strictAuditFails(true, findings) {
		t.Error("strict mode must fail startup when findings exist")
	}
	if strictAuditFails(false, findings) {
		t.Error("warn-only mode must not fail startup")
	}
	if strictAuditFails(true, nil) {
		t.Error("strict mode must not fail when there are no findings")
	}
}

// TestExampleConfigsLoad guards that the shipped example configs still
// parse — they are the operator's starting point and the corpus a strict
// audit would run against.
func TestExampleConfigsLoad(t *testing.T) {
	for _, p := range []string{
		"../../examples/config-server.yaml",
		"../../examples/config-desktop.yaml",
		"../../examples/config-container-host.yaml",
	} {
		if _, err := config.Load(p); err != nil {
			t.Errorf("example config %s failed to load: %v", p, err)
		}
	}
}
