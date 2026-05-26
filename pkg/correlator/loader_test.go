package correlator

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadFromDir_MissingIsNoError(t *testing.T) {
	rules, err := LoadFromDir("/nonexistent/path/xyz123")
	if err != nil {
		t.Errorf("missing dir should return nil err, got: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("missing dir should yield 0 rules, got %d", len(rules))
	}
}

func TestLoadFromDir_MultiDocFile(t *testing.T) {
	dir := t.TempDir()
	content := `---
id: rule_one
desc: first rule
severity: high
window: 10m
group_by: [cgroup_id]
steps:
  - select: 'event.sensor == "ebpf.net"'
    within: 30s
  - select: 'event.sensor == "fim"'
---
id: rule_two
desc: second rule
severity: warn
window: 5m
group_by: [pid]
steps:
  - select: 'event.sensor == "identity.sshd"'
`
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadFromDir(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("rules=%d want 2", len(rules))
	}
	if rules[0].ID != "rule_one" || rules[1].ID != "rule_two" {
		t.Errorf("rule IDs mismatch: %s, %s", rules[0].ID, rules[1].ID)
	}
	if rules[0].Window != 10*time.Minute {
		t.Errorf("rule_one window=%v want 10m", rules[0].Window)
	}
	if len(rules[0].Steps) != 2 {
		t.Errorf("rule_one steps=%d want 2", len(rules[0].Steps))
	}
}

func TestLoadFromDir_DeterministicOrder(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"b.yaml", "a.yaml", "c.yaml"} {
		content := "id: r_" + name[0:1] + "\ndesc: x\nsteps:\n  - select: 'true'\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	rules, _ := LoadFromDir(dir)
	if len(rules) != 3 || rules[0].ID != "r_a" || rules[1].ID != "r_b" || rules[2].ID != "r_c" {
		t.Errorf("order not alphabetic by filename: %+v", rules)
	}
}

func TestLoadFromDir_BadRuleSurfacedAsError(t *testing.T) {
	dir := t.TempDir()
	bad := "id: bad\nseverity: not_a_severity\nsteps:\n  - select: 'true'\n"
	good := "id: good\nseverity: high\nsteps:\n  - select: 'true'\n"
	_ = os.WriteFile(filepath.Join(dir, "01-bad.yaml"), []byte(bad), 0644)
	_ = os.WriteFile(filepath.Join(dir, "02-good.yaml"), []byte(good), 0644)
	rules, err := LoadFromDir(dir)
	if err == nil {
		t.Error("expected error for invalid severity")
	}
	// good rule should still be present
	foundGood := false
	for _, r := range rules {
		if r.ID == "good" {
			foundGood = true
		}
	}
	if !foundGood {
		t.Errorf("good rule should be returned alongside the bad-rule error")
	}
}
