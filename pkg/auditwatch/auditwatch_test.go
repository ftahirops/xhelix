package auditwatch

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// fakeAuditdHost lays out a tmpdir with a pid file pointing into a
// fake /proc tree and rules.d / audit.rules / auditd.conf files.
type fakeAuditdHost struct {
	root      string
	pid       uint32
	procRoot  string
	cfg       Config
}

func newFakeHost(t *testing.T, pid uint32, comm string, rules map[string]string, auditRules, conf string) *fakeAuditdHost {
	t.Helper()
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	rulesDir := filepath.Join(root, "etc", "audit", "rules.d")
	_ = os.MkdirAll(rulesDir, 0o755)
	_ = os.MkdirAll(filepath.Join(root, "etc", "audit"), 0o755)
	if pid != 0 {
		pidDir := filepath.Join(procRoot, strconv.FormatUint(uint64(pid), 10))
		_ = os.MkdirAll(pidDir, 0o755)
		_ = os.WriteFile(filepath.Join(pidDir, "comm"), []byte(comm+"\n"), 0o644)
	}
	pidFile := filepath.Join(root, "auditd.pid")
	if pid != 0 {
		_ = os.WriteFile(pidFile, []byte(strconv.FormatUint(uint64(pid), 10)+"\n"), 0o644)
	}
	for name, body := range rules {
		_ = os.WriteFile(filepath.Join(rulesDir, name), []byte(body), 0o644)
	}
	if auditRules != "" {
		_ = os.WriteFile(filepath.Join(root, "etc", "audit", "audit.rules"), []byte(auditRules), 0o644)
	}
	if conf != "" {
		_ = os.WriteFile(filepath.Join(root, "etc", "audit", "auditd.conf"), []byte(conf), 0o644)
	}
	return &fakeAuditdHost{
		root: root, pid: pid, procRoot: procRoot,
		cfg: Config{
			ProcRoot:       procRoot,
			PIDFile:        pidFile,
			RulesDir:       rulesDir,
			AuditRulesPath: filepath.Join(root, "etc", "audit", "audit.rules"),
			ConfPath:       filepath.Join(root, "etc", "audit", "auditd.conf"),
		},
	}
}

func TestSnapWithRunningAuditd(t *testing.T) {
	h := newFakeHost(t, 100, "auditd",
		map[string]string{"01-base.rules": "-a always,exit\n"},
		"-a always,exit\n",
		"local_events=yes\n",
	)
	s, err := Snap(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !s.AuditdRunning || s.AuditdPID != 100 {
		t.Fatalf("got %+v", s)
	}
	if len(s.RuleFiles) != 1 {
		t.Fatalf("rule files = %d", len(s.RuleFiles))
	}
	if s.AuditRulesHash == "" || s.ConfHash == "" {
		t.Fatalf("hashes missing: %+v", s)
	}
}

func TestSnapWithoutAuditd(t *testing.T) {
	h := newFakeHost(t, 0, "", nil, "", "")
	s, err := Snap(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.AuditdRunning {
		t.Fatalf("AuditdRunning = true on host with no auditd")
	}
}

func TestCompareDetectsAuditdStopped(t *testing.T) {
	h := newFakeHost(t, 100, "auditd", map[string]string{"01.rules": "x"}, "", "")
	base, _ := Snap(h.cfg)

	// "Stop" auditd by removing pidfile + /proc entry.
	_ = os.Remove(h.cfg.PIDFile)
	_ = os.RemoveAll(filepath.Join(h.procRoot, "100"))

	cur, _ := Snap(h.cfg)
	d := Compare(base, cur)
	if !d.AuditdStopped {
		t.Fatalf("AuditdStopped should be true: %+v", d)
	}
	if !d.HasCritical() {
		t.Fatal("HasCritical should be true on auditd stop")
	}
}

func TestCompareDetectsRulesAddedRemovedModified(t *testing.T) {
	h := newFakeHost(t, 100, "auditd",
		map[string]string{"a.rules": "1", "b.rules": "2"}, "", "")
	base, _ := Snap(h.cfg)

	// Remove b.rules, modify a.rules, add c.rules.
	_ = os.Remove(filepath.Join(h.cfg.RulesDir, "b.rules"))
	_ = os.WriteFile(filepath.Join(h.cfg.RulesDir, "a.rules"), []byte("CHANGED"), 0o644)
	_ = os.WriteFile(filepath.Join(h.cfg.RulesDir, "c.rules"), []byte("3"), 0o644)

	cur, _ := Snap(h.cfg)
	d := Compare(base, cur)
	if len(d.RulesAdded) != 1 || filepath.Base(d.RulesAdded[0]) != "c.rules" {
		t.Errorf("added: %v", d.RulesAdded)
	}
	if len(d.RulesRemoved) != 1 || filepath.Base(d.RulesRemoved[0]) != "b.rules" {
		t.Errorf("removed: %v", d.RulesRemoved)
	}
	if len(d.RulesModified) != 1 || filepath.Base(d.RulesModified[0]) != "a.rules" {
		t.Errorf("modified: %v", d.RulesModified)
	}
}

func TestCompareDetectsConfChange(t *testing.T) {
	h := newFakeHost(t, 100, "auditd", nil, "", "local_events=yes\n")
	base, _ := Snap(h.cfg)
	_ = os.WriteFile(h.cfg.ConfPath, []byte("local_events=no\n"), 0o644)
	cur, _ := Snap(h.cfg)
	d := Compare(base, cur)
	if !d.ConfChanged {
		t.Fatalf("ConfChanged should be true: %+v", d)
	}
}

func TestPidIsAuditdRejectsWrongComm(t *testing.T) {
	h := newFakeHost(t, 100, "imposter", nil, "", "")
	s, _ := Snap(h.cfg)
	if s.AuditdRunning {
		t.Fatal("AuditdRunning should be false when comm != auditd")
	}
}

func TestDiffIsEmpty(t *testing.T) {
	h := newFakeHost(t, 100, "auditd",
		map[string]string{"x.rules": "y"}, "z", "w")
	a, _ := Snap(h.cfg)
	b, _ := Snap(h.cfg)
	if !Compare(a, b).IsEmpty() {
		t.Fatal("identical snapshots should produce empty diff")
	}
}
