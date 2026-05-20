package configaudit

import (
	"testing"
)

type fakeCfg struct {
	Storage struct {
		Hot struct {
			Path           string `yaml:"path"`
			RetentionHours int    `yaml:"retention_hours"`
			MaxSizeMB      int    `yaml:"max_size_mb"`
		} `yaml:"hot"`
		Cold struct {
			Enabled bool   `yaml:"enabled"`
			Path    string `yaml:"path"`
		} `yaml:"cold"`
	} `yaml:"storage"`
	Alerts struct {
		Sinks []struct {
			Kind         string `yaml:"kind"`
			Path         string `yaml:"path"`
			RotateSizeMB int    `yaml:"rotate_size_mb"`
			Keep         int    `yaml:"keep"`
		} `yaml:"sinks"`
	} `yaml:"alerts"`
}

func makeCfg() fakeCfg {
	var c fakeCfg
	c.Storage.Hot.Path = "/var/lib/xhelix/hot.db"
	c.Storage.Hot.RetentionHours = 24
	c.Storage.Hot.MaxSizeMB = 2048
	c.Alerts.Sinks = []struct {
		Kind         string `yaml:"kind"`
		Path         string `yaml:"path"`
		RotateSizeMB int    `yaml:"rotate_size_mb"`
		Keep         int    `yaml:"keep"`
	}{
		{Kind: "file", Path: "/var/log/xhelix/alerts.jsonl", RotateSizeMB: 100, Keep: 7},
	}
	return c
}

func TestAudit_AllWitnessed_NoFindings(t *testing.T) {
	a := New()
	a.Witness("storage.hot.path", "OpenHot")
	a.Witness("storage.hot.retention_hours", "runHotPruner")
	a.Witness("storage.hot.max_size_mb", "runHotPruner")
	a.Witness("alerts.sinks[0].kind", "buildSinks")
	a.Witness("alerts.sinks[0].path", "FileSink")
	a.Witness("alerts.sinks[0].rotate_size_mb", "FileSink")
	a.Witness("alerts.sinks[0].keep", "FileSink")

	cfg := makeCfg()
	findings := a.Audit(&cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %v", findings)
	}
}

func TestAudit_FindsUnwitnessedRetention(t *testing.T) {
	a := New()
	// Witness only path; deliberately omit retention_hours + max_size_mb
	// — this simulates the actual hot.db bug class.
	a.Witness("storage.hot.path", "OpenHot")
	a.Declare("storage.hot.retention_hours")
	a.Declare("storage.hot.max_size_mb")

	cfg := makeCfg()
	findings := a.Audit(&cfg)
	// Three: retention_hours, max_size_mb, plus everything in
	// alerts.sinks (not Witness'd or Declare'd).
	if len(findings) == 0 {
		t.Fatal("expected findings, got none")
	}
	keyHit := func(k string) bool {
		for _, f := range findings {
			if f.Key == k {
				return true
			}
		}
		return false
	}
	if !keyHit("storage.hot.retention_hours") {
		t.Errorf("expected finding for storage.hot.retention_hours; got %v", findings)
	}
	if !keyHit("storage.hot.max_size_mb") {
		t.Errorf("expected finding for storage.hot.max_size_mb; got %v", findings)
	}
}

func TestAudit_ZeroValueNotFlagged(t *testing.T) {
	a := New()
	a.Witness("storage.hot.path", "OpenHot")
	a.Declare("storage.hot.retention_hours")
	a.Declare("storage.hot.max_size_mb")

	var cfg fakeCfg
	cfg.Storage.Hot.Path = "/var/lib/xhelix/hot.db"
	// retention_hours, max_size_mb deliberately zero (= default)
	findings := a.Audit(&cfg)
	for _, f := range findings {
		if f.Key == "storage.hot.retention_hours" || f.Key == "storage.hot.max_size_mb" {
			t.Errorf("zero-value field should not be flagged: %v", f)
		}
	}
}

func TestAudit_UnknownKey(t *testing.T) {
	a := New()
	// No Declare for any storage.* keys — they should all show up
	// as unknown.
	cfg := makeCfg()
	findings := a.Audit(&cfg)
	gotUnknown := 0
	for _, f := range findings {
		if f.Issue == "unknown-key" {
			gotUnknown++
		}
	}
	if gotUnknown == 0 {
		t.Errorf("expected unknown-key findings on un-Declare'd cfg, got %v", findings)
	}
}

func TestAudit_SliceOfStructsTraversed(t *testing.T) {
	a := New()
	a.Witness("alerts.sinks[0].kind", "buildSinks")
	a.Witness("alerts.sinks[0].path", "FileSink")
	a.Declare("alerts.sinks[0].rotate_size_mb")
	a.Declare("alerts.sinks[0].keep")
	a.Declare("storage.hot.path")
	a.Declare("storage.hot.retention_hours")
	a.Declare("storage.hot.max_size_mb")

	cfg := makeCfg()
	findings := a.Audit(&cfg)
	// Expect: alerts.sinks[0].rotate_size_mb + .keep unwitnessed
	// (Declare'd but not Witness'd).
	expectKeys := map[string]bool{
		"alerts.sinks[0].rotate_size_mb": false,
		"alerts.sinks[0].keep":           false,
	}
	for _, f := range findings {
		if _, ok := expectKeys[f.Key]; ok {
			expectKeys[f.Key] = true
		}
	}
	for k, hit := range expectKeys {
		if !hit {
			t.Errorf("expected unwitnessed finding for %q; got %v", k, findings)
		}
	}
}

func TestWitness_Stats_Witnessed(t *testing.T) {
	a := New()
	a.Witness("a.b", "c1")
	a.Witness("a.c", "c2")
	if !a.Witnessed("a.b") || !a.Witnessed("a.c") {
		t.Error("Witnessed should return true for registered keys")
	}
	if a.Witnessed("a.d") {
		t.Error("Witnessed should return false for unregistered")
	}
	if s := a.Stats(); s.Witnessed != 2 || s.Known != 2 {
		t.Errorf("stats = %+v, want witnessed=2 known=2", s)
	}
}

func TestAudit_ConcurrentWitness(t *testing.T) {
	a := New()
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(i int) {
			for j := 0; j < 100; j++ {
				a.Witness("a.b", "consumer")
			}
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
	if !a.Witnessed("a.b") {
		t.Error("concurrent Witness lost the key")
	}
}
