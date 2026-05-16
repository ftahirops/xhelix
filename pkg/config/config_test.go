package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg.Preset != "server" {
		t.Errorf("default preset = %q, want server", cfg.Preset)
	}
	if cfg.Storage.Hot.Path == "" {
		t.Error("default hot path should be set")
	}
	if !cfg.Sensors.Heartbeat.Enabled {
		t.Error("heartbeat sensor should be enabled by default")
	}
}

func TestLoadMissingFileReturnsDefault(t *testing.T) {
	cfg, err := Load("/does/not/exist.yaml")
	if err != nil {
		t.Fatalf("expected no error for missing file, got %v", err)
	}
	if cfg.Preset != "server" {
		t.Errorf("preset = %q, want server", cfg.Preset)
	}
}

func TestLoadOverridesPresetWatchPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.yaml")
	body := []byte(`
preset: desktop
sensors:
  fim:
    enabled: true
`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Preset != "desktop" {
		t.Errorf("preset = %q, want desktop", cfg.Preset)
	}
	if len(cfg.Sensors.FIM.WatchPaths) == 0 {
		t.Error("preset should populate watch paths")
	}
}
