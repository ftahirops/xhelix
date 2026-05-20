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

func TestConfig_ProtectedServicesLoad(t *testing.T) {
	yml := `
protected_services:
  enabled: true
  services:
    - name: nginx-main
      kind: nginx
      role: reverse_proxy
      unit: nginx.service
      exec_path: /usr/sbin/nginx
      cgroup_prefix: /system.slice/nginx.service
      contract:
        write_roots: ["/var/log/nginx", "/run/nginx"]
        upstream_cidrs: ["10.0.0.0/24"]
        strict_read_only: true
      response:
        deception:
          enabled: true
          fake_exec: true
          sinkhole: true
          decoy_fs: true
          poison_dns: true
`
	tmp := writeTempFile(t, yml)
	defer os.Remove(tmp)

	cfg, err := Load(tmp)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.ProtectedServices.Enabled {
		t.Fatal("ProtectedServices should be enabled")
	}
	if len(cfg.ProtectedServices.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(cfg.ProtectedServices.Services))
	}
	s := cfg.ProtectedServices.Services[0]
	if s.Name != "nginx-main" || string(s.Kind) != "nginx" || string(s.Role) != "reverse_proxy" {
		t.Errorf("metadata wrong: %+v", s)
	}
	if s.Unit != "nginx.service" || s.ExecPath != "/usr/sbin/nginx" {
		t.Errorf("identity wrong: %+v", s)
	}
	if len(s.Contract.WriteRoots) != 2 {
		t.Errorf("WriteRoots: %v", s.Contract.WriteRoots)
	}
	if len(s.Contract.UpstreamCIDRs) != 1 || s.Contract.UpstreamCIDRs[0] != "10.0.0.0/24" {
		t.Errorf("UpstreamCIDRs: %v", s.Contract.UpstreamCIDRs)
	}
	if !s.Contract.StrictReadOnly {
		t.Error("StrictReadOnly should be true")
	}
	d := s.Response.Deception
	if !d.Enabled || !d.FakeExec || !d.Sinkhole || !d.DecoyFS || !d.PoisonDNS {
		t.Errorf("Deception flags wrong: %+v", d)
	}
}

func TestConfig_ProtectedServicesEmptyOK(t *testing.T) {
	yml := `logging: {level: info}`
	tmp := writeTempFile(t, yml)
	defer os.Remove(tmp)
	cfg, err := Load(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProtectedServices.Enabled {
		t.Fatal("absent protected_services block should default to disabled")
	}
	if len(cfg.ProtectedServices.Services) != 0 {
		t.Fatal("absent block should yield empty Services slice")
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "xhelix-cfg-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}
