package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestApplyPreset_FillsTakeoverDefaults(t *testing.T) {
	cfg := ApplyPreset(Config{Preset: "server"})
	if cfg.Takeover.TickInterval != 5*time.Second {
		t.Errorf("TickInterval = %v, want 5s", cfg.Takeover.TickInterval)
	}
	if cfg.Takeover.MinScore != 50 {
		t.Errorf("MinScore = %d, want 50", cfg.Takeover.MinScore)
	}
	if cfg.Takeover.Active {
		t.Error("Active should NOT auto-enable")
	}
}

func TestApplyPreset_PreservesUserTakeoverOverrides(t *testing.T) {
	cfg := ApplyPreset(Config{
		Preset: "server",
		Takeover: TakeoverConfig{
			Active:       true,
			TickInterval: 10 * time.Second,
			MinScore:     75,
		},
	})
	if !cfg.Takeover.Active {
		t.Error("user Active=true should be preserved")
	}
	if cfg.Takeover.TickInterval != 10*time.Second {
		t.Errorf("user TickInterval=10s preserved? got %v", cfg.Takeover.TickInterval)
	}
	if cfg.Takeover.MinScore != 75 {
		t.Errorf("user MinScore=75 preserved? got %d", cfg.Takeover.MinScore)
	}
}

func TestApplyPreset_FillsForensicIngestDefaults(t *testing.T) {
	cfg := ApplyPreset(Config{Preset: "container-host"})
	if cfg.ForensicIngest.Dir != "/var/lib/xhelix/forensic" {
		t.Errorf("Dir = %q, want /var/lib/xhelix/forensic", cfg.ForensicIngest.Dir)
	}
	if cfg.ForensicIngest.ScanInterval != 5*time.Second {
		t.Errorf("ScanInterval = %v, want 5s", cfg.ForensicIngest.ScanInterval)
	}
	if cfg.ForensicIngest.PollInterval != 250*time.Millisecond {
		t.Errorf("PollInterval = %v, want 250ms", cfg.ForensicIngest.PollInterval)
	}
	if cfg.ForensicIngest.Enabled {
		t.Error("Enabled should NOT auto-enable")
	}
}

func TestApplyPreset_PreservesUserForensicOverrides(t *testing.T) {
	cfg := ApplyPreset(Config{
		Preset: "server",
		ForensicIngest: ForensicIngestConfig{
			Enabled:      true,
			Dir:          "/srv/xhelix",
			ScanInterval: 30 * time.Second,
		},
	})
	if !cfg.ForensicIngest.Enabled {
		t.Error("user Enabled=true should be preserved")
	}
	if cfg.ForensicIngest.Dir != "/srv/xhelix" {
		t.Errorf("user Dir preserved? got %q", cfg.ForensicIngest.Dir)
	}
	if cfg.ForensicIngest.ScanInterval != 30*time.Second {
		t.Errorf("user ScanInterval preserved? got %v", cfg.ForensicIngest.ScanInterval)
	}
	// PollInterval was zero — preset should still fill it.
	if cfg.ForensicIngest.PollInterval != 250*time.Millisecond {
		t.Errorf("PollInterval should be default-filled: got %v", cfg.ForensicIngest.PollInterval)
	}
}

func TestApplyPreset_ProtectedServicesStayEmpty(t *testing.T) {
	cfg := ApplyPreset(Config{Preset: "server"})
	if cfg.ProtectedServices.Enabled {
		t.Error("Enabled should NOT auto-enable")
	}
	if len(cfg.ProtectedServices.Services) != 0 {
		t.Errorf("Services should be empty, got %d", len(cfg.ProtectedServices.Services))
	}
}

func TestApplyPreset_AllPresetsGetTheDefaults(t *testing.T) {
	for _, p := range []string{"desktop", "server", "container-host", ""} {
		cfg := ApplyPreset(Config{Preset: p})
		if cfg.Takeover.TickInterval == 0 {
			t.Errorf("preset %q: Takeover.TickInterval not defaulted", p)
		}
		if cfg.ForensicIngest.Dir == "" {
			t.Errorf("preset %q: ForensicIngest.Dir not defaulted", p)
		}
	}
}

func TestDefault_DetectionAlertModeIsVisibility(t *testing.T) {
	c := Default()
	if c.Detection.AlertMode != "visibility" {
		t.Fatalf("default AlertMode must be 'visibility' for safety, got %q", c.Detection.AlertMode)
	}
}

func TestLoad_DetectionAlertMode_FromYAML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(p, []byte("detection:\n  alert_mode: detection\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Detection.AlertMode != "detection" {
		t.Fatalf("got %q", c.Detection.AlertMode)
	}
}

func TestLoad_DetectionAlertMode_RejectsUnknown(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(p, []byte("detection:\n  alert_mode: bogus\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatalf("unknown alert_mode must be a load error")
	}
}

func TestLoad_DetectionAlertMode_EmptyDefaultsToVisibility(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	// A config that doesn't mention detection at all must still end up visibility.
	if err := os.WriteFile(p, []byte("preset: server\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Detection.AlertMode != "visibility" {
		t.Fatalf("absent detection block must default to visibility, got %q", c.Detection.AlertMode)
	}
}

func TestDetection_FleetRarity_DefaultsOff(t *testing.T) {
	c := Default()
	if c.Detection.FleetRarity {
		t.Fatal("FleetRarity must default OFF")
	}
	if c.Detection.FleetMinCohort != 5 {
		t.Fatalf("FleetMinCohort default: got %d want 5", c.Detection.FleetMinCohort)
	}
}

func TestDetection_FleetRarity_FromYAML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(p, []byte("detection:\n  fleet_rarity: true\n  fleet_min_cohort: 10\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Detection.FleetRarity {
		t.Fatal("fleet_rarity should load true")
	}
	if c.Detection.FleetMinCohort != 10 {
		t.Fatalf("fleet_min_cohort: got %d want 10", c.Detection.FleetMinCohort)
	}
}

func TestDetection_FleetMinCohort_EmptyDefaults(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	// fleet_rarity set but no min_cohort → normalize() must default it to 5.
	if err := os.WriteFile(p, []byte("detection:\n  fleet_rarity: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Detection.FleetMinCohort != 5 {
		t.Fatalf("absent fleet_min_cohort must default to 5, got %d", c.Detection.FleetMinCohort)
	}
}
