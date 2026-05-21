package config

import "time"

// ApplyPreset overlays a profile on top of cfg. The profile fills
// only fields that are still zero-valued, so user overrides win.
//
// The three profiles match the documented operator personas:
//
//   - desktop: workstation; lots of legitimate bash, curl, git
//   - server: production server; default
//   - container-host: docker / k8s node
func ApplyPreset(cfg Config) Config {
	switch cfg.Preset {
	case "desktop":
		cfg = mergeDesktop(cfg)
	case "container-host":
		cfg = mergeContainerHost(cfg)
	case "server", "":
		cfg = mergeServer(cfg)
	}
	return applyNewDefaults(cfg)
}

// applyNewDefaults fills sensible defaults for the P-RF.9b/d/e
// fields (Takeover / ForensicIngest / ProtectedServices) without
// changing the on/off state of any feature. Behaviour-preserving:
// operator opt-in is still required to ENABLE these subsystems;
// the defaults just spare them from re-specifying every interval
// when they do.
func applyNewDefaults(cfg Config) Config {
	if cfg.Takeover.TickInterval == 0 {
		cfg.Takeover.TickInterval = 5 * time.Second
	}
	if cfg.Takeover.MinScore == 0 {
		cfg.Takeover.MinScore = 50
	}
	// Takeover.Active intentionally left at the user-set value
	// (default false). Flipping to active is an explicit operator
	// decision; no preset auto-enables it.

	if cfg.ForensicIngest.Dir == "" {
		cfg.ForensicIngest.Dir = "/var/lib/xhelix/forensic"
	}
	if cfg.ForensicIngest.ScanInterval == 0 {
		cfg.ForensicIngest.ScanInterval = 5 * time.Second
	}
	if cfg.ForensicIngest.PollInterval == 0 {
		cfg.ForensicIngest.PollInterval = 250 * time.Millisecond
	}
	// ForensicIngest.Enabled intentionally not flipped — the
	// deception binaries write to ForensicIngest.Dir, so if no
	// deception is running, ingesting from an empty dir is wasted
	// goroutine. Operator opts in alongside Ring 2.

	// ProtectedServices fields: nothing to default. Empty Services
	// + Enabled=false is the correct "no services declared" state.
	return cfg
}

func mergeServer(cfg Config) Config {
	if !cfg.Sensors.FIM.Enabled {
		cfg.Sensors.FIM.Enabled = true
	}
	if len(cfg.Sensors.FIM.WatchPaths) == 0 {
		cfg.Sensors.FIM.WatchPaths = defaultServerWatchPaths()
	}
	if !cfg.Sensors.FIM.PackageDiff {
		cfg.Sensors.FIM.PackageDiff = true
	}
	if !cfg.Sensors.FIM.SUIDBaseline {
		cfg.Sensors.FIM.SUIDBaseline = true
	}
	return cfg
}

func mergeDesktop(cfg Config) Config {
	if !cfg.Sensors.FIM.Enabled {
		cfg.Sensors.FIM.Enabled = true
	}
	if len(cfg.Sensors.FIM.WatchPaths) == 0 {
		cfg.Sensors.FIM.WatchPaths = defaultDesktopWatchPaths()
	}
	return cfg
}

func mergeContainerHost(cfg Config) Config {
	if !cfg.Sensors.FIM.Enabled {
		cfg.Sensors.FIM.Enabled = true
	}
	if len(cfg.Sensors.FIM.WatchPaths) == 0 {
		cfg.Sensors.FIM.WatchPaths = defaultContainerHostWatchPaths()
	}
	return cfg
}

func defaultServerWatchPaths() []string {
	return []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
		"/etc/sudoers.d",
		"/etc/cron.d",
		"/etc/cron.daily",
		"/etc/cron.hourly",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
		"/etc/crontab",
		"/etc/systemd/system",
		"/etc/ld.so.preload",
		"/etc/pam.d",
		"/lib/security",
		"/usr/lib64/security",
		"/root/.ssh",
		"/home/*/.ssh",
		"/etc/ssh",
	}
}

func defaultDesktopWatchPaths() []string {
	// Smaller list for workstations; less server-y persistence
	// surface to watch.
	return []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
		"/etc/ld.so.preload",
		"/etc/pam.d",
		"/lib/security",
		"/usr/lib64/security",
		"/home/*/.ssh",
	}
}

func defaultContainerHostWatchPaths() []string {
	// Same server set plus container runtime paths.
	paths := defaultServerWatchPaths()
	paths = append(paths,
		"/etc/docker",
		"/var/lib/kubelet",
		"/etc/kubernetes",
		"/etc/containerd",
	)
	return paths
}
