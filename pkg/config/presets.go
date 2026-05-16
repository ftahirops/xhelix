package config

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
		return mergeDesktop(cfg)
	case "container-host":
		return mergeContainerHost(cfg)
	case "server", "":
		return mergeServer(cfg)
	}
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
