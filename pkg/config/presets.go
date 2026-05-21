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
		// ─── Identity / authz ─────────────────────────────────
		"/etc/passwd",
		"/etc/shadow",
		"/etc/group",
		"/etc/gshadow",
		"/etc/sudoers",
		"/etc/sudoers.d",
		"/etc/security",
		// ─── Cron / scheduled execution ───────────────────────
		"/etc/cron.d",
		"/etc/cron.daily",
		"/etc/cron.hourly",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
		"/etc/crontab",
		"/etc/anacrontab",
		// User crontabs — top-10 persistence vector, was missing
		// pre-P-AB.7. /var/spool/cron/crontabs/ is the Debian/Ubuntu
		// path; /var/spool/cron/ (no subdir) is RHEL/CentOS.
		"/var/spool/cron",
		"/var/spool/cron/crontabs",
		"/var/spool/anacron",
		// ─── systemd / init ───────────────────────────────────
		"/etc/systemd/system",
		"/lib/systemd/system",
		"/usr/lib/systemd/system",
		"/etc/systemd/user",
		"/etc/rc.local",
		"/etc/init.d",
		"/etc/rc.d",
		// XDG autostart (mostly desktop, but ssh-jumphost
		// + remote-desktop servers also hit this).
		"/etc/xdg/autostart",
		// ─── Loader / preload hijacks ─────────────────────────
		"/etc/ld.so.preload",
		"/etc/ld.so.conf",
		"/etc/ld.so.conf.d",
		// ─── PAM / login pipeline ─────────────────────────────
		"/etc/pam.d",
		"/lib/security",
		"/usr/lib64/security",
		"/usr/lib/security",
		// ─── Shell startup / login hooks (P-AB.7) ─────────────
		// System-wide shell startup files. Adding new commands
		// here runs them for every interactive login — classic
		// re-entry path.
		"/etc/profile",
		"/etc/profile.d",
		"/etc/bash.bashrc",
		"/etc/bashrc",
		"/etc/zsh",
		"/etc/zshrc",
		"/etc/zsh/zshrc",
		"/etc/zsh/zlogin",
		"/etc/zsh/zprofile",
		"/etc/skel",
		// Per-user dotfiles. root only by default — per-user
		// dotfile coverage is added via glob below.
		"/root/.bashrc",
		"/root/.bash_profile",
		"/root/.bash_login",
		"/root/.profile",
		"/root/.zshrc",
		"/root/.zshenv",
		"/root/.zprofile",
		"/root/.bash_logout",
		"/root/.config/fish/config.fish",
		"/home/*/.bashrc",
		"/home/*/.bash_profile",
		"/home/*/.bash_login",
		"/home/*/.profile",
		"/home/*/.zshrc",
		"/home/*/.zshenv",
		"/home/*/.zprofile",
		// ─── SSH ──────────────────────────────────────────────
		"/root/.ssh",
		"/home/*/.ssh",
		"/etc/ssh",
		// SSH per-account login hooks (.ssh/rc runs on every
		// login if present — undocumented persistence path).
		// Covered by the /root/.ssh and /home/*/.ssh dirs above
		// but called out here for the rule.
		// ─── Network policy ───────────────────────────────────
		"/etc/hosts",
		"/etc/hosts.allow",
		"/etc/hosts.deny",
		"/etc/resolv.conf",
		"/etc/nsswitch.conf",
		"/etc/sysctl.conf",
		"/etc/sysctl.d",
		// ─── Web-server entrypoints (apache/nginx) ────────────
		"/etc/apache2",
		"/etc/httpd",
		"/etc/nginx",
		// ─── Plesk-specific tenant webroots (P-AB.7) ──────────
		// Glob expands per-domain. Tenant webshells / wp-config
		// tampering / .htaccess overrides land here. Apache
		// per-vhost suexec / php-fpm pool drops too.
		"/var/www/vhosts/*/httpdocs/wp-config.php",
		"/var/www/vhosts/*/httpdocs/.htaccess",
		"/var/www/vhosts/*/httpdocs/configuration.php",
		"/var/www/vhosts/*/httpdocs/wp-content/mu-plugins",
		"/var/www/vhosts/*/conf",
		"/var/www/html",
		// Generic webroot fallbacks.
		"/srv/www",
		// ─── App config / secrets at common locations ─────────
		// DLCF catalog (P7.1) covers semantic data-loss; FIM here
		// catches direct tamper of the files.
		"/etc/environment",
		"/etc/default",
		// ─── Container runtime config ─────────────────────────
		"/etc/docker",
		"/etc/containerd",
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
	// Same server set plus container runtime + orchestrator config
	// + common compose-file drop locations.
	paths := defaultServerWatchPaths()
	paths = append(paths,
		"/etc/docker",
		"/etc/docker/daemon.json",
		"/var/lib/kubelet",
		"/etc/kubernetes",
		"/etc/containerd",
		// docker-compose drop-in spots (P-AB.7). Most attackers
		// who own a build/CI host modify compose files to add a
		// `volumes: [/:/host]` or `privileged: true` service.
		"/opt/docker-compose.yml",
		"/opt/docker-compose.yaml",
		"/srv/docker-compose.yml",
		// Per-tenant compose files under common roots.
		"/home/*/docker-compose.yml",
		"/var/www/vhosts/*/docker-compose.yml",
	)
	return paths
}
