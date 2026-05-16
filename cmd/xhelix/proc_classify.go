package main

import (
	"strings"
)

// classifyProcess returns a short human-readable category for a
// process based on its exe path, comm, and systemd unit. Categories
// are deliberately coarse — the UI groups by them, so too many
// labels would hurt readability.
//
// Returns one of:
//   "system", "network", "container", "browser", "dev", "shell",
//   "package", "ssh", "monitoring", "media", "messenger", "other"
func classifyProcess(exe, comm, unit string) string {
	exe = strings.ToLower(exe)
	comm = strings.ToLower(comm)
	unit = strings.ToLower(unit)

	// Container infrastructure first — these often have surprising
	// comm names that would mis-classify under other categories.
	if matchAny(exe, "containerd", "dockerd", "podman", "runc", "crio", "kubelet", "kube-proxy", "etcd") ||
		matchAny(comm, "containerd", "dockerd", "runc", "crio", "podman", "kubelet") {
		return "container"
	}

	// Browsers.
	if matchAny(exe, "chrome", "chromium", "firefox", "brave", "edge", "opera", "vivaldi", "epiphany") ||
		matchAny(comm, "chrome", "firefox", "chromium", "brave", "msedge") {
		return "browser"
	}

	// SSH client/server.
	if matchAny(comm, "sshd", "ssh-agent", "ssh") ||
		matchAny(exe, "/usr/sbin/sshd", "/usr/bin/ssh", "openssh") {
		return "ssh"
	}

	// Package managers + their helpers.
	if matchAny(comm, "apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "pacman", "snapd", "snap", "flatpak", "unattended-up") ||
		matchAny(exe, "/usr/bin/apt", "/usr/bin/dpkg", "snapd", "flatpak") {
		return "package"
	}

	// Network servers / proxies / DNS.
	if matchAny(comm, "nginx", "apache", "apache2", "httpd", "haproxy", "envoy", "caddy",
		"postfix", "dovecot", "exim", "sendmail",
		"dnsmasq", "named", "unbound", "bind9", "systemd-resolve",
		"chrony", "ntpd", "ntpdate") ||
		matchAny(exe, "/usr/sbin/nginx", "/usr/sbin/apache", "haproxy") {
		return "network"
	}

	// Development tooling.
	if matchAny(comm, "code", "code-server", "code-helper", "code-tunnel", "vscode",
		"node", "npm", "npx", "pnpm", "yarn", "deno", "bun",
		"python", "python3", "pip", "pip3",
		"go", "gopls", "compile", "link",
		"cargo", "rustc", "rust-analyzer",
		"java", "javac", "mvn", "gradle",
		"ruby", "gem", "bundler",
		"git", "gh", "hg", "make", "cmake", "ninja", "ld",
		"jetbrains", "idea", "pycharm", "goland", "webstorm", "clion") ||
		matchAny(exe, "/usr/bin/code", "/usr/local/bin/node", "jetbrains") {
		return "dev"
	}

	// Monitoring / agents (xhelix itself counts as monitoring).
	if matchAny(comm, "xhelix", "xhelixctl", "mynetgate", "prometheus", "grafana",
		"telegraf", "node_exporter", "datadog-agent", "fluentd", "fluent-bit",
		"newrelic-infra", "filebeat", "metricbeat", "auditd", "rsyslog",
		"systemd-journal") {
		return "monitoring"
	}

	// Media.
	if matchAny(comm, "spotify", "vlc", "mpv", "rhythmbox", "audacious", "obs",
		"discord", "slack", "telegram", "signal", "zoom", "teams") {
		return "messenger"
	}

	// Shell + terminal + the like.
	if matchAny(comm, "bash", "zsh", "sh", "fish", "dash",
		"tmux", "screen", "tilix", "gnome-terminal", "alacritty", "kitty", "wezterm") {
		return "shell"
	}

	// System: systemd-* and friends; runs as root, low-level.
	if strings.HasPrefix(comm, "systemd") || strings.HasPrefix(comm, "kworker") ||
		matchAny(comm, "init", "kthreadd", "udev", "udevd", "dbus", "polkitd", "logind", "cron",
			"crond", "atd", "anacron", "irqbalance", "smartd", "modemmanager",
			"networkmanager", "NetworkManager", "wpa_supplicant", "dhclient", "rpcbind") {
		return "system"
	}

	return "other"
}

func matchAny(s string, patterns ...string) bool {
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if s == p || strings.HasSuffix(s, "/"+p) || strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// readProcState returns the one-letter Linux task state for the pid:
//
//	R running, S sleeping, D disk-wait, T stopped, Z zombie, I idle,
//	"" if unavailable.
func readProcState(pid uint32) string {
	st := readProcStatus(pid)
	if st.State == "" {
		return ""
	}
	// /proc/PID/status reports "R (running)"; first field is fine.
	for i := 0; i < len(st.State); i++ {
		c := st.State[i]
		if c >= 'A' && c <= 'Z' {
			return string(c)
		}
	}
	return ""
}
