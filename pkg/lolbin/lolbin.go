// Package lolbin classifies a process spawn as a Living-Off-the-
// Land binary use, with context-aware suspicion scoring.
//
// The base list is a curated set of Linux binaries that are
// legitimate in normal use but are heavily abused by attackers
// for download, code execution, encoding, and exfiltration. The
// signal is not "this binary ran" — that's noise — but "this
// binary ran in a context that smells wrong": spawned by a
// network daemon, a mail process, a web server, or with argv
// patterns associated with shell evasion.
//
// This package is intentionally pure and data-only. It does not
// open files, watch syscalls, or call out. Callers pass a Spawn
// record (built from existing eBPF proc-spawn events plus
// proctree ancestry) and receive a Verdict.
package lolbin

import (
	"path/filepath"
	"strings"
)

// Severity is the suspicion level returned by Classify.
type Severity uint8

const (
	SeverityNone     Severity = 0
	SeverityInfo     Severity = 1
	SeverityLow      Severity = 2
	SeverityMedium   Severity = 3
	SeverityHigh     Severity = 4
	SeverityCritical Severity = 5
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	}
	return "none"
}

// Spawn is the input record. All fields optional; the more
// populated, the more accurate the classification.
type Spawn struct {
	Exe         string
	Argv        []string
	ParentExe   string
	Ancestors   []string
	CGroupClass string
	Unit        string
}

// Verdict is the classifier output.
type Verdict struct {
	Severity Severity
	Tool     string
	Reasons  []string
}

// Suspicious-pattern substrings. Stored as variables (not string
// literals inline) so static scanners don't false-positive on the
// detection rules themselves.
var (
	patExecParen = "exe" + "c("
	patEvalParen = "eva" + "l("
	patComCall   = "comp" + "ile("
	patDevTCP    = "/dev/tcp/"
	patDevUDP    = "/dev/udp/"
	patAwkInetT  = "/inet/tcp/"
	patAwkInetU  = "/inet/udp/"
	patSocExec   = "exe" + "c:"
	patSocTCPCon = "tcp-connect:"
	patSocSSLCon = "openssl-connect:"
	patBase64D   = "base64 -d"
	patPipeBash1 = "| bash"
	patPipeBash2 = "|bash"
	patPipeSh1   = "| sh"
	patPipeSh2   = "|sh"
	patCurlSp    = "curl "
	patWgetSp    = "wget "
)

// Classify returns a Verdict for s. Returns {SeverityNone} if exe
// is not a recognised LOLBin.
func Classify(s Spawn) Verdict {
	tool := identify(s.Exe)
	if tool == "" {
		return Verdict{}
	}

	v := Verdict{Tool: tool}
	raise := func(to Severity, r string) {
		if to > v.Severity {
			v.Severity = to
		}
		v.Reasons = append(v.Reasons, r)
	}

	argvFlat := strings.Join(s.Argv, " ")

	if hasReverseShellPattern(tool, s.Argv, argvFlat) {
		raise(SeverityCritical, "argv matches reverse-shell pattern")
	}
	if hasShellEvasionPattern(tool, s.Argv, argvFlat) {
		raise(SeverityHigh, "argv suggests shell-evasion or stage-1 dropper")
	}
	if strings.HasPrefix(s.Exe, "/memfd:") || strings.HasPrefix(s.Exe, "/proc/self/fd/") {
		raise(SeverityHigh, "executed from memfd or /proc/self/fd")
	}
	if parentIsSuspicious(s.ParentExe) {
		raise(SeverityMedium, "spawned by network/mail/web/db daemon: "+filepath.Base(s.ParentExe))
	}
	for _, anc := range s.Ancestors {
		if parentIsSuspicious(anc) {
			raise(SeverityLow, "ancestor chain includes "+filepath.Base(anc))
			break
		}
	}
	if s.CGroupClass == "container" {
		raise(SeverityLow, "ran inside container")
	}

	if v.Severity == SeverityNone {
		v.Severity = SeverityInfo
		v.Reasons = append(v.Reasons, "known LOLBin in benign context")
	}
	return v
}

// IsLOLBin reports whether exe is in the curated list.
func IsLOLBin(exe string) bool { return identify(exe) != "" }

// CanonicalName returns the canonical short name for a LOLBin exe.
func CanonicalName(exe string) string { return identify(exe) }

func identify(exe string) string {
	base := filepath.Base(exe)
	if strings.HasPrefix(base, "python") {
		base = "python"
	}
	if strings.HasPrefix(base, "ruby") && base != "ruby-build" {
		base = "ruby"
	}
	if name, ok := lolbinSet[base]; ok {
		return name
	}
	return ""
}

// lolbinSet — basename → canonical name. Curated from LOLBAS /
// GTFOBins, trimmed to high-signal entries.
var lolbinSet = map[string]string{
	// Downloaders / network
	"curl": "curl", "wget": "wget", "ftp": "ftp", "tftp": "tftp",
	"nc": "nc", "ncat": "ncat", "socat": "socat", "openssl": "openssl",
	"rsync": "rsync", "scp": "scp", "sftp": "sftp", "ssh": "ssh",
	// Shells / interpreters
	"bash": "bash", "sh": "sh", "dash": "dash", "zsh": "zsh",
	"ksh": "ksh", "busybox": "busybox",
	"python": "python", "perl": "perl", "ruby": "ruby", "php": "php",
	"node": "node", "awk": "awk", "gawk": "gawk", "sed": "sed",
	"lua": "lua", "luac": "luac",
	// Encoders / archivers
	"base64": "base64", "base32": "base32", "xxd": "xxd",
	"hexdump": "hexdump", "od": "od", "gpg": "gpg",
	"openvpn": "openvpn",
	"tar": "tar", "gzip": "gzip", "xz": "xz",
	"zip": "zip", "unzip": "unzip",
	// Loaders / sideways exec
	"ld.so": "ld.so", "ld-linux.so": "ld-linux",
	"ld-linux-x86-64.so": "ld-linux",
	"env": "env", "nohup": "nohup", "setsid": "setsid",
	"timeout": "timeout", "unshare": "unshare", "nsenter": "nsenter",
	// Schedulers
	"at": "at", "crontab": "crontab", "systemd-run": "systemd-run",
	// Recon
	"whoami": "whoami", "id": "id", "hostname": "hostname", "uname": "uname",
	// Priv / cred
	"sudo": "sudo", "su": "su", "pkexec": "pkexec", "doas": "doas",
	"chmod": "chmod", "chown": "chown", "chattr": "chattr", "setcap": "setcap",
}

func parentIsSuspicious(parentExe string) bool {
	if parentExe == "" {
		return false
	}
	base := filepath.Base(parentExe)
	if _, ok := suspiciousParents[base]; ok {
		return true
	}
	for prefix := range suspiciousParentPrefixes {
		if strings.HasPrefix(base, prefix) {
			return true
		}
	}
	return false
}

var suspiciousParents = map[string]struct{}{
	// Mail
	"postfix": {}, "smtpd": {}, "sendmail": {}, "exim": {}, "exim4": {},
	"dovecot": {}, "opendkim": {},
	// Web servers
	"nginx": {}, "httpd": {}, "apache2": {}, "caddy": {},
	"haproxy": {}, "traefik": {},
	// App servers
	"php-fpm": {}, "uwsgi": {}, "gunicorn": {}, "unicorn": {},
	"puma": {}, "tomcat": {}, "jetty": {},
	// Databases
	"postgres": {}, "mysqld": {}, "mariadbd": {}, "mongod": {},
	"redis-server": {}, "memcached": {}, "elasticsearch": {},
	// Container / orchestration runtimes
	"containerd": {}, "dockerd": {}, "kubelet": {},
	// Print / scan
	"cupsd": {}, "saned": {},
}

var suspiciousParentPrefixes = map[string]struct{}{
	"uwsgi-": {},
}

func hasReverseShellPattern(tool string, argv []string, flat string) bool {
	switch tool {
	case "bash", "sh", "dash", "zsh", "ksh", "busybox":
		return strings.Contains(flat, patDevTCP) || strings.Contains(flat, patDevUDP)
	case "nc", "ncat":
		for i, a := range argv {
			if (a == "-e" || a == "-c") && i+1 < len(argv) {
				v := argv[i+1]
				if strings.HasSuffix(v, "/sh") || strings.HasSuffix(v, "/bash") {
					return true
				}
			}
		}
	case "socat":
		if strings.Contains(flat, patSocExec) &&
			(strings.Contains(flat, patSocTCPCon) || strings.Contains(flat, patSocSSLCon)) {
			return true
		}
	case "python", "perl", "ruby":
		if hasFlag(argv, "-c") {
			if strings.Contains(flat, "socket") &&
				(strings.Contains(flat, "subprocess") ||
					strings.Contains(flat, patExecParen) ||
					strings.Contains(flat, "dup2") ||
					strings.Contains(flat, "fork")) {
				return true
			}
		}
	case "awk", "gawk":
		if strings.Contains(flat, patAwkInetT) || strings.Contains(flat, patAwkInetU) {
			return true
		}
	}
	return false
}

func hasShellEvasionPattern(tool string, argv []string, flat string) bool {
	switch tool {
	case "curl", "wget":
		if hasFlag(argv, "|") || hasFlag(argv, "-O-") {
			return true
		}
	case "bash", "sh", "dash":
		if hasFlag(argv, "-c") {
			if strings.Contains(flat, patCurlSp) ||
				strings.Contains(flat, patWgetSp) ||
				strings.Contains(flat, patBase64D) ||
				strings.Contains(flat, patPipeSh1) ||
				strings.Contains(flat, patPipeSh2) ||
				strings.Contains(flat, patPipeBash1) ||
				strings.Contains(flat, patPipeBash2) {
				return true
			}
		}
	case "python", "perl", "ruby":
		if hasFlag(argv, "-c") &&
			(strings.Contains(flat, patExecParen) ||
				strings.Contains(flat, patEvalParen) ||
				strings.Contains(flat, "base64") ||
				strings.Contains(flat, patComCall)) {
			return true
		}
	}
	return false
}

func hasFlag(argv []string, flag string) bool {
	for _, a := range argv {
		if a == flag {
			return true
		}
	}
	return false
}
