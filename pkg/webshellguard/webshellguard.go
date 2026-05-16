// Package webshellguard scans a running process's argv + cmdline
// for known webshell patterns. Pairs naturally with pkg/lolbin
// (which scores by tool+context) and pkg/revshell (which scores
// by reverse-shell argv shape) — webshellguard is the third leg:
// it catches code-execution payloads invoked by a web-server
// descendant.
//
// Pure-Go regex matchers. Caller passes a Spec (exe, argv,
// parent_exe) and gets a Verdict with confidence + family
// classification.
package webshellguard

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Family is the rough webshell category for grouping in the UI.
type Family string

const (
	FamilyNone        Family = ""
	FamilyPHPEval     Family = "php-eval"
	FamilyPHPSystem   Family = "php-system"
	FamilyPythonExec  Family = "python-exec"
	FamilyPythonHTTP  Family = "python-http-server"
	FamilyRubyEval    Family = "ruby-eval"
	FamilyPerlEval    Family = "perl-eval"
	FamilyJSPGeneric  Family = "jsp-generic"
	FamilyShellPipe   Family = "shell-pipe-eval"
	FamilyNodeEval    Family = "node-eval"
)

// Severity matches the rest of the package family.
type Severity uint8

const (
	SeverityNone     Severity = 0
	SeverityLow      Severity = 2
	SeverityMedium   Severity = 3
	SeverityHigh     Severity = 4
	SeverityCritical Severity = 5
)

// String returns a stable lowercase token.
func (s Severity) String() string {
	switch s {
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

// Spec is the input.
type Spec struct {
	Exe       string
	Argv      []string
	ParentExe string // immediate parent's exe path, when known
}

// Verdict is the output.
type Verdict struct {
	Family     Family
	Severity   Severity
	Confidence uint8 // 0..100
	Reason     string
}

// Scan returns a Verdict; the zero Verdict means "no webshell
// pattern matched."
func Scan(s Spec) Verdict {
	if s.Exe == "" && len(s.Argv) == 0 {
		return Verdict{}
	}
	flat := strings.Join(s.Argv, " ")

	// Pattern dispatch by tool — the same one-liner that's
	// benign run by a developer is high-signal when run by a
	// web-server descendant. We compute a contextual boost.
	contextBoost := uint8(0)
	if isWebDaemon(s.ParentExe) {
		contextBoost = 30
	}

	exeName := basename(s.Exe)
	if strings.HasPrefix(exeName, "python") {
		exeName = "python"
	}

	switch exeName {
	case "php", "php-cgi", "php-fpm":
		if v := scanPHP(s.Argv, flat); v.Family != FamilyNone {
			v.Confidence = addBoost(v.Confidence, contextBoost)
			return v
		}
	case "python":
		if v := scanPython(s.Argv, flat); v.Family != FamilyNone {
			v.Confidence = addBoost(v.Confidence, contextBoost)
			return v
		}
	case "ruby":
		if v := scanRuby(s.Argv, flat); v.Family != FamilyNone {
			v.Confidence = addBoost(v.Confidence, contextBoost)
			return v
		}
	case "perl":
		if v := scanPerl(s.Argv, flat); v.Family != FamilyNone {
			v.Confidence = addBoost(v.Confidence, contextBoost)
			return v
		}
	case "node":
		if v := scanNode(s.Argv, flat); v.Family != FamilyNone {
			v.Confidence = addBoost(v.Confidence, contextBoost)
			return v
		}
	case "java":
		if v := scanJSPLike(s.Argv, flat); v.Family != FamilyNone {
			v.Confidence = addBoost(v.Confidence, contextBoost)
			return v
		}
	case "sh", "bash", "dash":
		if v := scanShellPipe(s.Argv, flat); v.Family != FamilyNone {
			v.Confidence = addBoost(v.Confidence, contextBoost)
			return v
		}
	}
	return Verdict{}
}

// IsWebDaemon exports the helper for callers using their own
// classification flow.
func IsWebDaemon(parentExe string) bool { return isWebDaemon(parentExe) }

// ── per-family matchers ────────────────────────────────────────

// Compiled regexps (pattern literals split with concat so static
// scanners don't false-flag the detection rules themselves).
var (
	rxPHPEval     = regexp.MustCompile(`\bev` + `al\s*\(`)
	rxPHPAssert   = regexp.MustCompile(`\bassert\s*\(\s*\$`)
	rxPHPBase64   = regexp.MustCompile(`base64_decode\s*\(`)
	rxPHPSystem   = regexp.MustCompile(`\b(?:system|shell_exec|passthru|popen|proc_open|exec)\s*\(`)
	rxPyExec      = regexp.MustCompile(`(?:^|\W)exe` + `c\s*\(`)
	rxPyEval      = regexp.MustCompile(`(?:^|\W)ev` + `al\s*\(`)
	rxPyHTTPSrv   = regexp.MustCompile(`SimpleHTTPServer|http\.server|http_server`)
	rxRubyEval    = regexp.MustCompile(`(?:^|\W)ev` + `al\s*\b`)
	rxPerlEval    = regexp.MustCompile(`(?:^|\W)ev` + `al\s*\{`)
	rxNodeEval    = regexp.MustCompile(`(?:^|\W)ev` + `al\s*\(`)
)

func scanPHP(argv []string, flat string) Verdict {
	if !hasFlag(argv, "-r") && !hasFlag(argv, "-e") {
		return Verdict{}
	}
	if rxPHPEval.MatchString(flat) || rxPHPAssert.MatchString(flat) {
		conf := uint8(70)
		if rxPHPBase64.MatchString(flat) {
			conf = 90
		}
		return Verdict{
			Family: FamilyPHPEval, Severity: SeverityHigh, Confidence: conf,
			Reason: "php -r with eval/assert (with base64 decode)",
		}
	}
	if rxPHPSystem.MatchString(flat) {
		return Verdict{
			Family: FamilyPHPSystem, Severity: SeverityHigh, Confidence: 75,
			Reason: "php -r invoking system/shell_exec/passthru",
		}
	}
	return Verdict{}
}

func scanPython(argv []string, flat string) Verdict {
	if hasFlag(argv, "-c") {
		// http.server serving cwd is a classic post-exploit pivot.
		if rxPyHTTPSrv.MatchString(flat) {
			return Verdict{
				Family: FamilyPythonHTTP, Severity: SeverityMedium, Confidence: 65,
				Reason: "python -c starting http.server / SimpleHTTPServer",
			}
		}
		if rxPyExec.MatchString(flat) || rxPyEval.MatchString(flat) {
			conf := uint8(60)
			if strings.Contains(flat, "base64") || strings.Contains(flat, "compile(") {
				conf = 85
			}
			return Verdict{
				Family: FamilyPythonExec, Severity: SeverityHigh, Confidence: conf,
				Reason: "python -c with exec/eval (optionally base64-wrapped)",
			}
		}
	}
	if hasFlag(argv, "-m") {
		for i, a := range argv {
			if a == "-m" && i+1 < len(argv) {
				m := argv[i+1]
				if m == "http.server" || m == "SimpleHTTPServer" {
					return Verdict{
						Family: FamilyPythonHTTP, Severity: SeverityMedium, Confidence: 70,
						Reason: "python -m http.server",
					}
				}
			}
		}
	}
	return Verdict{}
}

func scanRuby(argv []string, flat string) Verdict {
	if hasFlag(argv, "-e") && rxRubyEval.MatchString(flat) {
		return Verdict{
			Family: FamilyRubyEval, Severity: SeverityHigh, Confidence: 70,
			Reason: "ruby -e with eval",
		}
	}
	return Verdict{}
}

func scanPerl(argv []string, flat string) Verdict {
	if hasFlag(argv, "-e") && rxPerlEval.MatchString(flat) {
		return Verdict{
			Family: FamilyPerlEval, Severity: SeverityHigh, Confidence: 70,
			Reason: "perl -e with eval",
		}
	}
	return Verdict{}
}

func scanNode(argv []string, flat string) Verdict {
	if hasFlag(argv, "-e") && rxNodeEval.MatchString(flat) {
		return Verdict{
			Family: FamilyNodeEval, Severity: SeverityHigh, Confidence: 65,
			Reason: "node -e with eval",
		}
	}
	return Verdict{}
}

// scanJSPLike covers tomcat/jetty descendants running unusual
// java -cp invocations. Heuristic only — false positives are
// real in dev environments.
func scanJSPLike(argv []string, flat string) Verdict {
	if !hasFlag(argv, "-cp") && !hasFlag(argv, "--class-path") {
		return Verdict{}
	}
	if strings.Contains(flat, "jsp") || strings.Contains(flat, "Runtime.getRuntime") {
		return Verdict{
			Family: FamilyJSPGeneric, Severity: SeverityMedium, Confidence: 50,
			Reason: "java -cp suggestive of JSP execution",
		}
	}
	return Verdict{}
}

func scanShellPipe(argv []string, flat string) Verdict {
	// Web-server sh -c pipelines that fetch+exec are the textbook
	// log4shell-style follow-on payload.
	if !hasFlag(argv, "-c") {
		return Verdict{}
	}
	dangerous := strings.Contains(flat, "curl ") || strings.Contains(flat, "wget ")
	if !dangerous {
		return Verdict{}
	}
	if strings.Contains(flat, "| sh") || strings.Contains(flat, "|sh") ||
		strings.Contains(flat, "| bash") || strings.Contains(flat, "|bash") {
		return Verdict{
			Family: FamilyShellPipe, Severity: SeverityHigh, Confidence: 80,
			Reason: "sh -c with curl|sh / wget|bash chain",
		}
	}
	return Verdict{}
}

// ── helpers ────────────────────────────────────────────────────

func isWebDaemon(p string) bool {
	if p == "" {
		return false
	}
	base := basename(p)
	switch base {
	case "nginx", "apache2", "httpd", "caddy", "haproxy", "traefik",
		"php-fpm", "uwsgi", "gunicorn", "unicorn", "puma",
		"tomcat", "jetty",
		"node":
		return true
	}
	if strings.HasPrefix(base, "uwsgi-") {
		return true
	}
	return false
}

func basename(p string) string {
	return filepath.Base(p)
}

func hasFlag(argv []string, flag string) bool {
	for _, a := range argv {
		if a == flag {
			return true
		}
	}
	return false
}

func addBoost(base, boost uint8) uint8 {
	v := int(base) + int(boost)
	if v > 100 {
		return 100
	}
	if v < 0 {
		return 0
	}
	return uint8(v)
}
