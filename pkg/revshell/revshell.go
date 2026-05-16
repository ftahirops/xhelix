// Package revshell is a focused reverse-shell command-line
// matcher. It complements pkg/lolbin: lolbin scores by (tool +
// context), revshell scores by argv shape alone.
//
// Output is a Match{Pattern, Confidence, Description}. Pattern is
// a stable identifier ("bash-devtcp", "nc-e-flag", etc.) suitable
// for alert deduplication. Confidence is 0..100; >=70 should be
// treated as high signal.
//
// All patterns are matched as substrings or compiled regexps over
// the full argv (joined with spaces). Pure Go, no I/O, no state.
package revshell

import (
	"regexp"
	"strings"
)

// Match describes a single reverse-shell pattern hit.
type Match struct {
	Pattern     string
	Description string
	Confidence  uint8 // 0..100
}

// Detect scans the joined argv for reverse-shell patterns.
// Returns all matches found (callers typically pick the highest-
// confidence). Empty result = no pattern matched.
func Detect(argv []string) []Match {
	if len(argv) == 0 {
		return nil
	}
	flat := strings.Join(argv, " ")

	var hits []Match
	for _, p := range patterns {
		if p.test(argv, flat) {
			hits = append(hits, Match{
				Pattern:     p.name,
				Description: p.desc,
				Confidence:  p.conf,
			})
		}
	}
	return hits
}

// Best returns the highest-confidence Match, or zero Match if none.
func Best(argv []string) Match {
	hits := Detect(argv)
	if len(hits) == 0 {
		return Match{}
	}
	best := hits[0]
	for _, h := range hits[1:] {
		if h.Confidence > best.Confidence {
			best = h
		}
	}
	return best
}

// pattern is the internal rule shape.
type pattern struct {
	name string
	desc string
	conf uint8
	test func(argv []string, flat string) bool
}

// Compiled regexps — built once at package init.
var (
	rxBashDevTCP    = regexp.MustCompile(`(?:bash|sh|dash|zsh|ksh)\s+-i\s+.*(?:/dev/tcp/|/dev/udp/)`)
	rxAnyDevTCP     = regexp.MustCompile(`(?:/dev/tcp/|/dev/udp/)\S+/\S+`)
	rxNcEFlag       = regexp.MustCompile(`\bn(?:c|cat)\b.*\s-e\s+\S+`)
	rxNcCFlag       = regexp.MustCompile(`\bn(?:c|cat)\b.*\s-c\s+\S+`)
	rxSocatExec     = regexp.MustCompile(`socat.*(?:tcp-connect:|openssl-connect:|udp-connect:).*ex` + `ec:`)
	rxPerlSocket    = regexp.MustCompile(`perl\b.*-e.*socket`)
	rxPythonPty     = regexp.MustCompile(`python[0-9.]*\s+-c.*pty\.spawn`)
	rxRubyTCPSocket = regexp.MustCompile(`ruby\b.*-r?e?.*TCPSocket`)
	rxPhpFsockopen  = regexp.MustCompile(`php\b.*-r.*fsockopen`)
	rxNodeNetSocket = regexp.MustCompile(`node\b.*-e.*(?:net\.connect|net\.createConnection|require\(['"]net['"]\)\.connect)`)
	rxLuaSocket     = regexp.MustCompile(`lua\b.*-e.*socket\.tcp`)
	rxAwkInet       = regexp.MustCompile(`(?:awk|gawk)\b.*/inet/(?:tcp|udp)/`)
)

// patterns is evaluated in order; all matches are returned.
var patterns = []pattern{
	{
		name: "bash-devtcp-i",
		desc: "interactive shell with /dev/tcp redirect (bash/sh/dash/zsh/ksh -i to /dev/tcp/.../...)",
		conf: 95,
		test: func(_ []string, flat string) bool { return rxBashDevTCP.MatchString(flat) },
	},
	{
		name: "any-devtcp",
		desc: "argv references /dev/tcp/host/port or /dev/udp/host/port",
		conf: 85,
		test: func(_ []string, flat string) bool { return rxAnyDevTCP.MatchString(flat) },
	},
	{
		name: "nc-e-flag",
		desc: "netcat with -e <shell>; classic reverse shell",
		conf: 90,
		test: func(argv []string, flat string) bool {
			if !rxNcEFlag.MatchString(flat) {
				return false
			}
			return ncFollowsShellPath(argv, "-e")
		},
	},
	{
		name: "nc-c-flag",
		desc: "netcat with -c <shell>; variant of -e on some builds",
		conf: 85,
		test: func(argv []string, flat string) bool {
			if !rxNcCFlag.MatchString(flat) {
				return false
			}
			return ncFollowsShellPath(argv, "-c")
		},
	},
	{
		name: "socat-exec-connect",
		desc: "socat exec: paired with tcp-connect / openssl-connect / udp-connect",
		conf: 95,
		test: func(_ []string, flat string) bool { return rxSocatExec.MatchString(flat) },
	},
	{
		name: "perl-socket-e",
		desc: "perl -e referencing socket — likely reverse-shell oneliner",
		conf: 80,
		test: func(_ []string, flat string) bool {
			if !rxPerlSocket.MatchString(flat) {
				return false
			}
			return strings.Contains(flat, "exe"+"c") ||
				strings.Contains(flat, "fork") ||
				strings.Contains(flat, "dup2") ||
				strings.Contains(flat, "STDIN") ||
				strings.Contains(flat, "STDOUT")
		},
	},
	{
		name: "python-pty-spawn",
		desc: "python -c with pty.spawn — interactive reverse shell upgrade",
		conf: 85,
		test: func(_ []string, flat string) bool { return rxPythonPty.MatchString(flat) },
	},
	{
		name: "python-socket-c",
		desc: "python -c importing socket plus subprocess/dup2/fork",
		conf: 80,
		test: func(argv []string, flat string) bool {
			if !hasFlag(argv, "-c") || !strings.Contains(flat, "python") {
				return false
			}
			if !strings.Contains(flat, "socket") {
				return false
			}
			return strings.Contains(flat, "subprocess") ||
				strings.Contains(flat, "dup2") ||
				strings.Contains(flat, "fork")
		},
	},
	{
		name: "ruby-tcpsocket",
		desc: "ruby with TCPSocket — reverse-shell oneliner shape",
		conf: 80,
		test: func(_ []string, flat string) bool { return rxRubyTCPSocket.MatchString(flat) },
	},
	{
		name: "php-fsockopen",
		desc: "php -r with fsockopen — common webshell-to-reverse-shell pivot",
		conf: 85,
		test: func(_ []string, flat string) bool { return rxPhpFsockopen.MatchString(flat) },
	},
	{
		name: "node-net-connect",
		desc: "node -e with net.connect / net.createConnection",
		conf: 75,
		test: func(_ []string, flat string) bool { return rxNodeNetSocket.MatchString(flat) },
	},
	{
		name: "lua-socket-tcp",
		desc: "lua -e with socket.tcp",
		conf: 70,
		test: func(_ []string, flat string) bool { return rxLuaSocket.MatchString(flat) },
	},
	{
		name: "awk-inet-tcp",
		desc: "awk/gawk with /inet/tcp/ or /inet/udp/ pseudo-file",
		conf: 90,
		test: func(_ []string, flat string) bool { return rxAwkInet.MatchString(flat) },
	},
	{
		name: "telnet-pipe",
		desc: "telnet pipe variant (telnet host port | /bin/sh | telnet host port)",
		conf: 75,
		test: func(_ []string, flat string) bool {
			lower := strings.ToLower(flat)
			if !strings.Contains(lower, "telnet ") {
				return false
			}
			return strings.Contains(lower, "/bin/sh") ||
				strings.Contains(lower, "/bin/bash") ||
				strings.Contains(lower, "mkfifo")
		},
	},
	{
		name: "mkfifo-pipe",
		desc: "mkfifo + /bin/sh + nc pattern",
		conf: 80,
		test: func(_ []string, flat string) bool {
			return strings.Contains(flat, "mkfifo") &&
				(strings.Contains(flat, "/bin/sh") || strings.Contains(flat, "/bin/bash")) &&
				(strings.Contains(flat, " nc ") || strings.Contains(flat, "openssl s_client"))
		},
	},
	{
		name: "openssl-sclient-shell",
		desc: "openssl s_client paired with shell — TLS-wrapped reverse shell",
		conf: 80,
		test: func(_ []string, flat string) bool {
			return strings.Contains(flat, "openssl s_client") &&
				(strings.Contains(flat, "/bin/sh") || strings.Contains(flat, "/bin/bash"))
		},
	},
}

// ncFollowsShellPath returns true if the value after the given
// flag is a shell path (.../sh or .../bash). Stops a false
// positive when -e is followed by something else.
func ncFollowsShellPath(argv []string, flag string) bool {
	for i, a := range argv {
		if a == flag && i+1 < len(argv) {
			v := argv[i+1]
			if strings.HasSuffix(v, "/sh") || strings.HasSuffix(v, "/bash") ||
				v == "/bin/sh" || v == "/bin/bash" {
				return true
			}
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
