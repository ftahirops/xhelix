// Package honeysh is the Ring 2 fake shell. It accepts a command
// stream from an attacker (typically routed here via
// bpf_override_return on security_bprm_check — see P-PS.6b), prints
// plausible-but-fake output with realistic latency, and emits every
// keystroke + response as a forensic event into the evidence chain.
//
// See PROTECTED_SERVICES_TRAP.md §4.1 for the design. The goal:
// attacker believes they have RCE for 60s+ while we harvest their
// commands, tooling, and TTPs. After ~90s of activity OR first
// observed privilege-escalation attempt, the planner score crosses
// 75 and SuspendProcess fires; the attacker's "shell" hangs forever.
//
// Pure Go, CGO_ENABLED=0. Standard library only.
package honeysh

import (
	"bufio"
	"io"
	"math/rand"
	"os"
	"strings"
	"time"
)

// Config tunes the per-session behavior. Zero values mean defaults.
type Config struct {
	// User shown in prompt + commands like `id`, `whoami`. Defaults
	// to "www-data" — the canonical web-server uid name.
	User string
	// Host shown in prompt + commands like `hostname`, `uname -n`.
	// Defaults to the matching protected service host name.
	Host string
	// CWD is the initial current-working-directory. Defaults to
	// "/var/www/html" (the canonical nginx document root).
	CWD string

	// MaxCommands ends the session after this many commands seen.
	// Defaults to 64.
	MaxCommands int
	// MaxDuration ends the session after this real-time window.
	// Defaults to 120s.
	MaxDuration time.Duration

	// LatencyMin / LatencyMax bound the per-command sleep inserted
	// before printing the response. Defaults: 80ms / 800ms.
	// Cost-asymmetry budget — attacker burns hundreds of seconds in
	// a multi-command interaction, we burn microseconds.
	LatencyMin time.Duration
	LatencyMax time.Duration

	// Rand seeds the latency randomizer. nil = use a fresh
	// time-based source (production); pass a deterministic
	// rand.Rand for tests.
	Rand *rand.Rand

	// Now returns the current time. nil = time.Now (production);
	// pass a fixed clock in tests.
	Now func() time.Time

	// Sleep is the function that injects latency. nil = time.Sleep
	// (production); set to a no-op for tests.
	Sleep func(time.Duration)
}

func (c *Config) defaulted() Config {
	d := *c
	if d.User == "" {
		d.User = "www-data"
	}
	if d.Host == "" {
		d.Host = "webhost"
	}
	if d.CWD == "" {
		d.CWD = "/var/www/html"
	}
	if d.MaxCommands == 0 {
		d.MaxCommands = 64
	}
	if d.MaxDuration == 0 {
		d.MaxDuration = 120 * time.Second
	}
	if d.LatencyMin == 0 {
		d.LatencyMin = 80 * time.Millisecond
	}
	if d.LatencyMax == 0 {
		d.LatencyMax = 800 * time.Millisecond
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Sleep == nil {
		d.Sleep = time.Sleep
	}
	if d.Rand == nil {
		d.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	return d
}

// Logger receives session events. Implementations push them into
// the evidence chain (P-PS.11) or stdout JSON during local testing.
// All methods MUST be safe for concurrent use.
type Logger interface {
	OnSessionStart(meta SessionMeta)
	OnCommand(c CommandEvent)
	OnSessionEnd(reason string, ev SessionEnd)
}

// SessionMeta is emitted once per session at startup.
type SessionMeta struct {
	SessionID string
	StartedAt time.Time
	User      string
	Host      string
	CWD       string

	// Optional attribution — populated by the dispatcher when the
	// session was triggered by a refusal that carried a remote IP.
	RemoteIP    string
	PID         uint32
	LineageID   uint64
	ServiceName string
}

// CommandEvent is emitted once per attacker command.
type CommandEvent struct {
	SessionID string
	At        time.Time
	Sequence  int    // 1-based counter within the session
	Raw       string // exact line the attacker typed
	Command   string // first token after parsing
	Args      []string
	Response  string // what we printed back (lossy capture for huge outputs)
	Latency   time.Duration

	// IOC hints — extracted opportunistically. Real extraction
	// happens in P-PS.11 across the full session.
	URLs    []string `json:",omitempty"`
	IPs     []string `json:",omitempty"`
	Domains []string `json:",omitempty"`
}

// SessionEnd is emitted once per session at end.
type SessionEnd struct {
	SessionID string
	EndedAt   time.Time
	Duration  time.Duration
	Commands  int
}

// Shell is one fake-shell session. Single-use — create one per
// attacker connection.
type Shell struct {
	cfg Config
	log Logger
	id  string
}

// New returns a Shell with the given config and logger.
//
// P-RF.9g L2: if cfg.Host matches the real host's os.Hostname()
// the deception surface leaks fleet identity to the attacker.
// New writes a warning to stderr in that case so operators catch
// the misconfiguration during integration. Real production
// deployments set Host to a plausible-but-fake value distinct
// from the production hostname.
func New(cfg Config, log Logger) *Shell {
	if log == nil {
		log = noopLogger{}
	}
	if real := realHostname(); real != "" && cfg.Host == real {
		_, _ = os.Stderr.WriteString(
			"xhelix-honeysh WARNING: cfg.Host == real os.Hostname() " +
				"(" + real + ") — attacker can correlate honey host with " +
				"fleet inventory. Set Host to a fake value.\n")
	}
	return &Shell{cfg: cfg.defaulted(), log: log, id: randSessionID(cfg.Rand)}
}

func realHostname() string {
	h, _ := os.Hostname()
	return h
}

// Serve runs one interactive shell session. Returns when the
// session ends (MaxCommands, MaxDuration, explicit "exit", or EOF).
//
// Returns the reason the session ended; nil error unless an I/O
// problem occurred.
func (s *Shell) Serve(stdin io.Reader, stdout io.Writer, attribution SessionMeta) (string, error) {
	meta := attribution
	meta.SessionID = s.id
	meta.StartedAt = s.cfg.Now()
	meta.User = s.cfg.User
	meta.Host = s.cfg.Host
	meta.CWD = s.cfg.CWD
	s.log.OnSessionStart(meta)

	deadline := meta.StartedAt.Add(s.cfg.MaxDuration)
	cwd := s.cfg.CWD
	scanner := bufio.NewScanner(stdin)
	scanner.Buffer(make([]byte, 64*1024), 256*1024)

	commands := 0
	endReason := "eof"
	for {
		// Prompt.
		if _, err := io.WriteString(stdout, prompt(s.cfg.User, s.cfg.Host, cwd)); err != nil {
			return "io_error", err
		}
		if !scanner.Scan() {
			break
		}
		line := strings.TrimRight(scanner.Text(), "\r\n")

		// Inject latency BEFORE the response (matches a slow
		// remote shell). Bounded by config.
		lat := randDuration(s.cfg.Rand, s.cfg.LatencyMin, s.cfg.LatencyMax)
		s.cfg.Sleep(lat)

		commands++
		ev := CommandEvent{
			SessionID: s.id,
			At:        s.cfg.Now(),
			Sequence:  commands,
			Raw:       line,
			Latency:   lat,
		}
		ev.Command, ev.Args = parseFirst(line)

		// Built-in: exit / quit / logout end the session cleanly.
		if isExitCommand(ev.Command) {
			endReason = "attacker_exit"
			s.log.OnCommand(ev)
			break
		}

		// Built-in: `cd <dir>` updates our cwd. Real bash would
		// validate; we accept any path.
		if ev.Command == "cd" {
			if len(ev.Args) > 0 {
				cwd = resolveCWD(cwd, ev.Args[0])
			} else {
				cwd = "/" + s.cfg.User // ~ → /www-data
			}
			ev.Response = ""
			s.log.OnCommand(ev)
			continue
		}

		// Compose response from the per-command generator.
		resp := respondTo(ev.Command, ev.Args, &s.cfg, cwd)
		if resp != "" {
			if _, err := io.WriteString(stdout, resp); err != nil {
				return "io_error", err
			}
			// Match real bash — most commands' output ends in \n.
			if !strings.HasSuffix(resp, "\n") {
				_, _ = io.WriteString(stdout, "\n")
			}
		}
		ev.Response = truncate(resp, 4096)
		extractIOCs(line, &ev)
		s.log.OnCommand(ev)

		if commands >= s.cfg.MaxCommands {
			endReason = "max_commands"
			break
		}
		if s.cfg.Now().After(deadline) {
			endReason = "max_duration"
			break
		}
	}

	end := SessionEnd{
		SessionID: s.id,
		EndedAt:   s.cfg.Now(),
		Duration:  s.cfg.Now().Sub(meta.StartedAt),
		Commands:  commands,
	}
	s.log.OnSessionEnd(endReason, end)
	return endReason, nil
}

// --- helpers ---

func prompt(user, host, cwd string) string {
	// Match Debian/Ubuntu default PS1: "user@host:cwd$ "
	short := cwd
	if user == "root" {
		return user + "@" + host + ":" + short + "# "
	}
	return user + "@" + host + ":" + short + "$ "
}

// parseFirst extracts the leading command and its args from a shell
// line, ignoring leading variable assignments and stripping
// pipes/redirects/sequences after the first command.
func parseFirst(line string) (cmd string, args []string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", nil
	}

	// Snip at the first shell separator — pipe, sequence, etc.
	for _, sep := range []string{" | ", " || ", " && ", ";", "|"} {
		if i := strings.Index(line, sep); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
	}
	// Strip leading `VAR=value` assignments — real bash treats them
	// as env for the next command. For our purposes we just want the
	// command.
	fields := strings.Fields(line)
	for len(fields) > 0 && strings.Contains(fields[0], "=") && !strings.HasPrefix(fields[0], "=") {
		// "FOO=bar" → drop.
		if !strings.HasPrefix(fields[0], "-") {
			fields = fields[1:]
			continue
		}
		break
	}
	if len(fields) == 0 {
		return "", nil
	}
	return fields[0], fields[1:]
}

func isExitCommand(cmd string) bool {
	switch cmd {
	case "exit", "quit", "logout":
		return true
	}
	return false
}

func resolveCWD(cur, target string) string {
	if target == "" || target == "~" {
		return "/root"
	}
	if strings.HasPrefix(target, "/") {
		return target
	}
	return cur + "/" + target
}

func randDuration(r *rand.Rand, lo, hi time.Duration) time.Duration {
	if hi <= lo {
		return lo
	}
	span := int64(hi - lo)
	return lo + time.Duration(r.Int63n(span))
}

func randSessionID(r *rand.Rand) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	if r == nil {
		r = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	b := make([]byte, 12)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...[truncated]"
}

// noopLogger is the default when caller doesn't supply one.
type noopLogger struct{}

func (noopLogger) OnSessionStart(SessionMeta)     {}
func (noopLogger) OnCommand(CommandEvent)         {}
func (noopLogger) OnSessionEnd(string, SessionEnd) {}
