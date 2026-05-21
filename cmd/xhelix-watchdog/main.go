// Command xhelix-watchdog is the independent verifier that runs
// alongside the xhelix daemon (or on a separate host) and detects
// three failure classes the daemon itself cannot:
//
//  1. xhelix daemon is dead / unresponsive (the pidfile points
//     nowhere, or the LocalAPI socket is stale).
//  2. The on-disk evidence chain doesn't verify (truncated,
//     tampered with, or rewound).
//  3. Alerts.jsonl has stopped growing despite the daemon being
//     alive (the alert sink is dead — exactly the bug P-PS.25
//     fixed).
//
// The watchdog is single-binary, monitor-only. On failure it:
//
//  - writes a tagged line to a separate alarm log
//    (/var/log/xhelix/watchdog.jsonl)
//  - exits non-zero so systemd / cron / a remote orchestrator
//    notices
//  - optionally POSTs to a webhook URL
//
// Why a separate process: if xhelix's own tamperguard is
// compromised by the very attack we're trying to detect, an
// independent process catches it. Run under a separate systemd
// unit (xhelix-watchdog.service) so its lifecycle is decoupled
// from xhelix.service.
//
// Run: xhelix-watchdog --chain /var/lib/xhelix/chain --pub <hex> \
//          --alerts /var/log/xhelix/alerts.jsonl --pid /run/xhelix/xhelix.pid
//
// Exit codes:
//   0  — all checks pass
//   2  — daemon missing
//   3  — chain verify failed
//   4  — alerts.jsonl stale (no growth)
//   5  — local API socket missing / unresponsive
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	var (
		chainDir     = flag.String("chain", "/var/lib/xhelix/chain", "evidence chain dir")
		pubHex       = flag.String("pub", "", "ed25519 pubkey hex (chain.pub)")
		pubFile      = flag.String("pub-file", "", "alternative: path to file containing hex pub")
		alertsPath   = flag.String("alerts", "/var/log/xhelix/alerts.jsonl", "alerts.jsonl path")
		pidPath      = flag.String("pid", "/run/xhelix/xhelix.pid", "xhelix.pid path")
		sockPath     = flag.String("socket", "/run/xhelix/xhelix.sock", "LocalAPI socket")
		alarmLog     = flag.String("alarm-log", "/var/log/xhelix/watchdog.jsonl", "where alarms go")
		webhook      = flag.String("webhook", "", "optional webhook URL for alarms")
		staleAlertS  = flag.Int("stale-alert-secs", 600, "fail if alerts.jsonl hasn't grown for N seconds")
		verifyBin    = flag.String("verify-bin", "/usr/local/bin/xhelix-verify", "xhelix-verify binary")
		once         = flag.Bool("once", false, "run all checks once + exit (for systemd OnCalendar)")
		interval     = flag.Duration("interval", 5*time.Minute, "loop interval (when not --once)")
	)
	flag.Parse()

	if *pubHex == "" && *pubFile != "" {
		b, err := os.ReadFile(*pubFile)
		if err != nil {
			die("read pub-file %s: %v", *pubFile, err)
		}
		*pubHex = strings.TrimSpace(string(b))
	}
	if *pubHex != "" {
		if _, err := hex.DecodeString(*pubHex); err != nil {
			die("invalid pub hex: %v", err)
		}
	}

	w := &watchdog{
		chainDir:    *chainDir,
		pubHex:      *pubHex,
		alertsPath:  *alertsPath,
		pidPath:     *pidPath,
		sockPath:    *sockPath,
		alarmLog:    *alarmLog,
		webhook:     *webhook,
		staleSecs:   *staleAlertS,
		verifyBin:   *verifyBin,
	}

	if *once {
		os.Exit(w.runOnce())
	}
	for {
		_ = w.runOnce()
		time.Sleep(*interval)
	}
}

type watchdog struct {
	chainDir, pubHex, alertsPath, pidPath, sockPath, alarmLog, webhook string
	staleSecs                                                          int
	verifyBin                                                          string
}

// alarm records the watchdog's verdict to the alarm log and (if
// configured) the webhook. Returns the exit code that runOnce
// should propagate.
type alarm struct {
	Kind     string    `json:"kind"`
	Reason   string    `json:"reason"`
	Time     time.Time `json:"time"`
	Hostname string    `json:"hostname"`
	ExitCode int       `json:"exit_code"`
}

func (w *watchdog) runOnce() int {
	checks := []func() (int, string){
		w.checkDaemonAlive,
		w.checkSocketReachable,
		w.checkAlertsFlowing,
		w.checkChainVerifies,
	}
	for i, ck := range checks {
		code, reason := ck()
		if code != 0 {
			w.raise(alarm{
				Kind: kindForCheck(i), Reason: reason,
				Time: time.Now().UTC(), Hostname: hostname(),
				ExitCode: code,
			})
			return code
		}
	}
	return 0
}

func kindForCheck(i int) string {
	switch i {
	case 0:
		return "daemon-missing"
	case 1:
		return "socket-unreachable"
	case 2:
		return "alerts-stale"
	case 3:
		return "chain-verify-failed"
	}
	return "unknown"
}

// ─── checks ─────────────────────────────────────────────────

func (w *watchdog) checkDaemonAlive() (int, string) {
	data, err := os.ReadFile(w.pidPath)
	if err != nil {
		return 2, fmt.Sprintf("read pidfile %s: %v", w.pidPath, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 2, fmt.Sprintf("parse pid: %v", err)
	}
	commData, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return 2, fmt.Sprintf("daemon pid %d not in /proc: %v", pid, err)
	}
	if comm := strings.TrimSpace(string(commData)); comm != "xhelix" {
		return 2, fmt.Sprintf("pid %d comm=%q, want 'xhelix'", pid, comm)
	}
	return 0, ""
}

func (w *watchdog) checkSocketReachable() (int, string) {
	c, err := net.DialTimeout("unix", w.sockPath, 2*time.Second)
	if err != nil {
		return 5, fmt.Sprintf("connect %s: %v", w.sockPath, err)
	}
	_ = c.Close()
	return 0, ""
}

func (w *watchdog) checkAlertsFlowing() (int, string) {
	st, err := os.Stat(w.alertsPath)
	if err != nil {
		return 4, fmt.Sprintf("stat %s: %v", w.alertsPath, err)
	}
	age := time.Since(st.ModTime())
	if age > time.Duration(w.staleSecs)*time.Second {
		return 4, fmt.Sprintf("alerts.jsonl unchanged for %s (threshold %ds)",
			age.Truncate(time.Second), w.staleSecs)
	}
	return 0, ""
}

func (w *watchdog) checkChainVerifies() (int, string) {
	if w.pubHex == "" {
		// no pubkey → skip verify (operator hasn't wired it yet)
		return 0, ""
	}
	if _, err := os.Stat(w.verifyBin); err != nil {
		return 0, "" // not installed; skip
	}
	if _, err := os.Stat(w.chainDir); err != nil {
		return 3, fmt.Sprintf("chain dir %s missing: %v", w.chainDir, err)
	}
	out, err := exec.Command(w.verifyBin, "--chain", w.chainDir, "--pub", w.pubHex).
		CombinedOutput()
	if err != nil {
		return 3, fmt.Sprintf("xhelix-verify failed: %v\n%s", err, out)
	}
	return 0, ""
}

// ─── alarm raising ───────────────────────────────────────────

func (w *watchdog) raise(a alarm) {
	// 1. Write a JSON-line to the alarm log.
	if dir := filepath.Dir(w.alarmLog); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o750)
	}
	if f, err := os.OpenFile(w.alarmLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640); err == nil {
		_ = json.NewEncoder(f).Encode(a)
		_ = f.Close()
	}
	// 2. Webhook if configured.
	if w.webhook != "" {
		body, _ := json.Marshal(a)
		req, err := http.NewRequest("POST", w.webhook, strings.NewReader(string(body)))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			c := &http.Client{Timeout: 3 * time.Second}
			if resp, err := c.Do(req); err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}
	}
	// 3. Stderr so systemd journal sees it.
	fmt.Fprintf(os.Stderr, "xhelix-watchdog ALARM kind=%s reason=%s\n",
		a.Kind, a.Reason)
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

var _ = errors.New // future-use
