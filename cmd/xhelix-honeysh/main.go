// Command xhelix-honeysh is the static fake-shell binary that
// bpf_override_return routes forbidden execve attempts to (P-PS.6b).
//
// Pure Go, CGO_ENABLED=0 — static binary suitable for shipping in
// /usr/lib/xhelix/honey-sh.
//
// Reads stdin, writes plausible fake output to stdout, emits JSON-
// lines forensic events to a configured sink (file path, or stdout
// of fd 3 if env XHELIX_HONEYSH_LOG_FD=3 is set — useful when the
// daemon supervises us via socketpair).
//
// See PROTECTED_SERVICES_TRAP.md §4.1.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/xhelix/xhelix/pkg/deception/honeysh"
)

func main() {
	user := flag.String("user", envOr("USER", "www-data"), "username shown in prompt and `id` output")
	host := flag.String("host", envOr("HOSTNAME", "webhost"), "hostname shown in prompt and `uname -n`")
	cwd := flag.String("cwd", "/var/www/html", "starting cwd")
	logPath := flag.String("log", os.Getenv("XHELIX_HONEYSH_LOG"), "JSON-lines forensic log path (default: stderr)")
	remoteIP := flag.String("remote-ip", os.Getenv("XHELIX_HONEYSH_REMOTE_IP"), "attacker IP for attribution")
	service := flag.String("service", os.Getenv("XHELIX_HONEYSH_SERVICE"), "protected service name for attribution")
	lineage := flag.Uint64("lineage", envUint64("XHELIX_HONEYSH_LINEAGE"), "lineage_id for attribution")
	flag.Parse()

	logger, closer, err := openLogger(*logPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "xhelix-honeysh: log open:", err)
		os.Exit(2)
	}
	if closer != nil {
		defer closer.Close()
	}

	cfg := honeysh.Config{User: *user, Host: *host, CWD: *cwd}
	s := honeysh.New(cfg, logger)
	attr := honeysh.SessionMeta{
		RemoteIP:    *remoteIP,
		PID:         uint32(os.Getpid()),
		LineageID:   *lineage,
		ServiceName: *service,
	}
	if _, err := s.Serve(os.Stdin, os.Stdout, attr); err != nil {
		fmt.Fprintln(os.Stderr, "xhelix-honeysh: serve:", err)
		os.Exit(2)
	}
	// Always exit 0 — attacker should see a normal shell exit. The
	// real "containment" happened upstream.
	os.Exit(0)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envUint64(k string) uint64 {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			return n
		}
	}
	return 0
}

// openLogger returns a Logger that writes JSON lines to either:
//   - the file at logPath (created/appended) if non-empty
//   - the inherited fd in XHELIX_HONEYSH_LOG_FD if set
//   - os.Stderr otherwise
func openLogger(logPath string) (honeysh.Logger, io.Closer, error) {
	if fdStr := os.Getenv("XHELIX_HONEYSH_LOG_FD"); fdStr != "" {
		fd, err := strconv.Atoi(fdStr)
		if err != nil {
			return nil, nil, fmt.Errorf("bad XHELIX_HONEYSH_LOG_FD: %w", err)
		}
		f := os.NewFile(uintptr(fd), fmt.Sprintf("honeysh-log-fd-%d", fd))
		if f == nil {
			return nil, nil, fmt.Errorf("could not open fd %d", fd)
		}
		return &jsonlLogger{w: f}, f, nil
	}
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, err
		}
		return &jsonlLogger{w: f}, f, nil
	}
	return &jsonlLogger{w: os.Stderr}, nil, nil
}

// jsonlLogger writes one JSON object per line for every event. Each
// line is also valid for the evidence-chain ingester (P-PS.11).
type jsonlLogger struct {
	w io.Writer
}

type jsonRecord struct {
	Type  string      `json:"type"`
	Body  interface{} `json:"body"`
}

func (l *jsonlLogger) emit(typ string, body interface{}) {
	rec := jsonRecord{Type: typ, Body: body}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	_, _ = l.w.Write(append(b, '\n'))
}

func (l *jsonlLogger) OnSessionStart(m honeysh.SessionMeta)        { l.emit("session_start", m) }
func (l *jsonlLogger) OnCommand(c honeysh.CommandEvent)             { l.emit("command", c) }
func (l *jsonlLogger) OnSessionEnd(reason string, e honeysh.SessionEnd) {
	l.emit("session_end", struct {
		Reason string `json:"reason"`
		honeysh.SessionEnd
	}{reason, e})
}
