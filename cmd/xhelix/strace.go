package main

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// runStrace runs `strace -p <pid> -f -e trace=network,file -t -s 256`
// for `dur` and returns the captured lines, parsed into a small
// structured slice.
//
// Requires CAP_SYS_PTRACE (xhelix has it via systemd unit). Bounded:
// caller passes a duration; we kill -SIGTERM at the bound.
func runStrace(parent context.Context, pid uint32, dur time.Duration) ([]map[string]any, error) {
	ctx, cancel := context.WithTimeout(parent, dur+time.Second)
	defer cancel()

	// -ff would emit to per-pid files; we want everything on stderr
	// so we can stream it. -e trace= keeps the noise down.
	cmd := exec.CommandContext(ctx, "strace",
		"-p", fmt.Sprintf("%d", pid),
		"-f",
		"-e", "trace=network,file",
		"-t",
		"-s", "256",
		"-y",
	)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("strace start: %w", err)
	}

	// Hard deadline: send SIGTERM then SIGKILL.
	go func() {
		select {
		case <-time.After(dur):
			_ = cmd.Process.Signal(syscall.SIGTERM)
			time.Sleep(200 * time.Millisecond)
			_ = cmd.Process.Kill()
		case <-ctx.Done():
		}
	}()

	out := []map[string]any{}
	scanner := bufio.NewScanner(stderr)
	scanner.Buffer(make([]byte, 1<<16), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		parsed := parseStraceLine(line)
		if parsed == nil {
			continue
		}
		out = append(out, parsed)
		if len(out) >= 500 {
			break
		}
	}
	_ = cmd.Wait()
	return out, nil
}

// parseStraceLine extracts (time, pid, syscall, args, ret) from one
// strace line. The grammar is forgiving — strace's output isn't
// strictly structured, so we capture the shape that's useful and
// leave the rest as the raw line.
//
// Expected forms:
//   "12345 12:34:56 connect(5<TCP:[127.0.0.1:1234->1.2.3.4:443]>, ...) = 0"
//   "12:34:56 connect(...) = 0"
func parseStraceLine(s string) map[string]any {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	// Skip strace's own status lines.
	if strings.HasPrefix(s, "strace:") {
		return nil
	}
	// Skip unfinished/resumed marker lines (multi-line syscalls).
	if strings.Contains(s, "<unfinished ...>") || strings.Contains(s, "resumed>") {
		return nil
	}
	// Skip signal-delivered lines (no syscall structure).
	if strings.HasPrefix(s, "---") || strings.HasPrefix(s, "+++") {
		return nil
	}
	out := map[string]any{"raw": s}
	// First optional field: pid (digits only).
	rest := s
	if i := strings.IndexByte(rest, ' '); i > 0 && allDigits(rest[:i]) {
		out["pid"] = rest[:i]
		rest = strings.TrimSpace(rest[i+1:])
	}
	// Optional time HH:MM:SS.
	if len(rest) >= 8 && rest[2] == ':' && rest[5] == ':' {
		out["time"] = rest[:8]
		rest = strings.TrimSpace(rest[8:])
	}
	// syscall name up to '('.
	if i := strings.IndexByte(rest, '('); i > 0 {
		out["syscall"] = rest[:i]
		rest = rest[i:]
	}
	// args + ret split on " = ".
	if i := strings.LastIndex(rest, " = "); i > 0 {
		out["args"] = rest[:i]
		out["ret"] = strings.TrimSpace(rest[i+3:])
	} else {
		out["args"] = rest
	}
	return out
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
