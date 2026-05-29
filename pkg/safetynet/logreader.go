// Kernel-log tailer for the safetynet block_observe drop chain.
//
// nftables installs a `log prefix "xhelix-bo "` rule before the drop.
// The kernel writes one line per dropped packet to the ring buffer,
// reachable via journalctl -k. Lines look like:
//
//   xhelix-bo IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=5.6.7.8 \
//   	PROTO=TCP SPT=12345 DPT=443 LEN=60 ...
//
// We tail the journal, grep for our prefix, parse SRC=/DST=/PROTO=/DPT=
// into Attempt, and feed SafetyNet.RecordAttempt. Best-effort: if
// journalctl isn't available we return a no-op stopper (the daemon
// keeps running without per-attempt forensics).
package safetynet

import (
	"bufio"
	"context"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
)

// StartLogReader starts a goroutine tailing the kernel log for
// "xhelix-bo " lines and feeding SafetyNet.RecordAttempt. Returns a
// stop func tied to ctx cancellation.
//
// Best-effort: if journalctl is missing we log a warning once and
// return a no-op stop func.
func StartLogReader(ctx context.Context, sn *SafetyNet, logger *slog.Logger) func() {
	if sn == nil {
		return func() {}
	}
	if _, err := exec.LookPath("journalctl"); err != nil {
		if logger != nil {
			logger.Warn("safetynet logreader: journalctl not found; attempt log disabled")
		}
		return func() {}
	}

	rctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(rctx, "journalctl", "-k", "-f", "--output=cat", "--grep=xhelix-bo")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		if logger != nil {
			logger.Warn("safetynet logreader: stdout pipe", "err", err)
		}
		return func() {}
	}
	if err := cmd.Start(); err != nil {
		cancel()
		if logger != nil {
			logger.Warn("safetynet logreader: start", "err", err)
		}
		return func() {}
	}

	go func() {
		defer func() { _ = cmd.Wait() }()
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64*1024), 256*1024)
		for sc.Scan() {
			line := sc.Text()
			if !strings.Contains(line, "xhelix-bo") {
				continue
			}
			if a, ok := parseNftLine(line); ok {
				sn.RecordAttempt(a)
			}
		}
	}()

	return func() {
		cancel()
		_ = cmd.Process.Kill()
	}
}

// parseNftLine extracts SRC/DST/PROTO/DPT/LEN out of an nftables
// kernel log line. Returns ok=false if no SRC field is present.
func parseNftLine(line string) (Attempt, bool) {
	var a Attempt
	gotSrc := false
	// Scan space-separated KEY=VALUE tokens.
	for _, tok := range strings.Fields(line) {
		eq := strings.IndexByte(tok, '=')
		if eq <= 0 {
			continue
		}
		k, v := tok[:eq], tok[eq+1:]
		switch k {
		case "SRC":
			a.SrcIP = v
			gotSrc = true
		case "DST":
			a.DstIP = v
		case "PROTO":
			a.Proto = v
		case "DPT":
			if n, err := strconv.ParseUint(v, 10, 16); err == nil {
				a.DstPort = uint16(n)
			}
		case "LEN":
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				a.Bytes = n
			}
		}
	}
	return a, gotSrc
}
