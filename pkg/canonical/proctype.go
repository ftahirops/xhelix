// Package canonical provides stable, PID-reuse-safe identities for
// processes, files, and sockets used by the xhelix Event Admission
// Controller and downstream enrichment pipeline.
//
// The package contains no decision logic; it only canonicalises
// what the kernel reports into identifiers that can be used as map
// keys and audit-chain references.
package canonical

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ProcKey is the PID-reuse-safe process identifier.
//
// Linux reuses PID numbers after a process exits. (PID, StartTicks)
// is unique for the lifetime of the current kernel boot because no
// two processes can have the same PID at the same start tick.
//
// StartTicks is /proc/PID/stat field 22 (starttime) — jiffies since
// boot. Converting to wall-clock nanoseconds requires the boot time
// + clock-tick rate; for identity purposes the raw tick value is
// sufficient and avoids the conversion expense.
type ProcKey struct {
	PID        uint32
	StartTicks uint64
}

// Zero is the zero-value sentinel.
var Zero = ProcKey{}

// IsValid returns true if the key carries a real process identity.
// A zero PID or zero StartTicks is treated as unset.
func (p ProcKey) IsValid() bool {
	return p.PID != 0 && p.StartTicks != 0
}

// Equal returns true if both fields match.
func (p ProcKey) Equal(other ProcKey) bool {
	return p.PID == other.PID && p.StartTicks == other.StartTicks
}

// String renders as "pid@starttick" for logs and audit-chain refs.
func (p ProcKey) String() string {
	if !p.IsValid() {
		return "0@0"
	}
	return fmt.Sprintf("%d@%d", p.PID, p.StartTicks)
}

// ReadProcKey reads /proc/PID/stat and constructs a ProcKey.
// Returns ProcKeyNotFound if the process doesn't exist; any other
// error indicates a malformed stat line or read failure.
func ReadProcKey(pid uint32) (ProcKey, error) {
	if pid == 0 {
		return Zero, fmt.Errorf("canonical: pid 0 not a real process")
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		if os.IsNotExist(err) {
			return Zero, ProcKeyNotFound{PID: pid}
		}
		return Zero, fmt.Errorf("canonical: read /proc/%d/stat: %w", pid, err)
	}
	ticks, err := parseStartTime(data)
	if err != nil {
		return Zero, fmt.Errorf("canonical: pid %d: %w", pid, err)
	}
	return ProcKey{PID: pid, StartTicks: ticks}, nil
}

// ProcKeyNotFound indicates the process no longer exists.
type ProcKeyNotFound struct {
	PID uint32
}

func (e ProcKeyNotFound) Error() string {
	return fmt.Sprintf("canonical: pid %d not found", e.PID)
}

// parseStartTime extracts field 22 (starttime) from /proc/PID/stat.
//
// The stat line shape is:
//   PID (comm) state ppid pgrp session tty_nr ...
//
// The comm field is parenthesised and may contain spaces or special
// characters. We walk backwards to find the closing paren, then count
// space-separated fields from there. After the closing paren the next
// field is "state" (which is field 3 in the full line); field 22
// (starttime) is index 19 in the post-paren slice.
func parseStartTime(line []byte) (uint64, error) {
	paren := -1
	for i := len(line) - 1; i >= 0; i-- {
		if line[i] == ')' {
			paren = i
			break
		}
	}
	if paren < 0 {
		return 0, fmt.Errorf("malformed stat: no closing comm paren")
	}
	rest := string(line[paren+1:])
	fields := strings.Fields(rest)

	const startTimeIdx = 19
	if len(fields) <= startTimeIdx {
		return 0, fmt.Errorf("malformed stat: %d fields after comm, need >%d",
			len(fields), startTimeIdx)
	}
	ticks, err := strconv.ParseUint(fields[startTimeIdx], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse starttime %q: %w", fields[startTimeIdx], err)
	}
	if ticks == 0 {
		return 0, fmt.Errorf("starttime is zero (unexpected for a real process)")
	}
	return ticks, nil
}
