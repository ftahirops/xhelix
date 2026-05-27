package pkgmgr

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// TailApt tails /var/log/apt/history.log and feeds Start-Date / End-Date
// transitions into the Store. Blocks until ctx is cancelled.
//
// apt history.log format:
//
//	Start-Date: 2026-05-01  06:50:50
//	Commandline: /usr/bin/unattended-upgrade
//	Upgrade: ...
//	End-Date: 2026-05-01  06:51:05
//	(blank line)
//
// Missing log file is logged + returned as nil (the daemon should not
// crash if apt isn't installed).
func TailApt(ctx context.Context, store *Store, path string) error {
	return tailLog(ctx, store, path, ManagerApt, parseAptLine)
}

// aptLineState is per-tailer parse state — apt transactions span
// multiple lines and we need to remember the Start-Date until we
// see the matching End-Date.
type aptLineState struct {
	pendingStart   time.Time
	pendingCommand string
}

var aptState aptLineState

func parseAptLine(line string, _ time.Time) lineEvent {
	if strings.HasPrefix(line, "Start-Date: ") {
		t, err := time.Parse("2006-01-02  15:04:05", line[len("Start-Date: "):])
		if err != nil {
			return lineEvent{}
		}
		aptState.pendingStart = t
		return lineEvent{}
	}
	if strings.HasPrefix(line, "Commandline: ") {
		aptState.pendingCommand = line[len("Commandline: "):]
		return lineEvent{}
	}
	if strings.HasPrefix(line, "End-Date: ") {
		t, err := time.Parse("2006-01-02  15:04:05", line[len("End-Date: "):])
		if err != nil {
			return lineEvent{}
		}
		ev := lineEvent{
			kind:     openClose,
			start:    aptState.pendingStart,
			end:      t,
			command:  aptState.pendingCommand,
		}
		aptState.pendingStart = time.Time{}
		aptState.pendingCommand = ""
		return ev
	}
	return lineEvent{}
}

// ──────────────────────────────────────────────────────────────────
// Generic tail loop — shared by apt + dpkg + dnf parsers.
// ──────────────────────────────────────────────────────────────────

type lineEventKind int

const (
	noEvent lineEventKind = iota
	openOnly             // just bump the active window (dpkg)
	openClose            // explicit start + end (apt)
)

type lineEvent struct {
	kind    lineEventKind
	start   time.Time
	end     time.Time
	command string
}

type lineParser func(line string, fallbackTs time.Time) lineEvent

func tailLog(ctx context.Context, store *Store, path string, m Manager, parser lineParser) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			// Missing log is fine — operator may not have this manager installed.
			if store.log != nil {
				store.log.Info("pkgmgr: tailer skipped — log file not present", "path", path, "manager", string(m))
			}
			return nil
		}
		return fmt.Errorf("tailLog stat %s: %w", path, err)
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("tailLog open %s: %w", path, err)
	}
	defer f.Close()

	// Seek to end so we don't replay history on startup. Historical
	// transactions are not actionable.
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("tailLog seek end: %w", err)
	}

	reader := bufio.NewReader(f)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				// No new data. Wait + check for log rotation.
				select {
				case <-ctx.Done():
					return nil
				case <-ticker.C:
				}
				// Detect log rotation: stat the original path; if inode
				// changed, reopen.
				if newInode, ok := inodeOf(path); ok {
					curInode, _ := inodeOfFd(f)
					if newInode != curInode {
						_ = f.Close()
						f, err = os.Open(path)
						if err != nil {
							// Couldn't reopen — wait + retry.
							time.Sleep(2 * time.Second)
							continue
						}
						reader = bufio.NewReader(f)
						if store.log != nil {
							store.log.Info("pkgmgr: tailer rotated", "path", path, "manager", string(m))
						}
					}
				}
				continue
			}
			return fmt.Errorf("tailLog read: %w", err)
		}

		line = strings.TrimRight(line, "\r\n")
		ev := parser(line, time.Now())
		switch ev.kind {
		case openOnly:
			store.Open(m, ev.start, ev.end, ev.command)
		case openClose:
			store.Open(m, ev.start, ev.end, ev.command)
			store.Close(m, ev.end)
		}
	}
}

func inodeOf(path string) (uint64, bool) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	if sys, ok := st.Sys().(interface{ Ino() uint64 }); ok {
		return sys.Ino(), true
	}
	// Fallback to syscall.Stat_t — see inode_linux.go.
	return statInode(st)
}

func inodeOfFd(f *os.File) (uint64, bool) {
	st, err := f.Stat()
	if err != nil {
		return 0, false
	}
	return statInode(st)
}
