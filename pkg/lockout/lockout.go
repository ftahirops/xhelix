// Package lockout neutralises a compromised local account.
//
// Steps, in order (any one failing is logged but does not abort):
//
//  1. passwd -l <user>           — locks the password hash
//  2. usermod -L -e 1 <user>     — sets account expiry to epoch
//  3. revoke ~/.ssh/authorized_keys (rename with timestamp suffix)
//  4. SIGKILL every process belonging to the user
//  5. Force-disconnect every PTY/SSH session of the user (pkill -KILL -t)
//
// The intent is not subtle: an operator pressing the lockout button
// has decided this account is hostile. We err toward "fully kicked
// out" rather than "partially restricted". Restoration is manual.
package lockout

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Result is the per-step outcome.
type Result struct {
	User           string
	PasswordLocked bool
	AccountExpired bool
	KeysRevoked    bool
	ProcessesKilled int
	SessionsKilled  int
	Errors         []string
}

// Lockout runs the full sequence against username. Returns a Result
// even on partial failure; the operator UI shows what worked.
func Lockout(username string) Result {
	r := Result{User: username}

	if username == "" {
		r.Errors = append(r.Errors, "empty username")
		return r
	}
	// Refuse to lock root or uid<1000 system accounts unless the
	// caller passes the explicit prefix. This prevents a misfired
	// rule from disabling the only account that can recover the box.
	if username == "root" {
		r.Errors = append(r.Errors, "refusing to lock root")
		return r
	}
	u, err := user.Lookup(username)
	if err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("user lookup: %v", err))
		return r
	}
	uid, _ := strconv.Atoi(u.Uid)
	if uid < 1000 {
		r.Errors = append(r.Errors, fmt.Sprintf("refusing to lock system uid %d", uid))
		return r
	}

	// 1. Lock password.
	if err := run("passwd", "-l", username); err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("passwd -l: %v", err))
	} else {
		r.PasswordLocked = true
	}

	// 2. Expire account (defence in depth: passwd -l can be undone
	// by an attacker with shadow write; usermod -e adds a second hook).
	if err := run("usermod", "-L", "-e", "1", username); err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("usermod: %v", err))
	} else {
		r.AccountExpired = true
	}

	// 3. Revoke authorized_keys. We rename with timestamp rather than
	// delete so the operator can audit what was there.
	authKeys := filepath.Join(u.HomeDir, ".ssh", "authorized_keys")
	if _, err := os.Stat(authKeys); err == nil {
		ts := time.Now().UTC().Format("20060102T150405Z")
		newPath := authKeys + ".xhelix-revoked." + ts
		if err := os.Rename(authKeys, newPath); err != nil {
			r.Errors = append(r.Errors, fmt.Sprintf("revoke keys: %v", err))
		} else {
			r.KeysRevoked = true
		}
	}

	// 4. Kill the user's processes. pkill -KILL -u handles this
	// atomically across the whole user session.
	if out, err := exec.Command("pkill", "-KILL", "-u", username).CombinedOutput(); err == nil {
		// pkill exit 0 means at least one match was killed; exit 1
		// means none. Either is fine.
		r.ProcessesKilled = countLines(string(out))
	} else if !exitedNoMatch(err) {
		r.Errors = append(r.Errors, fmt.Sprintf("pkill -u: %v", err))
	}

	// 5. Tear down PTYs/SSH sessions specifically. -t ttyname is what
	// kicks ssh sessions even if the parent shell already died.
	ttys, _ := userTTYs(username)
	for _, tty := range ttys {
		if err := exec.Command("pkill", "-KILL", "-t", tty).Run(); err == nil {
			r.SessionsKilled++
		}
	}

	return r
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func exitedNoMatch(err error) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode() == 1
	}
	return false
}

func countLines(s string) int {
	if s == "" {
		return 0
	}
	n := strings.Count(s, "\n")
	if !strings.HasSuffix(s, "\n") {
		n++
	}
	return n
}

// userTTYs returns the tty names attached to username, parsed from
// `who`. Returns nil on any error — TTY enumeration is best-effort.
//
// Each candidate is validated against a strict regex before being
// returned. utmp on some configurations is world-writable, so a
// crafted entry could put a leading-dash value into fields[1] that
// pkill would interpret as a flag (`pkill -KILL -t -a` with a forged
// "-a" tty would behave as `pkill -a`). The validation kills that
// vector — only the standard tty/pts shape is accepted.
func userTTYs(username string) ([]string, error) {
	out, err := exec.Command("who").Output()
	if err != nil {
		return nil, err
	}
	var ttys []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != username {
			continue
		}
		if !validTTYName(fields[1]) {
			continue
		}
		ttys = append(ttys, fields[1])
	}
	return ttys, nil
}

// validTTYName matches "ttyN", "ttyXY", "pts/N", and "console" only —
// the standard tty / pts shape. Anything else (including leading dash,
// shell metacharacters, or path traversal attempts) is rejected so
// the value can be safely passed to `pkill -t`.
var ttyRe = regexp.MustCompile(`^(tty[a-zA-Z0-9]+|pts/\d+|console)$`)

func validTTYName(s string) bool { return ttyRe.MatchString(s) }
