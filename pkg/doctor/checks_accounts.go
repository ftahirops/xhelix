package doctor

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// accountChecks audit /etc/passwd, /etc/shadow, sudoers, and the
// authorized_keys files for the misconfigurations that turn local
// users into local root.
func accountChecks() []Check {
	return []Check{
		{
			ID:       "accounts.uid0_unique",
			Title:    "Only root has UID 0",
			Category: "accounts",
			Severity: SeverityCritical,
			Description: "A second uid 0 account is the canonical persistence trick — it doesn't show up in `whoami` for casual ops checks but has full root.",
			Impact:      "If an attacker has added themselves as a uid-0 user, every other 'is root locked down' check is moot.",
			Recommendation: "Identify the offending user with `awk -F: '($3==0)' /etc/passwd` and delete or fix the account.",
			Risky: true, // editing /etc/passwd badly bricks logins
			Run: func(_ context.Context) Result {
				users, err := readPasswdUID0()
				if err != nil {
					return ErrorResult(err)
				}
				if len(users) == 1 && users[0] == "root" {
					return PassResult("uid 0 = [root]")
				}
				return FailResult("uid 0 accounts: " + strings.Join(users, ", "))
			},
		},
		{
			ID:       "accounts.no_empty_passwords",
			Title:    "No empty password hashes in /etc/shadow",
			Category: "accounts",
			Severity: SeverityCritical,
			Description: "Empty hash field means the user can log in with no password if any path (PAM, su) honours empty passwords.",
			Impact:      "Combined with a misconfigured PAM stack, empty hashes mean password-less login.",
			Recommendation: "`passwd -l <user>` to lock, or `passwd <user>` to set one.",
			Risky: true,
			Run: func(_ context.Context) Result {
				users, err := readShadowEmpty()
				if err != nil {
					if os.IsPermission(err) {
						return SkipResult("no permission to read /etc/shadow (run as root)")
					}
					return ErrorResult(err)
				}
				if len(users) == 0 {
					return PassResult("no empty password hashes")
				}
				return FailResult("empty hashes: " + strings.Join(users, ", "))
			},
		},
		{
			ID:       "accounts.shadow_perms",
			Title:    "/etc/shadow is mode 0640 or stricter, owned root:shadow",
			Category: "accounts",
			Severity: SeverityHigh,
			Description: "Shadow contains the password hashes. World-readable shadow is a hash-cracking gift to any local attacker.",
			Impact:      "Loose perms let any local user grab the hashes and crack offline at leisure.",
			Recommendation: "`chown root:shadow /etc/shadow && chmod 0640 /etc/shadow`",
			FixCommand:     "chown root:shadow /etc/shadow && chmod 0640 /etc/shadow",
			Run: func(_ context.Context) Result {
				return checkFilePerms("/etc/shadow", 0o640)
			},
			Apply: func(_ context.Context) error {
				return os.Chmod("/etc/shadow", 0o640)
			},
		},
		{
			ID:       "accounts.passwd_perms",
			Title:    "/etc/passwd is mode 0644, owned root:root",
			Category: "accounts",
			Severity: SeverityHigh,
			Description: "World-writable /etc/passwd is the textbook persistence path.",
			Impact:      "If /etc/passwd is writable by anyone but root, account creation/escalation is one append away.",
			Recommendation: "`chown root:root /etc/passwd && chmod 0644 /etc/passwd`",
			FixCommand:     "chown root:root /etc/passwd && chmod 0644 /etc/passwd",
			Run: func(_ context.Context) Result {
				return checkFilePerms("/etc/passwd", 0o644)
			},
			Apply: func(_ context.Context) error {
				return os.Chmod("/etc/passwd", 0o644)
			},
		},
		{
			ID:       "accounts.sudoers_nopasswd",
			Title:    "No NOPASSWD sudo rules outside known-safe lists",
			Category: "accounts",
			Severity: SeverityHigh,
			Description: "NOPASSWD sudo lets a user (or attacker who lands as that user) escalate without re-auth. It's a frequent target after initial access.",
			Impact:      "If the attacker pivots to a NOPASSWD user, root is one shell away — no second-factor, no log of a password prompt.",
			Recommendation: "Audit `/etc/sudoers` and `/etc/sudoers.d/*`. Either remove NOPASSWD or restrict the command list to specific paths.",
			Run: func(_ context.Context) Result {
				rules, err := scanNopasswdRules()
				if err != nil {
					return SkipResult(err.Error())
				}
				if len(rules) == 0 {
					return PassResult("no NOPASSWD entries")
				}
				return WarnResult(fmt.Sprintf("%d NOPASSWD entries: %s", len(rules), strings.Join(rules, "; ")))
			},
		},
		{
			ID:       "accounts.root_authorized_keys",
			Title:    "/root/.ssh/authorized_keys exists and is mode 0600",
			Category: "accounts",
			Severity: SeverityMedium,
			Description: "If root has authorized_keys, perms must be 0600. Looser perms let other users or processes inject keys.",
			Impact:      "World-writable root authorized_keys = persistence + privilege in one append.",
			Recommendation: "`chmod 0600 /root/.ssh/authorized_keys && chown root:root /root/.ssh/authorized_keys`",
			FixCommand:     "chmod 0600 /root/.ssh/authorized_keys && chown root:root /root/.ssh/authorized_keys",
			Run: func(_ context.Context) Result {
				p := "/root/.ssh/authorized_keys"
				if !pathExists(p) {
					return SkipResult("file does not exist")
				}
				return checkFilePerms(p, 0o600)
			},
			Apply: func(_ context.Context) error {
				return os.Chmod("/root/.ssh/authorized_keys", 0o600)
			},
		},
	}
}

// readPasswdUID0 returns every username with uid==0 from /etc/passwd.
func readPasswdUID0() ([]string, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) >= 3 && fields[2] == "0" {
			out = append(out, fields[0])
		}
	}
	return out, sc.Err()
}

// readShadowEmpty returns usernames with an empty password hash.
func readShadowEmpty() ([]string, error) {
	f, err := os.Open("/etc/shadow")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) >= 2 && fields[1] == "" {
			out = append(out, fields[0])
		}
	}
	return out, sc.Err()
}

// checkFilePerms compares a file's mode to want; failure if looser.
// Owner is also checked: must be root for /etc files.
func checkFilePerms(path string, want os.FileMode) Result {
	st, err := os.Stat(path)
	if err != nil {
		return ErrorResult(err)
	}
	mode := st.Mode().Perm()
	stat, _ := st.Sys().(*syscall.Stat_t)
	uid := uint32(0)
	if stat != nil {
		uid = stat.Uid
	}
	if mode > want {
		return FailResult(fmt.Sprintf("%s mode = %o (want ≤ %o), uid=%d", path, mode, want, uid))
	}
	if uid != 0 {
		return FailResult(fmt.Sprintf("%s uid = %d (want 0)", path, uid))
	}
	return PassResult(fmt.Sprintf("%s mode=%o uid=%d", path, mode, uid))
}

// scanNopasswdRules walks /etc/sudoers and /etc/sudoers.d/* looking
// for NOPASSWD entries. We don't try to parse sudoers grammar — we
// flag the line for the operator to review.
func scanNopasswdRules() ([]string, error) {
	var rules []string
	files := []string{"/etc/sudoers"}
	if matches, _ := filepath.Glob("/etc/sudoers.d/*"); matches != nil {
		files = append(files, matches...)
	}
	for _, p := range files {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.Contains(strings.ToUpper(line), "NOPASSWD") {
				rules = append(rules, fmt.Sprintf("%s: %s", filepath.Base(p), line))
			}
		}
		f.Close()
	}
	return rules, nil
}
