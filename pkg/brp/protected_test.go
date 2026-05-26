package brp

import "testing"

func TestIsProtectedPath_DirectoryPrefix(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		// Exact directory entry.
		{"/etc/psa/", true},
		// Files within a protected dir.
		{"/etc/psa/.psa.shadow", true},
		{"/etc/psa/private/secret_key", true},
		{"/var/lib/mysql/ibdata1", true},
		{"/root/.ssh/authorized_keys", true},
		{"/etc/cron.d/backup", true},
		{"/etc/sudoers.d/operator", true},
		// Bare directory without trailing slash should also match.
		{"/etc/psa", true},
		{"/var/lib/mysql", true},
		// Non-protected paths.
		{"/home/alice/file", false},
		{"/var/www/index.html", false},
		{"/tmp/random.log", false},
		// Empty and trivial.
		{"", false},
		{"/", false},
	}
	for _, c := range cases {
		if got := IsProtectedPath(c.path); got != c.want {
			t.Errorf("IsProtectedPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestIsProtectedPath_ExactFile(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/etc/passwd", true},
		{"/etc/shadow", true},
		{"/etc/sudoers", true},
		{"/etc/fstab", true},
		{"/etc/hosts", true},
		{"/etc/resolv.conf", true},
		// Adjacent files that should NOT match.
		{"/etc/passwd-", false},  // backup file
		{"/etc/passwdx", false},  // similar prefix
		{"/etc/hosts.allow", false},
	}
	for _, c := range cases {
		if got := IsProtectedPath(c.path); got != c.want {
			t.Errorf("IsProtectedPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestIntersectsProtected_DirectAndParent(t *testing.T) {
	cases := []struct {
		roots []string
		want  string
	}{
		// Direct hit on a protected dir.
		{[]string{"/var/lib/mysql/"}, "/var/lib/mysql/"},
		// Parent that *contains* protected children (should reject too).
		{[]string{"/etc/"}, "/etc/passwd"}, // first protected child under /etc/
		// Multiple roots, second one hits.
		{[]string{"/var/www/", "/etc/shadow"}, "/etc/shadow"},
		// No intersection.
		{[]string{"/var/www/", "/srv/data/"}, ""},
		// Empty input.
		{nil, ""},
		{[]string{""}, ""},
	}
	for i, c := range cases {
		got := IntersectsProtected(c.roots)
		if got != c.want {
			t.Errorf("case %d: IntersectsProtected(%v) = %q, want %q",
				i, c.roots, got, c.want)
		}
	}
}

func TestIntersectsProtected_RejectsBroadGrant(t *testing.T) {
	// A profile claiming write access to /etc/ should be rejected
	// because /etc/ contains many protected files. This is the v2
	// "protect-our-own" backstop in action.
	if got := IntersectsProtected([]string{"/etc/"}); got == "" {
		t.Error("a profile granting write to /etc/ should be rejected")
	}
	// Same for /var/lib/.
	if got := IntersectsProtected([]string{"/var/lib/"}); got == "" {
		t.Error("a profile granting write to /var/lib/ should be rejected")
	}
}

func TestProtectedList_NotEmpty(t *testing.T) {
	// Cheap sanity check that ProtectedSystemPaths is non-empty.
	// Without this, the entire backstop is silently disabled.
	if len(ProtectedSystemPaths) < 20 {
		t.Errorf("ProtectedSystemPaths suspiciously short: %d entries", len(ProtectedSystemPaths))
	}
	// And that the specific entries motivating this change are present.
	mustHave := []string{
		"/etc/passwd", "/etc/shadow", "/etc/sudoers",
		"/etc/psa/", "/var/lib/mysql/", "/boot/",
		"/etc/cron.d/", "/etc/systemd/network/",
	}
	for _, p := range mustHave {
		found := false
		for _, x := range ProtectedSystemPaths {
			if x == p {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ProtectedSystemPaths missing required entry %q", p)
		}
	}
}
