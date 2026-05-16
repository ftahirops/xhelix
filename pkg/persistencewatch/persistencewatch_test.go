package persistencewatch

import "testing"

func TestCategoryForPath(t *testing.T) {
	cases := []struct {
		path string
		want Category
	}{
		{"/etc/crontab", CategoryCron},
		{"/etc/cron.d/zzz-malware", CategoryCron},
		{"/etc/cron.daily/cleanup", CategoryCron},
		{"/var/spool/cron/crontabs/alice", CategoryCron},
		{"/var/spool/at/a0001", CategoryAtJob},
		{"/etc/systemd/system/backdoor.service", CategorySystemdUnit},
		{"/usr/lib/systemd/system/nginx.service", CategorySystemdUnit},
		{"/lib/systemd/system/ssh.service", CategorySystemdUnit},
		{"/etc/systemd/system/persist.timer", CategorySystemdTimer},
		{"/etc/profile", CategoryShellInit},
		{"/etc/bash.bashrc", CategoryShellInit},
		{"/etc/profile.d/custom.sh", CategoryShellInit},
		{"/etc/rc.local", CategoryRcInit},
		{"/etc/init.d/legacy", CategoryRcInit},
		{"/etc/modules", CategoryKernelModule},
		{"/etc/modules-load.d/nf.conf", CategoryKernelModule},
		{"/etc/ld.so.preload", CategoryLdPreload},
		{"/etc/ld.so.conf.d/extra.conf", CategoryLdPreload},
		{"/etc/xdg/autostart/spy.desktop", CategoryXDGAutostart},
		{"/etc/pam.d/sshd", CategoryPAM},
		{"/lib/security/pam_unix.so", CategoryPAM},
		{"/usr/lib/security/pam_evil.so", CategoryPAM},
		{"/home/alice/.bashrc", CategoryShellInit},
		{"/home/alice/.bash_profile", CategoryShellInit},
		{"/home/alice/.profile", CategoryShellInit},
		{"/root/.bashrc", CategoryShellInit},
		{"/home/alice/.zshrc", CategoryShellInit},
		{"/home/alice/.config/autostart/spy.desktop", CategoryXDGAutostart},
		{"/root/.config/autostart/x.desktop", CategoryXDGAutostart},
		{"/home/alice/.ssh/authorized_keys", CategorySSHAuthKeys},
		{"/root/.ssh/authorized_keys2", CategorySSHAuthKeys},
		{"/home/alice/.config/systemd/user/persist.service", CategorySystemdUnit},
		{"/some/random/path", CategoryUnknown},
		{"", CategoryUnknown},
	}
	for _, c := range cases {
		got := CategoryForPath(c.path)
		if got != c.want {
			t.Errorf("CategoryForPath(%q) = %s, want %s", c.path, got, c.want)
		}
	}
}

func TestSeverity(t *testing.T) {
	tests := []struct {
		c    Category
		want string
	}{
		{CategoryLdPreload, "critical"},
		{CategoryPAM, "critical"},
		{CategorySSHAuthKeys, "critical"},
		{CategorySystemdUnit, "high"},
		{CategorySystemdTimer, "high"},
		{CategoryKernelModule, "high"},
		{CategoryCron, "medium"},
		{CategoryShellInit, "low"},
		{CategoryUnknown, "info"},
	}
	for _, tt := range tests {
		if got := tt.c.Severity(); got != tt.want {
			t.Errorf("%s severity = %s, want %s", tt.c, got, tt.want)
		}
	}
}

func TestCompareEmptyBaselineAllAdded(t *testing.T) {
	base := Snapshot{}
	cur := Snapshot{Entries: []Entry{
		{Category: CategoryCron, Path: "/etc/crontab", SHA256: "abc"},
		{Category: CategoryShellInit, Path: "/etc/profile", SHA256: "def"},
	}}
	d := Compare(base, cur)
	if len(d.Added) != 2 {
		t.Fatalf("added = %d, want 2", len(d.Added))
	}
	if len(d.Removed) != 0 || len(d.Modified) != 0 {
		t.Fatalf("non-added diffs leaked: %+v", d)
	}
	// Sorted
	if d.Added[0].Path != "/etc/crontab" || d.Added[1].Path != "/etc/profile" {
		t.Fatalf("added not sorted: %+v", d.Added)
	}
}

func TestCompareDetectsRemoval(t *testing.T) {
	base := Snapshot{Entries: []Entry{
		{Category: CategoryCron, Path: "/etc/crontab", SHA256: "x"},
	}}
	cur := Snapshot{}
	d := Compare(base, cur)
	if len(d.Removed) != 1 || d.Removed[0].Path != "/etc/crontab" {
		t.Fatalf("removed = %+v", d.Removed)
	}
}

func TestCompareDetectsModification(t *testing.T) {
	base := Snapshot{Entries: []Entry{
		{Category: CategoryLdPreload, Path: "/etc/ld.so.preload", SHA256: "old", Size: 10, Mode: 0o644},
	}}
	cur := Snapshot{Entries: []Entry{
		{Category: CategoryLdPreload, Path: "/etc/ld.so.preload", SHA256: "new", Size: 20, Mode: 0o644},
	}}
	d := Compare(base, cur)
	if len(d.Modified) != 1 {
		t.Fatalf("modified = %d, want 1", len(d.Modified))
	}
	if d.Modified[0].Old.SHA256 != "old" || d.Modified[0].New.SHA256 != "new" {
		t.Fatalf("modified entry wrong: %+v", d.Modified[0])
	}
	if len(d.Added) != 0 || len(d.Removed) != 0 {
		t.Fatalf("unexpected adds/removes: %+v", d)
	}
}

func TestCompareNoChangeReturnsEmpty(t *testing.T) {
	e := Entry{Category: CategoryCron, Path: "/etc/crontab", SHA256: "stable"}
	base := Snapshot{Entries: []Entry{e}}
	cur := Snapshot{Entries: []Entry{e}}
	if d := Compare(base, cur); !d.IsEmpty() {
		t.Fatalf("expected empty diff; got %+v", d)
	}
}

func TestCompareFallbackOnSizeMode(t *testing.T) {
	// Both sides have empty SHA256 — falls back to size+mode.
	base := Snapshot{Entries: []Entry{
		{Category: CategoryCron, Path: "/etc/crontab", Size: 100, Mode: 0o644},
	}}
	cur := Snapshot{Entries: []Entry{
		{Category: CategoryCron, Path: "/etc/crontab", Size: 200, Mode: 0o644},
	}}
	d := Compare(base, cur)
	if len(d.Modified) != 1 {
		t.Fatalf("modified = %d, want 1 (size delta)", len(d.Modified))
	}
}

func TestCountBySeverity(t *testing.T) {
	d := Diff{
		Added: []Entry{
			{Category: CategoryLdPreload, Path: "/etc/ld.so.preload"},
			{Category: CategoryCron, Path: "/etc/crontab"},
		},
		Modified: []ModifiedEntry{
			{New: Entry{Category: CategoryPAM, Path: "/etc/pam.d/sshd"}},
		},
	}
	c := d.CountBySeverity()
	if c["critical"] != 2 {
		t.Errorf("critical = %d, want 2", c["critical"])
	}
	if c["medium"] != 1 {
		t.Errorf("medium = %d, want 1", c["medium"])
	}
}

func TestSortedDiffOutput(t *testing.T) {
	base := Snapshot{}
	cur := Snapshot{Entries: []Entry{
		{Path: "/c"}, {Path: "/a"}, {Path: "/b"},
	}}
	d := Compare(base, cur)
	if d.Added[0].Path != "/a" || d.Added[1].Path != "/b" || d.Added[2].Path != "/c" {
		t.Fatalf("not sorted: %+v", d.Added)
	}
}
