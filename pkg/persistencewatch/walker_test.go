package persistencewatch

import (
	"os"
	"path/filepath"
	"testing"
)

// buildFakeRoot lays out a minimal persistence-paths tree under
// tmpdir and returns the root.
func buildFakeRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	mkfile := func(p, content string) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	mkfile("etc/crontab", "* * * * * root /usr/bin/true\n")
	mkfile("etc/cron.d/zzz-malware", "* * * * * root /tmp/x\n")
	mkfile("etc/systemd/system/backdoor.service", "[Unit]\n[Service]\nExecStart=/tmp/payload\n")
	mkfile("etc/systemd/system/persist.timer", "[Timer]\nOnBootSec=5min\n")
	mkfile("etc/profile", "export PATH=/usr/bin\n")
	mkfile("etc/profile.d/custom.sh", "echo loaded\n")
	mkfile("etc/rc.local", "#!/bin/sh\nexit 0\n")
	mkfile("etc/modules", "vboxdrv\n")
	mkfile("etc/ld.so.preload", "/lib/x86_64-linux-gnu/libfakeroot.so\n")
	mkfile("etc/pam.d/sshd", "auth required pam_unix.so\n")
	mkfile("etc/xdg/autostart/foo.desktop", "[Desktop Entry]\nExec=/bin/foo\n")
	mkfile("home/alice/.bashrc", "alias ll=ls\n")
	mkfile("home/alice/.config/autostart/spy.desktop", "[Desktop Entry]\nExec=/tmp/spy\n")
	mkfile("home/alice/.ssh/authorized_keys", "ssh-rsa AAAA...\n")
	mkfile("root/.bashrc", "export PS1=#\n")

	return root
}

func TestWalkPopulatesEntries(t *testing.T) {
	root := buildFakeRoot(t)
	SetWalkerRoot(root)
	defer SetWalkerRoot("")

	snap, err := Walk(WalkConfig{Root: root, IncludeUserHomes: true})
	if err != nil {
		t.Fatal(err)
	}
	// Bucket count by category for an at-a-glance sanity check.
	count := map[Category]int{}
	for _, e := range snap.Entries {
		count[e.Category]++
	}
	for _, want := range []Category{
		CategoryCron, CategorySystemdUnit, CategorySystemdTimer,
		CategoryShellInit, CategoryRcInit, CategoryKernelModule,
		CategoryLdPreload, CategoryXDGAutostart, CategoryPAM,
		CategorySSHAuthKeys,
	} {
		if count[want] == 0 {
			t.Errorf("no entries for %s\nall: %+v", want, count)
		}
	}
}

func TestWalkHashesSmallFiles(t *testing.T) {
	root := buildFakeRoot(t)
	SetWalkerRoot(root)
	defer SetWalkerRoot("")

	snap, _ := Walk(WalkConfig{Root: root, IncludeUserHomes: true})
	hashed := 0
	for _, e := range snap.Entries {
		if e.SHA256 != "" {
			hashed++
		}
	}
	if hashed == 0 {
		t.Fatal("no entries hashed")
	}
}

func TestWalkSkipsOversizedFiles(t *testing.T) {
	root := buildFakeRoot(t)
	// Replace one file with a "large" body and set MaxFileSize tiny.
	big := filepath.Join(root, "etc/crontab")
	_ = os.WriteFile(big, make([]byte, 10_000), 0o644)
	SetWalkerRoot(root)
	defer SetWalkerRoot("")

	snap, _ := Walk(WalkConfig{Root: root, MaxFileSize: 100})
	for _, e := range snap.Entries {
		if stripWalkerRoot(e.Path) == "/etc/crontab" && e.SHA256 != "" {
			t.Fatal("oversized file should not be hashed")
		}
	}
}

func TestCompareAfterWalkDetectsChange(t *testing.T) {
	root := buildFakeRoot(t)
	SetWalkerRoot(root)
	defer SetWalkerRoot("")

	base, _ := Walk(WalkConfig{Root: root, IncludeUserHomes: true})
	// Modify one file
	_ = os.WriteFile(filepath.Join(root, "etc/ld.so.preload"),
		[]byte("/tmp/evil.so\n"), 0o644)
	cur, _ := Walk(WalkConfig{Root: root, IncludeUserHomes: true})

	diff := Compare(base, cur)
	if len(diff.Modified) != 1 {
		t.Fatalf("modified count = %d, want 1\ndiff=%+v", len(diff.Modified), diff)
	}
}

func TestExtractOwnerFromPath(t *testing.T) {
	cases := []struct {
		p    string
		want string
	}{
		{"/home/alice/.bashrc", "alice"},
		{"/home/bob/.config/autostart/x.desktop", "bob"},
		{"/root/.bashrc", "root"},
		{"/etc/crontab", ""},
	}
	for _, c := range cases {
		if got := extractOwnerFromPath(c.p); got != c.want {
			t.Errorf("extractOwnerFromPath(%q) = %q, want %q", c.p, got, c.want)
		}
	}
}

func TestStripWalkerRoot(t *testing.T) {
	SetWalkerRoot("/tmp/root-1234")
	defer SetWalkerRoot("")
	if got := stripWalkerRoot("/tmp/root-1234/etc/crontab"); got != "/etc/crontab" {
		t.Errorf("got %q", got)
	}
	if got := stripWalkerRoot("/etc/crontab"); got != "/etc/crontab" {
		t.Errorf("non-prefix path mutated: %q", got)
	}
}
