package lockout

import (
	"strings"
	"testing"
)

func TestRefusesEmpty(t *testing.T) {
	r := Lockout("")
	if len(r.Errors) == 0 || !strings.Contains(r.Errors[0], "empty") {
		t.Errorf("expected empty-username error, got %v", r.Errors)
	}
}

func TestRefusesRoot(t *testing.T) {
	r := Lockout("root")
	if len(r.Errors) == 0 || !strings.Contains(strings.Join(r.Errors, ";"), "root") {
		t.Errorf("expected root-refusal, got %v", r.Errors)
	}
	if r.PasswordLocked || r.AccountExpired {
		t.Errorf("root must not be touched: %+v", r)
	}
}

func TestRefusesMissingUser(t *testing.T) {
	r := Lockout("xhelix-nonexistent-user-9c7a")
	if len(r.Errors) == 0 {
		t.Errorf("expected lookup error")
	}
	if r.PasswordLocked {
		t.Errorf("must not have locked anything: %+v", r)
	}
}

func TestValidTTYName(t *testing.T) {
	good := []string{"tty1", "tty7", "ttyS0", "pts/0", "pts/123", "console"}
	for _, s := range good {
		if !validTTYName(s) {
			t.Errorf("validTTYName(%q) = false, want true", s)
		}
	}
	// All of these would have been a flag injection vector if they
	// were ever passed to pkill -t. Reject all.
	bad := []string{
		"-a", "--signal", "../etc/passwd", "tty1; rm -rf /",
		"pts/0`id`", "tty 1", "", "pts/", "tty/", "pts/x", "pts/-1",
	}
	for _, s := range bad {
		if validTTYName(s) {
			t.Errorf("validTTYName(%q) = true, want false (would be injection)", s)
		}
	}
}

func TestCountLines(t *testing.T) {
	for in, want := range map[string]int{
		"":     0,
		"a":    1,
		"a\n":  1,
		"a\nb": 2,
	} {
		if got := countLines(in); got != want {
			t.Errorf("countLines(%q) = %d want %d", in, got, want)
		}
	}
}
