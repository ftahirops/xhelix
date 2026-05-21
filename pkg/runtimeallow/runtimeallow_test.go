package runtimeallow

import "testing"

func TestDefault_JITEngines(t *testing.T) {
	s := New(Default())
	for _, img := range []string{
		"/usr/bin/node",
		"/root/.nvm/versions/node/v20.20.2/bin/node",
		"/usr/lib/jvm/java-21-openjdk-amd64/bin/java",
		"/usr/share/dotnet/dotnet",
		"/usr/bin/python3",
		"/usr/bin/python3.12",
		"/usr/bin/sudo",
		"/usr/bin/runc",
		"/usr/bin/snapd",
	} {
		if !s.Match(img) {
			t.Errorf("expected %q to be allowlisted", img)
		}
	}
}

func TestDefault_NotAllowlisted(t *testing.T) {
	s := New(Default())
	for _, img := range []string{
		"/tmp/attacker_payload",
		"/dev/shm/x",
		"/proc/self/fd/9",
		"/home/user/evil.bin",
	} {
		if s.Match(img) {
			t.Errorf("did NOT expect %q to be allowlisted", img)
		}
	}
}

func TestMatchAny_CommFallback(t *testing.T) {
	s := New(Default())
	if !s.MatchAny("", "sudo") {
		t.Error("expected comm=sudo to match")
	}
	if !s.MatchAny("", "node") {
		t.Error("expected comm=node to match")
	}
	if s.MatchAny("", "evil") {
		t.Error("did NOT expect comm=evil to match")
	}
}

func TestMatchAny_EmptyInputs(t *testing.T) {
	s := New(Default())
	if s.MatchAny("", "") {
		t.Error("empty inputs must not match")
	}
}

func TestLoadFile_Missing(t *testing.T) {
	s, err := LoadFile("/nonexistent/path/runtime-allowlist.yaml")
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	// Should still have defaults.
	if !s.Match("/usr/bin/node") {
		t.Error("missing file should fall back to Default()")
	}
}
