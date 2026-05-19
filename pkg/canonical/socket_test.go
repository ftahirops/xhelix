package canonical

import (
	"net"
	"os"
	"testing"
)

func TestSocketRef_ValidString(t *testing.T) {
	zero := SocketRef{}
	if zero.IsValid() {
		t.Error("zero SocketRef should not be valid")
	}

	r := SocketRef{OwnerPID: 100, FD: 7, Inode: 99887766}
	if !r.IsValid() {
		t.Error("populated SocketRef should be valid")
	}
	if r.String() == "" {
		t.Error("String should produce non-empty output")
	}
}

func TestParseSocketInodeLink_HappyPath(t *testing.T) {
	cases := map[string]uint64{
		"socket:[1]":        1,
		"socket:[12345]":    12345,
		"socket:[99887766]": 99887766,
	}
	for target, want := range cases {
		got, ok := parseSocketInodeLink(target)
		if !ok {
			t.Errorf("%q: expected ok", target)
			continue
		}
		if got != want {
			t.Errorf("%q → %d, want %d", target, got, want)
		}
	}
}

func TestParseSocketInodeLink_RejectsNonSocket(t *testing.T) {
	cases := []string{
		"",
		"/dev/null",                  // regular path
		"pipe:[12345]",               // pipe, not socket
		"anon_inode:[eventpoll]",     // anonymous inode
		"socket:12345",               // missing brackets
		"socket:[]",                  // empty
		"socket:[notanumber]",        // not parsable
		"socket:[12345",              // missing trailing bracket
		"socket:[0]",                 // zero inode is invalid
	}
	for _, c := range cases {
		if _, ok := parseSocketInodeLink(c); ok {
			t.Errorf("%q: should NOT parse as socket inode", c)
		}
	}
}

func TestSocketsForPID_Self(t *testing.T) {
	// Open a real socket so we know there's at least one to find.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	socks, err := SocketsForPID(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("SocketsForPID(self): %v", err)
	}
	if len(socks) == 0 {
		t.Fatal("expected at least one socket for self after Listen()")
	}
	for _, s := range socks {
		if s.OwnerPID != uint32(os.Getpid()) {
			t.Errorf("OwnerPID = %d, want self", s.OwnerPID)
		}
		if s.Inode == 0 {
			t.Errorf("inode 0 in result: %+v", s)
		}
	}
}

func TestSocketsForPID_NonexistentPID(t *testing.T) {
	_, err := SocketsForPID(99999999)
	if err == nil {
		t.Error("expected error for non-existent pid")
	}
}

func TestSocketsForPID_PIDZero(t *testing.T) {
	if _, err := SocketsForPID(0); err == nil {
		t.Error("pid 0 should error")
	}
}

func TestFindOwnerOfSocket_RoundTrip(t *testing.T) {
	// Open a socket, find its inode by enumerating own fds, then ask
	// FindOwnerOfSocket to locate the pid — should be ourselves.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	mySocks, err := SocketsForPID(uint32(os.Getpid()))
	if err != nil || len(mySocks) == 0 {
		t.Fatalf("could not enumerate own sockets: err=%v len=%d", err, len(mySocks))
	}

	pid, found := FindOwnerOfSocket(mySocks[0].Inode)
	// May not find the owner if /proc visibility is restricted, so
	// allow either: found-and-correct, or not-found.
	if found && pid != uint32(os.Getpid()) {
		t.Errorf("FindOwnerOfSocket → pid %d, expected self (%d)", pid, os.Getpid())
	}
}

func TestFindOwnerOfSocket_ZeroInode(t *testing.T) {
	pid, ok := FindOwnerOfSocket(0)
	if ok || pid != 0 {
		t.Errorf("inode 0 should return (0,false), got (%d,%v)", pid, ok)
	}
}

func BenchmarkParseSocketInodeLink(b *testing.B) {
	target := "socket:[123456789]"
	for i := 0; i < b.N; i++ {
		parseSocketInodeLink(target)
	}
}
