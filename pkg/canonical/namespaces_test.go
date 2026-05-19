package canonical

import (
	"os"
	"testing"
)

func TestNamespaceSet_ValidEqualShares(t *testing.T) {
	zero := NamespaceSet{}
	if zero.IsValid() {
		t.Error("zero NamespaceSet should not be valid")
	}

	a := NamespaceSet{PID: 100, Mount: 200, Net: 300, User: 400}
	b := NamespaceSet{PID: 100, Mount: 200, Net: 300, User: 400}
	c := NamespaceSet{PID: 100, Mount: 999, Net: 300, User: 400}

	if !a.IsValid() {
		t.Error("set with PID + Mount + Net should be valid")
	}
	if !a.Equal(b) {
		t.Error("identical NamespaceSets should be Equal")
	}
	if a.Equal(c) {
		t.Error("different mount NS ⇒ not Equal")
	}
	if !a.SharesPIDNS(b) {
		t.Error("same PID NS ⇒ SharesPIDNS true")
	}
	if !a.SharesPIDNS(c) {
		t.Error("different mount but same PID ⇒ still SharesPIDNS true")
	}
}

func TestNamespaceSet_SharesPIDNSZeroIsFalse(t *testing.T) {
	if (NamespaceSet{}).SharesPIDNS(NamespaceSet{}) {
		t.Error("two zero sets should NOT be SharesPIDNS (PID=0 is sentinel)")
	}
}

func TestParseNsLinkTarget_HappyPath(t *testing.T) {
	cases := map[string]uint64{
		"pid:[4026531836]":    4026531836,
		"mnt:[4026531840]":    4026531840,
		"net:[4026531969]":    4026531969,
		"user:[4026531837]":   4026531837,
		"cgroup:[4026531835]": 4026531835,
	}
	for target, want := range cases {
		got, err := parseNsLinkTarget(target)
		if err != nil {
			t.Errorf("%q: %v", target, err)
			continue
		}
		if got != want {
			t.Errorf("%q → %d, want %d", target, got, want)
		}
	}
}

func TestParseNsLinkTarget_Malformed(t *testing.T) {
	cases := []string{
		"",
		"no brackets here",
		"pid:[]",
		"pid:[notanumber]",
		"pid:4026531836", // no brackets
	}
	for _, c := range cases {
		if _, err := parseNsLinkTarget(c); err == nil {
			t.Errorf("%q: expected error", c)
		}
	}
}

func TestReadNamespaces_Self(t *testing.T) {
	set, err := ReadNamespaces(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("ReadNamespaces(self): %v", err)
	}
	// On any modern Linux, at least pid + mnt + net should be present.
	if set.PID == 0 {
		t.Error("self PID NS inode should be non-zero")
	}
	if set.Mount == 0 {
		t.Error("self Mount NS inode should be non-zero")
	}
	if set.Net == 0 {
		t.Error("self Net NS inode should be non-zero")
	}
	if !set.IsValid() {
		t.Errorf("self NamespaceSet should be valid: %+v", set)
	}
}

func TestReadNamespaces_NonexistentPID(t *testing.T) {
	_, err := ReadNamespaces(99999999)
	if err == nil {
		t.Error("expected error for non-existent pid")
	}
	if _, ok := err.(ProcKeyNotFound); !ok {
		t.Logf("got %T (acceptable if /proc layout differs): %v", err, err)
	}
}

func TestReadNamespaces_PIDZero(t *testing.T) {
	if _, err := ReadNamespaces(0); err == nil {
		t.Error("pid 0 should error")
	}
}

func TestReadNamespaces_SameWithinProcess(t *testing.T) {
	// Two calls for the same pid should return identical inodes.
	a, err := ReadNamespaces(uint32(os.Getpid()))
	if err != nil {
		t.Skip(err)
	}
	b, err := ReadNamespaces(uint32(os.Getpid()))
	if err != nil {
		t.Skip(err)
	}
	if !a.Equal(b) {
		t.Errorf("self NamespaceSet not stable across calls:\n  a=%+v\n  b=%+v", a, b)
	}
}
