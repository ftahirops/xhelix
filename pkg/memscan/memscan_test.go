package memscan

import (
	"bytes"
	"os"
	"regexp"
	"runtime"
	"testing"
)

// canary is placed in the binary's data segment so the scanner can
// find it via /proc/self/mem.
var canary = []byte("XHELIX_MEMSCAN_CANARY_TOKEN_2c0fa1bd")

func TestScanSelfFindsCanary(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("memscan requires root / CAP_SYS_PTRACE for /proc/self/mem")
	}
	// Touch the canary so the compiler can't elide the global.
	runtime.KeepAlive(canary)

	patterns := []Pattern{
		{
			Name:     "test_canary",
			Severity: "info",
			Bytes:    bytes.Clone(canary),
		},
	}
	hits, err := Scan(os.Getpid(), patterns, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) == 0 {
		t.Fatal("canary not found in own memory")
	}
	if hits[0].PatternName != "test_canary" {
		t.Errorf("name = %q", hits[0].PatternName)
	}
	if hits[0].Address == 0 {
		t.Error("address = 0")
	}
}

func TestRegexPattern(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	patterns := []Pattern{
		{
			Name:     "regex_canary",
			Severity: "info",
			Regex:    regexp.MustCompile(`MEMSCAN_CANARY_TOKEN_[0-9a-f]{8}`),
		},
	}
	hits, err := Scan(os.Getpid(), patterns, Options{})
	if err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(canary)
	if len(hits) == 0 {
		t.Fatal("regex did not match")
	}
}

func TestInvalidPattern(t *testing.T) {
	_, err := Scan(os.Getpid(), []Pattern{{Name: "empty"}}, Options{})
	if err == nil {
		t.Fatal("expected error on pattern with no Bytes/Regex")
	}
}

func TestIndexBytes(t *testing.T) {
	cases := []struct {
		hay, ndl string
		want     int
	}{
		{"", "x", -1},
		{"abc", "", -1},
		{"abcdef", "cd", 2},
		{"aaaa", "aa", 0},
		{"abcdef", "fg", -1},
		// Regression: a 2-byte needle whose middle bytes "matter" —
		// the prior hand-rolled implementation had a off-by-one and
		// would produce false positives (any byte after a matching
		// first byte was treated as a match).
		{"\xeb\xff\xeb\x09", "\xeb\x09", 2}, // first byte of needle appears at 0 + 2; only 2 is a real match
		{"\xeb\xaa", "\xeb\x09", -1},        // looks like a match if we don't check needle[1]
	}
	for _, c := range cases {
		if got := indexBytes([]byte(c.hay), []byte(c.ndl)); got != c.want {
			t.Errorf("indexBytes(%q,%q) = %d want %d", c.hay, c.ndl, got, c.want)
		}
	}
}
