package threatintel

import (
	"net"
	"sort"
	"strings"
	"testing"
)

func TestParseDROPFormat(t *testing.T) {
	body := `; Spamhaus DROP List 2026-05-03
203.0.113.0/24 ; SBL12345
198.51.100.5/32 ; SBL67890
# comment
2001:db8::/32 ; SBL00001

`
	v4, v6, err := parseList(strings.NewReader(body), "spamhaus_drop")
	if err != nil {
		t.Fatal(err)
	}
	if len(v4) != 2 {
		t.Errorf("v4 = %d", len(v4))
	}
	if len(v6) != 1 {
		t.Errorf("v6 = %d", len(v6))
	}
}

func TestParseTorBulk(t *testing.T) {
	body := `185.220.101.1
185.220.101.2
1.2.3.4
`
	v4, _, err := parseList(strings.NewReader(body), "tor_exits")
	if err != nil {
		t.Fatal(err)
	}
	if len(v4) != 3 {
		t.Errorf("v4 = %d", len(v4))
	}
}

func TestLookup(t *testing.T) {
	body := `203.0.113.0/24
198.51.100.5
2001:db8::/32
`
	v4, v6, _ := parseList(strings.NewReader(body), "test")
	sort.Slice(v4, func(i, j int) bool { return v4[i].low < v4[j].low })
	sort.Slice(v6, func(i, j int) bool { return cmp16(v6[i].low, v6[j].low) < 0 })
	s := &Set{v4: v4, v6: v6, bySrc: map[string]int{}}

	cases := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.5", true},
		{"203.0.113.255", true},
		{"203.0.114.0", false},
		{"198.51.100.5", true},
		{"198.51.100.6", false},
		{"2001:db8::1", true},
		{"2001:db9::1", false},
		{"127.0.0.1", false},
	}
	for _, c := range cases {
		got := s.Lookup(net.ParseIP(c.ip)).Source != ""
		if got != c.want {
			t.Errorf("Lookup(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestParseSkipsComments(t *testing.T) {
	body := `# comment
; another
203.0.113.0/24
`
	v4, _, _ := parseList(strings.NewReader(body), "x")
	if len(v4) != 1 {
		t.Errorf("expected 1 entry past comments, got %d", len(v4))
	}
}
