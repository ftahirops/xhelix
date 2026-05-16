package verdict

import "testing"

func TestMatchHost(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "sub.example.com", false},
		{"*.example.com", "sub.example.com", true},
		{"*.example.com", "deep.sub.example.com", true},
		{"*.example.com", "example.com", true}, // apex match
		{"*.example.com", "notexample.com", false},
		{"*.google-analytics.com", "www.google-analytics.com", true},
		{"", "anything", false},
		{"x.com", "", false},
	}
	for _, c := range cases {
		got := MatchHost(c.pattern, c.host)
		if got != c.want {
			t.Errorf("MatchHost(%q,%q) = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}

// fakeLayer terminates at a configurable point in the chain.
type fakeLayer struct {
	name    string
	stop    bool
	action  Action
	conf    Confidence
	note    string
}

func (f fakeLayer) Name() string { return f.name }
func (f fakeLayer) Eval(_ Conn) (bool, Action, Confidence, []Reason) {
	r := []Reason{{Layer: f.name, Note: f.note}}
	if f.stop {
		return true, f.action, f.conf, r
	}
	return false, "", 0, r
}

func TestDecideStopsAtFirstTerminator(t *testing.T) {
	e := New(
		fakeLayer{name: "first", stop: false, note: "ran first"},
		fakeLayer{name: "second", stop: true, action: ActionDeny, conf: 90, note: "denied"},
		fakeLayer{name: "third", stop: true, action: ActionAllow, conf: 5, note: "should not run"},
	)
	v := e.Decide(Conn{})
	if v.Action != ActionDeny {
		t.Errorf("action = %v, want deny", v.Action)
	}
	if v.Layer != "second" {
		t.Errorf("layer = %v, want second", v.Layer)
	}
	if len(v.Reasons) != 2 {
		t.Errorf("reasons = %d, want 2 (first + second)", len(v.Reasons))
	}
}

func TestDecideDefaultAllowWhenNoTerminator(t *testing.T) {
	e := New(fakeLayer{name: "only", stop: false, note: "observed"})
	v := e.Decide(Conn{})
	if v.Action != ActionAllow {
		t.Errorf("default = %v, want allow", v.Action)
	}
	if v.Layer != "default" {
		t.Errorf("layer = %v", v.Layer)
	}
}

func TestSkipLayersDropsWork(t *testing.T) {
	e := New(
		fakeLayer{name: "deny-layer", stop: true, action: ActionDeny, conf: 90},
	)
	e.SkipLayers = func() map[string]struct{} {
		return map[string]struct{}{"deny-layer": {}}
	}
	v := e.Decide(Conn{})
	if v.Action != ActionAllow {
		t.Errorf("expected fallthrough allow when layer skipped, got %v", v.Action)
	}
}
