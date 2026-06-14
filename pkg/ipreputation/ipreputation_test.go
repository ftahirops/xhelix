package ipreputation

import (
	"net"
	"net/http"
	"testing"
)

// countingDoer records whether Do was ever called.
type countingDoer struct{ calls int }

func (d *countingDoer) Do(*http.Request) (*http.Response, error) {
	d.calls++
	return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
}

// THE SAFETY CONTRACT: disabled checker makes zero network calls.
func TestDisabled_MakesNoCall(t *testing.T) {
	d := &countingDoer{}
	c := New(false, "virustotal", "key", d)
	v, ok := c.Check(net.ParseIP("8.8.8.8"))
	if ok || v.Listed {
		t.Fatalf("disabled checker returned a verdict: %+v ok=%v", v, ok)
	}
	if d.calls != 0 {
		t.Fatalf("disabled checker made %d external calls, want 0", d.calls)
	}
	if c.Calls() != 0 {
		t.Fatalf("Calls()=%d, want 0", c.Calls())
	}
}

// When enabled, it issues exactly one request via the injected Doer.
func TestEnabled_CallsProvider(t *testing.T) {
	d := &countingDoer{}
	c := New(true, "abuseipdb", "key", d)
	v, ok := c.Check(net.ParseIP("1.2.3.4"))
	if !ok || !v.Listed || v.Source != "abuseipdb" {
		t.Fatalf("enabled checker verdict wrong: %+v ok=%v", v, ok)
	}
	if d.calls != 1 || c.Calls() != 1 {
		t.Fatalf("calls doer=%d Calls()=%d, want 1/1", d.calls, c.Calls())
	}
}

func TestNilIP_NoCall(t *testing.T) {
	d := &countingDoer{}
	c := New(true, "virustotal", "key", d)
	if _, ok := c.Check(nil); ok || d.calls != 0 {
		t.Fatalf("nil IP should make no call: ok=%v calls=%d", ok, d.calls)
	}
}
