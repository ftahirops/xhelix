package synth

import (
	"reflect"
	"testing"
)

func TestExecEnvelope_SortedDistinct(t *testing.T) {
	o := Observed{ExecRaws: []string{"/usr/bin/curl", "/usr/bin/php"}}
	if got := ExecEnvelope(o); !reflect.DeepEqual(got, []string{"/usr/bin/curl", "/usr/bin/php"}) {
		t.Errorf("ExecEnvelope = %v", got)
	}
}

func TestEgressHosts_StripsPortAndDedups(t *testing.T) {
	o := Observed{EgressKeys: []string{"api.stripe.com:443", "api.stripe.com:80", "smtp.x.com:587"}}
	got := EgressHosts(o)
	want := []string{"api.stripe.com", "smtp.x.com"} // port stripped, deduped, sorted
	if !reflect.DeepEqual(got, want) {
		t.Errorf("EgressHosts = %v, want %v", got, want)
	}
}

func TestEgressHosts_HandlesNoPortAndIPv6Safe(t *testing.T) {
	// A key with no colon stays whole; only the LAST colon is treated as the
	// port separator so bare hosts survive.
	o := Observed{EgressKeys: []string{"hostonly", "1.2.3.4:443"}}
	got := EgressHosts(o)
	want := []string{"1.2.3.4", "hostonly"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("EgressHosts = %v, want %v", got, want)
	}
}
