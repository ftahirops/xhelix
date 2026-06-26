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
	cases := []struct {
		name  string
		keys  []string
		want  []string
	}{
		{
			name: "bare host and IPv4 with port",
			keys: []string{"hostonly", "1.2.3.4:443"},
			want: []string{"1.2.3.4", "hostonly"},
		},
		{
			name: "bare IPv6 stays whole (multi-colon, unbracketed)",
			keys: []string{"2001:db8::1"},
			want: []string{"2001:db8::1"},
		},
		{
			name: "bracketed IPv6 with port strips correctly",
			keys: []string{"[2001:db8::1]:443"},
			want: []string{"2001:db8::1"},
		},
		{
			name: "mixed: IPv4 port + bare IPv6 + bracketed IPv6 port",
			keys: []string{"1.2.3.4:80", "2001:db8::1", "[2001:db8::2]:8080"},
			want: []string{"1.2.3.4", "2001:db8::1", "2001:db8::2"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := Observed{EgressKeys: tc.keys}
			got := EgressHosts(o)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("EgressHosts(%v) = %v, want %v", tc.keys, got, tc.want)
			}
		})
	}
}
