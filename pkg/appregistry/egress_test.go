package appregistry

import "testing"

func TestServiceEgressFieldsDefaultOff(t *testing.T) {
	var s Service // zero value
	if s.EgressDefaultDeny {
		t.Error("EgressDefaultDeny must default to false (opt-in)")
	}
	if s.EgressAllowCIDRs != nil {
		t.Error("EgressAllowCIDRs must default to nil")
	}
	s.EgressDefaultDeny = true
	s.EgressAllowCIDRs = []string{"10.0.0.0/8"}
	if !s.EgressDefaultDeny || len(s.EgressAllowCIDRs) != 1 {
		t.Errorf("fields not settable: %+v", s)
	}
}

func TestServiceEgressFQDNsSettable(t *testing.T) {
	var s Service
	if s.EgressAllowFQDNs != nil {
		t.Error("EgressAllowFQDNs must default to nil")
	}
	s.EgressAllowFQDNs = []string{"api.stripe.com"}
	if len(s.EgressAllowFQDNs) != 1 || s.EgressAllowFQDNs[0] != "api.stripe.com" {
		t.Errorf("not settable: %+v", s)
	}
}
