package xdpadmin

import (
	"net"
	"testing"
)

func TestAddRequiresAttachedMap(t *testing.T) {
	a := New("")
	err := a.Add(net.ParseIP("1.2.3.4"))
	if err == nil {
		t.Error("expected error when no map attached")
	}
}

func TestAddIPv6Rejected(t *testing.T) {
	a := New("")
	err := a.Add(net.ParseIP("2001:db8::1"))
	if err == nil {
		t.Error("expected error on IPv6")
	}
}

func TestAddCIDRRejectsWideRange(t *testing.T) {
	a := New("")
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	if err := a.AddCIDR(cidr); err == nil {
		t.Error("expected refusal for /8 (too wide)")
	}
}
