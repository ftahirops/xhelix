package trustzone

import (
	"net"
	"testing"
)

func TestDecide_TrustedAlwaysAllow(t *testing.T) {
	m := New("/nonexistent", LabelTrusted)
	in := DecisionInput{
		Subject:   Subject{UID: 0},
		DestIP:    net.ParseIP("8.8.8.8"),
		DestPort:  443,
		DestClass: "unknown",
	}
	a, lbl, _ := m.Decide(in)
	if a != ZoneAllow || lbl != LabelTrusted {
		t.Fatalf("trusted: got (%s,%s) want (allow,trusted)", a, lbl)
	}
}

func TestDecide_RestrictedAllowedClasses(t *testing.T) {
	m := New("/nonexistent", LabelTrusted)
	m.assignments = []Assignment{{UID: u32p(1000), Label: LabelRestricted}}
	classes := []string{"cloudflare", "google", "aws", "azure", "akamai", "fastly", "cdn", "private", "os_update", "dev_registry"}
	for _, c := range classes {
		a, _, _ := m.Decide(DecisionInput{
			Subject: Subject{UID: 1000}, DestIP: net.ParseIP("8.8.8.8"), DestPort: 443, DestClass: c,
		})
		if a != ZoneAllow {
			t.Errorf("restricted×%s: got %s want allow", c, a)
		}
	}
}

func TestDecide_RestrictedUnknownClassVerifies(t *testing.T) {
	m := New("/nonexistent", LabelTrusted)
	m.assignments = []Assignment{{UID: u32p(1000), Label: LabelRestricted}}
	a, _, _ := m.Decide(DecisionInput{
		Subject: Subject{UID: 1000}, DestIP: net.ParseIP("5.5.5.5"), DestPort: 443, DestClass: "unknown",
	})
	if a != ZoneVerify {
		t.Fatalf("restricted×unknown: got %s want verify", a)
	}
}

func TestDecide_RestrictedPrivateAllows(t *testing.T) {
	m := New("/nonexistent", LabelTrusted)
	m.assignments = []Assignment{{UID: u32p(1000), Label: LabelRestricted}}
	a, _, _ := m.Decide(DecisionInput{
		Subject: Subject{UID: 1000}, DestIP: net.ParseIP("10.0.0.5"), DestPort: 22, DestClass: "",
	})
	if a != ZoneAllow {
		t.Fatalf("restricted×private: got %s want allow", a)
	}
}

func TestDecide_UntrustedExternalDenies(t *testing.T) {
	m := New("/nonexistent", LabelTrusted)
	m.assignments = []Assignment{{UID: u32p(1001), Label: LabelUntrusted}}
	a, _, _ := m.Decide(DecisionInput{
		Subject: Subject{UID: 1001}, DestIP: net.ParseIP("8.8.8.8"), DestPort: 443, DestClass: "unknown",
	})
	if a != ZoneDeny {
		t.Fatalf("untrusted×external: got %s want deny", a)
	}
}

func TestDecide_UntrustedPrivateAllows(t *testing.T) {
	m := New("/nonexistent", LabelTrusted)
	m.assignments = []Assignment{{UID: u32p(1001), Label: LabelUntrusted}}
	a, _, _ := m.Decide(DecisionInput{
		Subject: Subject{UID: 1001}, DestIP: net.ParseIP("192.168.1.5"), DestPort: 22, DestClass: "",
	})
	if a != ZoneAllow {
		t.Fatalf("untrusted×private: got %s want allow", a)
	}
}

func TestDecide_TorOnlyLoopbackAllows(t *testing.T) {
	m := New("/nonexistent", LabelTrusted)
	m.assignments = []Assignment{{Comm: "tor-browser", Label: LabelTorOnly}}
	for _, port := range []uint16{9050, 9051, 9150, 9151} {
		a, _, _ := m.Decide(DecisionInput{
			Subject: Subject{Comm: "tor-browser"}, DestIP: net.ParseIP("127.0.0.1"), DestPort: port,
		})
		if a != ZoneAllow {
			t.Errorf("tor_only×127.0.0.1:%d: got %s want allow", port, a)
		}
	}
}

func TestDecide_TorOnlyExternalRequires(t *testing.T) {
	m := New("/nonexistent", LabelTrusted)
	m.assignments = []Assignment{{Comm: "tor-browser", Label: LabelTorOnly}}
	a, _, _ := m.Decide(DecisionInput{
		Subject: Subject{Comm: "tor-browser"}, DestIP: net.ParseIP("8.8.8.8"), DestPort: 53,
	})
	if a != ZoneTorRequire {
		t.Fatalf("tor_only×external: got %s want tor_require", a)
	}
}

func TestDecide_NilManager(t *testing.T) {
	var m *Manager
	a, _, _ := m.Decide(DecisionInput{DestIP: net.ParseIP("8.8.8.8"), DestPort: 443})
	if a != ZoneAllow {
		t.Fatalf("nil mgr decide: %s want allow", a)
	}
}

func TestZoneAction_String(t *testing.T) {
	cases := map[ZoneAction]string{
		ZoneAllow: "allow", ZoneObserve: "observe", ZoneVerify: "verify",
		ZoneDeny: "deny", ZoneTorRequire: "tor_require",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("%d: got %s want %s", k, got, want)
		}
	}
}
