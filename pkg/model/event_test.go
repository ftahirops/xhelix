package model

import "testing"

func TestSeverityRoundTrip(t *testing.T) {
	cases := []struct {
		s   Severity
		str string
	}{
		{SeverityInfo, "info"},
		{SeverityNotice, "notice"},
		{SeverityWarn, "warn"},
		{SeverityHigh, "high"},
		{SeverityCritical, "critical"},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.str {
			t.Errorf("severity %d -> %q, want %q", c.s, got, c.str)
		}
		got, ok := ParseSeverity(c.str)
		if !ok || got != c.s {
			t.Errorf("ParseSeverity(%q) = %v,%v; want %v,true", c.str, got, ok, c.s)
		}
	}
	if _, ok := ParseSeverity("nonsense"); ok {
		t.Error("ParseSeverity should reject unknown values")
	}
}

func TestNewEvent(t *testing.T) {
	e := NewEvent("test", SeverityWarn)
	if e.Sensor != "test" {
		t.Errorf("sensor = %q, want test", e.Sensor)
	}
	if e.Severity != SeverityWarn {
		t.Errorf("severity = %v, want warn", e.Severity)
	}
	if e.ID.Time() == 0 {
		t.Error("ulid should have nonzero time")
	}
	if e.Tags == nil {
		t.Error("tags map should be initialised")
	}
}

func TestRuleNormalize(t *testing.T) {
	r := &Rule{SeverityRaw: "high", ModeRaw: ""}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	if r.Severity != SeverityHigh {
		t.Errorf("severity = %v, want high", r.Severity)
	}
	if r.Mode != ModeDetect {
		t.Errorf("mode = %v, want detect", r.Mode)
	}

	bad := &Rule{SeverityRaw: "bogus"}
	if err := bad.Normalize(); err == nil {
		t.Error("expected error for bogus severity")
	}
}
