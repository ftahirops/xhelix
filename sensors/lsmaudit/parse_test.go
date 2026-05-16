package lsmaudit

import (
	"testing"

	"github.com/xhelix/xhelix/pkg/model"
)

func TestParseAppArmorDenied(t *testing.T) {
	line := `Apr 30 16:02:00 host kernel: audit: type=1400 audit(1714492920.123:42): apparmor="DENIED" operation="open" profile="/usr/sbin/cupsd" name="/etc/shadow" pid=1234 comm="cupsd" requested_mask="r" denied_mask="r" fsuid=0 ouid=0`
	v, ok := Parse(line)
	if !ok {
		t.Fatal("expected match")
	}
	if v.LSM != "apparmor" {
		t.Errorf("LSM = %q", v.LSM)
	}
	if v.Action != "DENIED" {
		t.Errorf("action = %q", v.Action)
	}
	if v.Profile != "/usr/sbin/cupsd" {
		t.Errorf("profile = %q", v.Profile)
	}
	if v.Path != "/etc/shadow" {
		t.Errorf("path = %q", v.Path)
	}
	if v.Comm != "cupsd" {
		t.Errorf("comm = %q", v.Comm)
	}

	ev := ToEvent(v, "h1")
	if ev.Severity != model.SeverityCritical {
		t.Errorf("severity = %v, want critical", ev.Severity)
	}
	if ev.Tags["lsm"] != "apparmor" {
		t.Errorf("tag lsm = %q", ev.Tags["lsm"])
	}
}

func TestParseSELinuxAVC(t *testing.T) {
	line := `type=AVC msg=audit(1714492920.123:42): avc:  denied  { read } for  pid=1234 comm="curl" name="shadow" dev="dm-0" ino=1234 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0`
	v, ok := Parse(line)
	if !ok {
		t.Fatal("expected match")
	}
	if v.LSM != "selinux" {
		t.Errorf("LSM = %q", v.LSM)
	}
	if v.Action != "denied" {
		t.Errorf("action = %q", v.Action)
	}
	if v.Operation != "read" {
		t.Errorf("operation = %q", v.Operation)
	}
	if v.Comm != "curl" {
		t.Errorf("comm = %q", v.Comm)
	}
	if v.Class != "file" {
		t.Errorf("tclass = %q", v.Class)
	}
	if v.SContext == "" || v.TContext == "" {
		t.Errorf("contexts: s=%q t=%q", v.SContext, v.TContext)
	}

	ev := ToEvent(v, "h1")
	if ev.Severity != model.SeverityCritical {
		t.Errorf("severity = %v, want critical", ev.Severity)
	}
}

func TestParseUnrelatedLine(t *testing.T) {
	if _, ok := Parse("Apr 30 16:02:00 host kernel: regular log line"); ok {
		t.Error("expected no match")
	}
}

func TestStatusSummary(t *testing.T) {
	s := Status{HasBPFLSM: true, HasAppArmor: true, AppArmorMode: "enforce"}
	got := s.Summary()
	if got != "BPF-LSM, AppArmor=enforce" {
		t.Errorf("summary = %q", got)
	}
}
