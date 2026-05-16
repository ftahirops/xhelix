package contguard

import "testing"

func TestCleanContainerNoFindings(t *testing.T) {
	f := Classify(Spec{
		Image: "alpine:3.20", RunAsUser: 1000,
	})
	if f.Severity != SeverityNone {
		t.Fatalf("severity = %s, want none; reasons=%v", f.Severity, f.Reasons)
	}
}

func TestPrivilegedIsCritical(t *testing.T) {
	f := Classify(Spec{Privileged: true})
	if f.Severity != SeverityCritical {
		t.Fatalf("severity = %s", f.Severity)
	}
}

func TestHostNamespacesAreHigh(t *testing.T) {
	for _, s := range []Spec{
		{HostPID: true},
		{HostNetwork: true},
		{HostIPC: true},
	} {
		f := Classify(s)
		if f.Severity != SeverityHigh {
			t.Errorf("severity = %s, want high for %+v", f.Severity, s)
		}
	}
}

func TestCapSysAdminIsCritical(t *testing.T) {
	f := Classify(Spec{CapAdd: []string{"SYS_ADMIN"}})
	if f.Severity != SeverityCritical {
		t.Fatalf("severity = %s", f.Severity)
	}
}

func TestCapPrefixToleration(t *testing.T) {
	f := Classify(Spec{CapAdd: []string{"CAP_SYS_ADMIN"}})
	if f.Severity != SeverityCritical {
		t.Fatalf("CAP_-prefixed should also classify; got %s", f.Severity)
	}
}

func TestMountRootIsCritical(t *testing.T) {
	f := Classify(Spec{Mounts: []Mount{{HostPath: "/", ContainerPath: "/host"}}})
	if f.Severity != SeverityCritical {
		t.Fatalf("severity = %s", f.Severity)
	}
}

func TestMountDockerSockIsCritical(t *testing.T) {
	f := Classify(Spec{Mounts: []Mount{{HostPath: "/var/run/docker.sock"}}})
	if f.Severity != SeverityCritical {
		t.Fatalf("severity = %s", f.Severity)
	}
}

func TestMountProcIsHigh(t *testing.T) {
	f := Classify(Spec{Mounts: []Mount{{HostPath: "/proc/sys"}}})
	if f.Severity != SeverityHigh {
		t.Fatalf("severity = %s", f.Severity)
	}
}

func TestUnconfinedSeccomp(t *testing.T) {
	f := Classify(Spec{SeccompProfile: "unconfined"})
	if f.Severity != SeverityHigh {
		t.Fatalf("severity = %s", f.Severity)
	}
}

func TestRunAsRootIsInfo(t *testing.T) {
	f := Classify(Spec{RunAsUser: 0})
	if f.Severity != SeverityInfo {
		t.Fatalf("severity = %s, want info", f.Severity)
	}
}

func TestMultipleFindingsAccumulate(t *testing.T) {
	tr := true
	f := Classify(Spec{
		Privileged: true, HostPID: true,
		CapAdd:                   []string{"SYS_MODULE"},
		Mounts:                   []Mount{{HostPath: "/"}},
		AppArmorProfile:          "unconfined",
		AllowPrivilegeEscalation: &tr,
	})
	if f.Severity != SeverityCritical {
		t.Fatalf("severity = %s", f.Severity)
	}
	if len(f.Reasons) < 4 {
		t.Errorf("expected ≥4 reasons; got %v", f.Reasons)
	}
}

func TestCapNetAdminIsWarn(t *testing.T) {
	f := Classify(Spec{CapAdd: []string{"NET_ADMIN"}})
	if f.Severity != SeverityWarn {
		t.Fatalf("severity = %s, want warn", f.Severity)
	}
}
