package canonical

import (
	"os"
	"strings"
	"testing"
)

func TestParseCgroupLine_HappyPath(t *testing.T) {
	id, ctrl, path := ParseCgroupLine("0::/system.slice/sshd.service")
	if id != "0" || ctrl != "" || path != "/system.slice/sshd.service" {
		t.Errorf("got id=%q ctrl=%q path=%q", id, ctrl, path)
	}
}

func TestParseCgroupLine_V1Variants(t *testing.T) {
	cases := []struct {
		line, id, ctrl, path string
	}{
		{"12:memory:/user.slice/user-1000.slice", "12", "memory", "/user.slice/user-1000.slice"},
		{"3:cpu,cpuacct:/", "3", "cpu,cpuacct", "/"},
	}
	for _, c := range cases {
		id, ctrl, path := ParseCgroupLine(c.line)
		if id != c.id || ctrl != c.ctrl || path != c.path {
			t.Errorf("%q → id=%q ctrl=%q path=%q (want id=%q ctrl=%q path=%q)",
				c.line, id, ctrl, path, c.id, c.ctrl, c.path)
		}
	}
}

func TestParseCgroupLine_Malformed(t *testing.T) {
	id, _, _ := ParseCgroupLine("not a cgroup line")
	if id != "" {
		t.Errorf("malformed line should return empty id")
	}
}

func TestParseCgroupFile_V2Wins(t *testing.T) {
	// Hybrid cgroup-v1 + v2 file. The v2 entry (id=0, controller="")
	// is what xhelix should prefer.
	content := `12:memory:/user.slice
8:cpu,cpuacct:/user.slice/user-1000.slice
0::/user.slice/user-1000.slice/session-1.scope`
	info, err := parseCgroupFile(strings.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if info.Path != "/user.slice/user-1000.slice/session-1.scope" {
		t.Errorf("Path = %q, want session-1.scope", info.Path)
	}
}

func TestParseCgroupFile_NoV2DeepestV1(t *testing.T) {
	// Pure cgroup-v1 — pick the deepest path.
	content := `12:memory:/system.slice
8:cpu:/system.slice/docker.service
3:devices:/`
	info, err := parseCgroupFile(strings.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if info.Path != "/system.slice/docker.service" {
		t.Errorf("Path = %q, want deepest v1 path", info.Path)
	}
}

func TestDetectContainer_Docker(t *testing.T) {
	cases := []string{
		"/docker/3e2f8c9b9e1a4d2b0f1a3c5d7e9b1c3d5f7a9b1c3d5f7a9b1c3d5f7a9b1c3d5f",
		"/system.slice/docker-3e2f8c9b9e1a4d2b0f1a3c5d7e9b1c3d5f7a9b1c3d5f7a9b1c3d5f7a9b1c3d5f.scope",
	}
	for _, p := range cases {
		runtime, id := detectContainer(p)
		if runtime != "docker" {
			t.Errorf("%q → runtime=%q, want docker", p, runtime)
		}
		if len(id) < 12 {
			t.Errorf("%q → container id too short: %q", p, id)
		}
	}
}

func TestDetectContainer_Kubernetes(t *testing.T) {
	p := "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234abcd_5678_9012_3456_789abcdef012.slice/cri-containerd-abcdef1234567890abcdef1234567890.scope"
	runtime, id := detectContainer(p)
	if runtime != "kubernetes" {
		t.Errorf("runtime = %q, want kubernetes", runtime)
	}
	if id == "" {
		t.Error("expected non-empty container id for k8s path")
	}
}

func TestDetectContainer_PodmanAndLxc(t *testing.T) {
	rt, _ := detectContainer("/machine.slice/libpod-abc123def456abc123def456abc123de.scope")
	if rt != "podman" {
		t.Errorf("podman path: runtime = %q", rt)
	}

	rt, id := detectContainer("/lxc/myguest")
	if rt != "lxc" || id != "myguest" {
		t.Errorf("lxc path: runtime=%q id=%q", rt, id)
	}
}

func TestDetectContainer_NotAContainer(t *testing.T) {
	cases := []string{
		"/",
		"/user.slice/user-1000.slice",
		"/system.slice/sshd.service",
	}
	for _, p := range cases {
		rt, id := detectContainer(p)
		if rt != "" || id != "" {
			t.Errorf("%q wrongly detected as container: rt=%q id=%q", p, rt, id)
		}
	}
}

func TestDetectSystemdUnit(t *testing.T) {
	cases := []struct {
		path, unit string
	}{
		{"/system.slice/sshd.service", "sshd.service"},
		{"/system.slice/docker.service/docker-abc.scope", "docker-abc.scope"},
		{"/user.slice/user-1000.slice", "user-1000.slice"},
		{"/", ""},
		{"/no-systemd-stuff/here", ""},
	}
	for _, c := range cases {
		got := detectSystemdUnit(c.path)
		if got != c.unit {
			t.Errorf("%q → %q, want %q", c.path, got, c.unit)
		}
	}
}

func TestIsHex(t *testing.T) {
	yes := []string{"abc123", "DEADBEEF", "0", "f"}
	no := []string{"", "ghij", "xyz", "abc-123", "abc 123"}
	for _, s := range yes {
		if !isHex(s) {
			t.Errorf("isHex(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if isHex(s) {
			t.Errorf("isHex(%q) = true, want false", s)
		}
	}
}

func TestReadCgroup_Self(t *testing.T) {
	info, err := ReadCgroup(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("ReadCgroup(self): %v", err)
	}
	if info.Path == "" {
		t.Errorf("self cgroup path should be non-empty")
	}
	if info.Path[0] != '/' {
		t.Errorf("cgroup path should start with / : %q", info.Path)
	}
}

func TestReadCgroup_NonexistentPID(t *testing.T) {
	_, err := ReadCgroup(99999999)
	if err == nil {
		t.Error("expected error for non-existent pid")
	}
}
