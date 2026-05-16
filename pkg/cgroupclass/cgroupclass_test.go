package cgroupclass

import (
	"testing"
)

func TestClassifyPath(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantClass Class
		wantUnit  string
		wantUser  string
		wantCID   string
	}{
		{
			name:      "user session firefox",
			path:      "/user.slice/user-1000.slice/user@1000.service/app.slice/firefox.service",
			wantClass: ClassUser,
			wantUnit:  "firefox.service",
			wantUser:  "1000",
		},
		{
			name:      "user session bare slice",
			path:      "/user.slice/user-1001.slice/session-3.scope",
			wantClass: ClassUser,
			wantUnit:  "session-3.scope",
			wantUser:  "1001",
		},
		{
			name:      "system daemon snapd",
			path:      "/system.slice/snapd.service",
			wantClass: ClassSystem,
			wantUnit:  "snapd.service",
		},
		{
			name:      "init scope",
			path:      "/init.scope",
			wantClass: ClassSystem,
		},
		{
			name:      "docker container",
			path:      "/system.slice/docker-9f8e7d6c5b4a3210fedcba9876543210fedcba9876543210fedcba9876543210.scope",
			wantClass: ClassContainer,
			wantCID:   "9f8e7d6c5b4a3210fedcba9876543210fedcba9876543210fedcba9876543210",
		},
		{
			name:      "kubepods cri-containerd",
			path:      "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234.slice/cri-containerd-abc123.scope",
			wantClass: ClassContainer,
			wantCID:   "abc123",
		},
		{
			name:      "machine.slice (nspawn/libvirt)",
			path:      "/machine.slice/machine-qemu-1-test.scope",
			wantClass: ClassContainer,
		},
		{
			name:      "empty path -> kernel",
			path:      "",
			wantClass: ClassKernel,
		},
		{
			name:      "root slash -> kernel",
			path:      "/",
			wantClass: ClassKernel,
		},
		{
			name:      "unrecognised slice -> system",
			path:      "/custom.slice/weird.service",
			wantClass: ClassSystem,
			wantUnit:  "weird.service",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyPath(tc.path)
			if got.Class != tc.wantClass {
				t.Errorf("class = %s, want %s", got.Class, tc.wantClass)
			}
			if tc.wantUnit != "" && got.Unit != tc.wantUnit {
				t.Errorf("unit = %q, want %q", got.Unit, tc.wantUnit)
			}
			if tc.wantUser != "" && got.UserID != tc.wantUser {
				t.Errorf("user = %q, want %q", got.UserID, tc.wantUser)
			}
			if tc.wantCID != "" && got.ContainerID != tc.wantCID {
				t.Errorf("container_id = %q, want %q", got.ContainerID, tc.wantCID)
			}
		})
	}
}

func TestParseCgroupFileV2Preferred(t *testing.T) {
	// Mixed v1 + v2 lines — the v2 unified line "0::..." wins.
	data := []byte(
		"11:perf_event:/\n" +
			"10:freezer:/user.slice/user-1000.slice\n" +
			"0::/user.slice/user-1000.slice/session-1.scope\n",
	)
	info := parseCgroupFile(data)
	if info.Class != ClassUser {
		t.Fatalf("class = %s, want user", info.Class)
	}
	if info.UserID != "1000" {
		t.Fatalf("user = %q, want 1000", info.UserID)
	}
	if info.Unit != "session-1.scope" {
		t.Fatalf("unit = %q, want session-1.scope", info.Unit)
	}
}

func TestClassifierCacheAndForget(t *testing.T) {
	c := New(8)
	c.read = func(path string) ([]byte, error) {
		return []byte("0::/system.slice/foo.service\n"), nil
	}

	info := c.Classify(42)
	if info.Class != ClassSystem || info.Unit != "foo.service" {
		t.Fatalf("first classify wrong: %+v", info)
	}
	if c.Len() != 1 {
		t.Fatalf("cache len = %d, want 1", c.Len())
	}

	// Second call must hit the cache (we change `read` to detect a re-read).
	c.read = func(path string) ([]byte, error) {
		t.Fatal("read called on cache hit")
		return nil, nil
	}
	_ = c.Classify(42)

	c.Forget(42)
	if c.Len() != 0 {
		t.Fatalf("cache len after forget = %d, want 0", c.Len())
	}
}

func TestClassifierEviction(t *testing.T) {
	c := New(4)
	c.read = func(path string) ([]byte, error) {
		return []byte("0::/system.slice/x.service\n"), nil
	}
	for pid := uint32(1); pid <= 10; pid++ {
		c.Classify(pid)
	}
	if c.Len() > 4 {
		t.Fatalf("cache len = %d, want <= 4", c.Len())
	}
}

func TestClassifyMissingProc(t *testing.T) {
	c := New(0)
	c.read = func(path string) ([]byte, error) {
		return nil, errFake
	}
	info := c.Classify(99999)
	if info.Class != ClassKernel {
		t.Fatalf("missing proc class = %s, want kernel", info.Class)
	}
}

type fakeErr struct{}

func (fakeErr) Error() string { return "no such file" }

var errFake = fakeErr{}
