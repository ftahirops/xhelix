package container

import "testing"

func TestExtractContainerID(t *testing.T) {
	cases := []struct {
		name, input, want string
	}{
		{
			"docker-classic",
			"12:cpu:/docker/abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		},
		{
			"systemd-docker-scope",
			"0::/system.slice/docker-1234567890ab.scope",
			"1234567890ab",
		},
		{
			"k8s-cri-containerd",
			"0::/kubepods/burstable/pod1/cri-containerd-fedcba9876543210.scope",
			"fedcba9876543210",
		},
		{
			"k8s-pod-trailing-id",
			"0::/kubepods/besteffort/pod-uuid/aabbccddeeff00112233",
			"aabbccddeeff00112233",
		},
		{
			"non-container",
			"0::/user.slice/user-1000.slice",
			"",
		},
	}
	for _, c := range cases {
		got := extractContainerID(c.input)
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestIsContainerID(t *testing.T) {
	if !isContainerID("abcdef0123456789") {
		t.Error("expected hex 16-char to be a container ID")
	}
	if isContainerID("short") {
		t.Error("'short' should not be a container ID")
	}
	if isContainerID("notHexLongEnoughString") {
		t.Error("non-hex should not be a container ID")
	}
}

func TestResolverCachesResults(t *testing.T) {
	r := New()
	cgPath := "0::/system.slice/docker-1234567890ab.scope"
	// First lookup (no docker socket on test host — returns ID-only).
	info := r.Resolve(cgPath)
	if info.ID != "1234567890ab" {
		t.Errorf("ID = %q", info.ID)
	}
	// Second lookup hits cache.
	r.mu.RLock()
	defer r.mu.RUnlock()
	if _, ok := r.cache["1234567890ab"]; !ok {
		t.Error("expected cache hit after first resolve")
	}
}
