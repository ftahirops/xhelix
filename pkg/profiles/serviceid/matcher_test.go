package serviceid

import (
	"errors"
	"strings"
	"testing"

	"github.com/xhelix/xhelix/pkg/protectedsvc"
)

func uidp(u uint32) *uint32 { return &u }

// stub matcher with controllable probes — avoids touching /proc.
func stubMatcher(reg *protectedsvc.Registry) *Matcher {
	return &Matcher{
		Reg:        reg,
		Cache:      NewCache(),
		ReadCgroup: func(pid uint32) (string, error) { return "", errors.New("no probe set") },
		ReadExe:    func(pid uint32) (string, error) { return "", errors.New("no probe set") },
		ReadUIDGID: func(pid uint32) (uint32, uint32, error) { return 0, 0, nil },
		HashFile:   func(p string) (string, error) { return "", nil },
		ReadUnit:   func(pid uint32) (string, error) { return "", nil },
	}
}

func newReg(t *testing.T, svcs ...protectedsvc.ProtectedService) *protectedsvc.Registry {
	t.Helper()
	r := protectedsvc.NewRegistry()
	if err := r.Load(svcs); err != nil {
		t.Fatalf("Load: %v", err)
	}
	return r
}

func TestMatchIdentity_CgroupPrefix(t *testing.T) {
	reg := newReg(t, protectedsvc.ProtectedService{
		Name: "nginx", Kind: protectedsvc.KindNginx, Role: protectedsvc.RoleStatic,
		ExecPath: "/usr/sbin/nginx", CgroupPrefix: "/system.slice/nginx.service",
	})
	m := stubMatcher(reg)
	v := m.MatchIdentity(protectedsvc.Identity{
		PID:     1234,
		ExePath: "/usr/sbin/nginx",
		CGroup:  "/system.slice/nginx.service/worker-1",
	})
	if !v.Matched || v.Service.Name != "nginx" {
		t.Fatalf("expected match; got %+v", v)
	}
	if v.Discrepancy != "" {
		t.Fatalf("expected no discrepancy; got %q", v.Discrepancy)
	}
}

func TestMatchIdentity_ExecPathMismatchIsDiscrepancy(t *testing.T) {
	reg := newReg(t, protectedsvc.ProtectedService{
		Name: "nginx", Kind: protectedsvc.KindNginx, Role: protectedsvc.RoleStatic,
		ExecPath: "/usr/sbin/nginx", CgroupPrefix: "/system.slice/nginx.service",
	})
	m := stubMatcher(reg)
	v := m.MatchIdentity(protectedsvc.Identity{
		PID:     1234,
		ExePath: "/tmp/evil-nginx", // hijacked binary
		CGroup:  "/system.slice/nginx.service",
	})
	if v.Matched {
		t.Fatal("hijacked exe must NOT match cleanly")
	}
	if v.Discrepancy == "" || !strings.Contains(v.Discrepancy, "exec_path") {
		t.Fatalf("expected exec_path discrepancy; got %+v", v)
	}
}

func TestMatchIdentity_ExeSHAMismatchIsDiscrepancy(t *testing.T) {
	good := strings.Repeat("a", 64)
	bad := strings.Repeat("b", 64)
	reg := newReg(t, protectedsvc.ProtectedService{
		Name: "nginx", Kind: protectedsvc.KindNginx, Role: protectedsvc.RoleStatic,
		ExecPath: "/usr/sbin/nginx", ExeSHA256: good,
		CgroupPrefix: "/system.slice/nginx.service",
	})
	m := stubMatcher(reg)
	v := m.MatchIdentity(protectedsvc.Identity{
		PID:       1234,
		ExePath:   "/usr/sbin/nginx",
		ExeSHA256: bad,
		CGroup:    "/system.slice/nginx.service",
	})
	if v.Matched {
		t.Fatal("SHA mismatch must NOT match cleanly")
	}
	if !strings.Contains(v.Discrepancy, "exe_sha256") {
		t.Fatalf("expected sha discrepancy; got %q", v.Discrepancy)
	}
}

func TestMatchIdentity_UIDMismatch(t *testing.T) {
	reg := newReg(t, protectedsvc.ProtectedService{
		Name: "nginx", Kind: protectedsvc.KindNginx, Role: protectedsvc.RoleStatic,
		ExecPath: "/usr/sbin/nginx", CgroupPrefix: "/system.slice/nginx.service",
		UID: uidp(33),
	})
	m := stubMatcher(reg)
	v := m.MatchIdentity(protectedsvc.Identity{
		PID: 1, ExePath: "/usr/sbin/nginx", CGroup: "/system.slice/nginx.service",
		UID: 0, // running as root — anomaly
	})
	if v.Matched {
		t.Fatal("uid mismatch must not match cleanly")
	}
	if !strings.Contains(v.Discrepancy, "uid") {
		t.Fatalf("expected uid discrepancy; got %q", v.Discrepancy)
	}
}

func TestMatchIdentity_UnitFallback(t *testing.T) {
	reg := newReg(t, protectedsvc.ProtectedService{
		Name: "nginx", Kind: protectedsvc.KindNginx, Role: protectedsvc.RoleStatic,
		ExecPath: "/usr/sbin/nginx", Unit: "nginx.service",
	})
	m := stubMatcher(reg)
	v := m.MatchIdentity(protectedsvc.Identity{
		PID: 1, ExePath: "/usr/sbin/nginx", Unit: "nginx.service",
		// No CGroup — fall back to unit lookup.
	})
	if !v.Matched {
		t.Fatalf("unit fallback should match; got %+v", v)
	}
}

func TestMatchIdentity_NoMatch(t *testing.T) {
	reg := newReg(t, protectedsvc.ProtectedService{
		Name: "nginx", Kind: protectedsvc.KindNginx, Role: protectedsvc.RoleStatic,
		ExecPath: "/usr/sbin/nginx", CgroupPrefix: "/system.slice/nginx.service",
	})
	m := stubMatcher(reg)
	v := m.MatchIdentity(protectedsvc.Identity{
		PID: 99, ExePath: "/usr/bin/vim", CGroup: "/user.slice/u1.scope",
	})
	if v.Matched || v.Service != nil {
		t.Fatalf("expected no match; got %+v", v)
	}
}

func TestMatchPID_CachesHitsAndMisses(t *testing.T) {
	reg := newReg(t, protectedsvc.ProtectedService{
		Name: "nginx", Kind: protectedsvc.KindNginx, Role: protectedsvc.RoleStatic,
		ExecPath: "/usr/sbin/nginx", CgroupPrefix: "/system.slice/nginx.service",
	})
	calls := 0
	m := &Matcher{
		Reg:   reg,
		Cache: NewCache(),
		ReadCgroup: func(pid uint32) (string, error) {
			calls++
			return "/system.slice/nginx.service/worker", nil
		},
		ReadExe:    func(pid uint32) (string, error) { return "/usr/sbin/nginx", nil },
		ReadUIDGID: func(pid uint32) (uint32, uint32, error) { return 33, 33, nil },
		HashFile:   func(p string) (string, error) { return "", nil },
		ReadUnit:   func(pid uint32) (string, error) { return "nginx.service", nil },
	}

	v1 := m.MatchPID(1234, 999) // cgroup_id 999
	v2 := m.MatchPID(5678, 999) // SAME cgroup_id, different pid — must hit cache
	if !v1.Matched || !v2.Matched {
		t.Fatalf("both should match: v1=%+v v2=%+v", v1, v2)
	}
	if calls != 1 {
		t.Fatalf("ReadCgroup should be called once due to cache; got %d", calls)
	}

	// Negative cache: cgroup_id 888 should resolve to no-match, then cache it.
	m.ReadCgroup = func(pid uint32) (string, error) { calls++; return "/user.slice/u1", nil }
	m.ReadExe = func(pid uint32) (string, error) { return "/usr/bin/vim", nil }
	before := calls
	v3 := m.MatchPID(9999, 888)
	v4 := m.MatchPID(8888, 888) // same cgroup_id — should NOT call ReadCgroup again
	if v3.Matched || v4.Matched {
		t.Fatal("should not match")
	}
	if got := calls - before; got != 1 {
		t.Fatalf("negative cache should suppress repeat probe; got %d new calls", got)
	}
}

func TestCache_FIFOEviction(t *testing.T) {
	c := NewCacheWithCap(2)
	c.Set(1, "a")
	c.Set(2, "b")
	c.Set(3, "c") // evicts 1
	if _, ok := c.Get(1); ok {
		t.Fatal("entry 1 should have been evicted")
	}
	if v, ok := c.Get(2); !ok || v != "b" {
		t.Fatalf("entry 2 wrong: %q ok=%v", v, ok)
	}
	if v, ok := c.Get(3); !ok || v != "c" {
		t.Fatalf("entry 3 wrong: %q ok=%v", v, ok)
	}
}

func TestCache_NegativeMarkedDistinct(t *testing.T) {
	c := NewCache()
	c.Set(7, "") // negative
	v, ok := c.Get(7)
	if !ok {
		t.Fatal("negative entry must read as present")
	}
	if v != "" {
		t.Fatalf("negative entry must be empty string; got %q", v)
	}
}
