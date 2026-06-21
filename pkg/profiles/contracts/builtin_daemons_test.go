package contracts

import (
	"testing"

	"github.com/xhelix/xhelix/pkg/protectedsvc"
)

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func TestBuiltinDaemonsDenyShellAndDownloaders(t *testing.T) {
	cases := []struct {
		kind protectedsvc.ServiceKind
		role protectedsvc.ServiceRole
	}{
		{protectedsvc.KindMysql, protectedsvc.RoleDatabase},
		{protectedsvc.KindPostgres, protectedsvc.RoleDatabase},
		{protectedsvc.KindRedis, protectedsvc.RoleCache},
	}
	for _, c := range cases {
		sc, err := Builtin(c.kind, c.role)
		if err != nil {
			t.Fatalf("Builtin(%s,%s) error: %v", c.kind, c.role, err)
		}
		for _, must := range []string{"/bin/sh", "/usr/bin/curl", "/usr/bin/python3"} {
			if !contains(sc.DenyExecPaths, must) {
				t.Errorf("%s/%s DenyExecPaths missing %q", c.kind, c.role, must)
			}
		}
		if len(sc.AllowExecPaths) != 0 {
			t.Errorf("%s/%s should allow no exec, got %v", c.kind, c.role, sc.AllowExecPaths)
		}
		if !contains(sc.DenySyscalls, "ptrace") || !contains(sc.DenySyscalls, "bpf") {
			t.Errorf("%s/%s DenySyscalls missing ptrace/bpf: %v", c.kind, c.role, sc.DenySyscalls)
		}
	}
}

func TestBuiltinRejectsMismatchedRole(t *testing.T) {
	if _, err := Builtin(protectedsvc.KindMysql, protectedsvc.RoleCache); err == nil {
		t.Error("expected ErrUnsupportedRole for mysql/cache")
	}
}
