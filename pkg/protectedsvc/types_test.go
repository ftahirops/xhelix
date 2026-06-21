package protectedsvc

import "testing"

func TestAllKindsIncludesDaemons(t *testing.T) {
	want := map[ServiceKind]bool{
		KindNginx: false, KindApache: false,
		KindMysql: false, KindPostgres: false, KindRedis: false,
	}
	for _, k := range AllKinds() {
		if _, ok := want[k]; ok {
			want[k] = true
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("AllKinds() missing %q", k)
		}
	}
}

func TestAllRolesIncludesDatabaseAndCache(t *testing.T) {
	got := map[ServiceRole]bool{}
	for _, r := range AllRoles() {
		got[r] = true
	}
	for _, r := range []ServiceRole{RoleDatabase, RoleCache} {
		if !got[r] {
			t.Errorf("AllRoles() missing %q", r)
		}
	}
}
