// Package servicerole classifies a process's cgroup path to a protected
// service (ServiceKind, ServiceRole) WITHOUT requiring an operator app
// declaration. It is the seam that lets the deterministic exec-deny floor
// apply scoped to a service's own workers (e.g. mysql workers) instead of
// host-globally.
//
// Deliberately conservative: only daemons with an UNAMBIGUOUS exec-deny
// invariant are recognized. php-fpm (legit shell-out) and sshd (legit login
// shells) are intentionally NOT classified here — they would cause false
// denials. The match is substring-on-cgroup, most-specific first.
package servicerole

import (
	"strings"

	"github.com/xhelix/xhelix/pkg/protectedsvc"
)

// ClassifyByCgroup resolves a cgroup path to a protected (kind, role).
// Returns ok=false for anything not a recognized single-purpose daemon.
func ClassifyByCgroup(cgroupPath string) (protectedsvc.ServiceKind, protectedsvc.ServiceRole, bool) {
	if cgroupPath == "" {
		return "", "", false
	}
	// Only system services are protected here; user sessions never are.
	if strings.Contains(cgroupPath, "/user.slice/") {
		return "", "", false
	}
	c := cgroupPath
	switch {
	case strings.Contains(c, "mariadb") || strings.Contains(c, "mysql"):
		return protectedsvc.KindMysql, protectedsvc.RoleDatabase, true
	case strings.Contains(c, "postgresql") || strings.Contains(c, "postgres"):
		return protectedsvc.KindPostgres, protectedsvc.RoleDatabase, true
	case strings.Contains(c, "redis"):
		return protectedsvc.KindRedis, protectedsvc.RoleCache, true
	case strings.Contains(c, "nginx"):
		return protectedsvc.KindNginx, protectedsvc.RoleReverseProxy, true
	case strings.Contains(c, "apache") || strings.Contains(c, "httpd"):
		return protectedsvc.KindApache, protectedsvc.RoleReverseProxy, true
	}
	return "", "", false
}
