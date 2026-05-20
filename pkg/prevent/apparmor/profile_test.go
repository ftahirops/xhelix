package apparmor

import (
	"strings"
	"testing"

	"github.com/xhelix/xhelix/pkg/profiles/contracts"
	"github.com/xhelix/xhelix/pkg/protectedsvc"
)

func newSvc(t *testing.T, kind protectedsvc.ServiceKind, role protectedsvc.ServiceRole) *protectedsvc.ProtectedService {
	t.Helper()
	c, err := contracts.Builtin(kind, role)
	if err != nil {
		t.Fatalf("Builtin(%s,%s): %v", kind, role, err)
	}
	return &protectedsvc.ProtectedService{
		Name:     "test-" + string(kind) + "-" + string(role),
		Kind:     kind,
		Role:     role,
		ExecPath: "/usr/sbin/" + string(kind),
		Contract: c,
	}
}

func TestRender_NginxReverseProxy_HasAllStructure(t *testing.T) {
	svc := newSvc(t, protectedsvc.KindNginx, protectedsvc.RoleReverseProxy)
	p, err := Render(svc)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, p.Body,
		"#include <tunables/global>",
		"profile xhelix.test-nginx-reverse_proxy /usr/sbin/nginx {",
		"/usr/sbin/nginx mr,",
		"/usr/sbin/nginx ix,",
		"/var/log/nginx/** rwk,",
		"network inet tcp,",
		"capability net_bind_service,",
		"deny /bin/sh xm,",
		"deny /usr/bin/curl xm,",
		"deny /proc/*/mem rw,",
		"deny /sys/kernel/security/** rw,",
		"}",
	)
}

func TestRender_EveryNeverLearnableExecHasDenyLine(t *testing.T) {
	svc := newSvc(t, protectedsvc.KindNginx, protectedsvc.RoleStatic)
	p, _ := Render(svc)
	for _, banned := range contracts.NeverLearnableExec {
		needle := "deny " + banned + " xm,"
		if !strings.Contains(p.Body, needle) {
			t.Errorf("profile missing deny for never-learnable %q", banned)
		}
	}
}

func TestRender_OperatorDenyExecPathsAlsoDenied(t *testing.T) {
	c, _ := contracts.Builtin(protectedsvc.KindNginx, protectedsvc.RoleStatic)
	c.DenyExecPaths = append(c.DenyExecPaths, "/opt/custom/evil")
	svc := &protectedsvc.ProtectedService{
		Name: "x", Kind: protectedsvc.KindNginx, Role: protectedsvc.RoleStatic,
		ExecPath: "/usr/sbin/nginx", Contract: c,
	}
	p, err := Render(svc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Body, "deny /opt/custom/evil xm,") {
		t.Fatal("operator DenyExecPaths entry not rendered")
	}
}

func TestRender_AllowExecPaths_Rendered(t *testing.T) {
	c, _ := contracts.Builtin(protectedsvc.KindApache, protectedsvc.RolePHPModule)
	c.AllowExecPaths = []string{"/usr/bin/convert", "/usr/bin/gs"}
	svc := &protectedsvc.ProtectedService{
		Name: "apache-php", Kind: protectedsvc.KindApache, Role: protectedsvc.RolePHPModule,
		ExecPath: "/usr/sbin/apache2", Contract: c,
	}
	p, err := Render(svc)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, p.Body,
		"# Operator-declared legitimate execs",
		"/usr/bin/convert ix,",
		"/usr/bin/gs ix,",
	)
}

func TestRender_UnixSocketsRendered(t *testing.T) {
	c, _ := contracts.Builtin(protectedsvc.KindNginx, protectedsvc.RoleFastCGI)
	svc := &protectedsvc.ProtectedService{
		Name: "nginx-fcgi", Kind: protectedsvc.KindNginx, Role: protectedsvc.RoleFastCGI,
		ExecPath: "/usr/sbin/nginx", Contract: c,
	}
	p, _ := Render(svc)
	if !strings.Contains(p.Body, "/run/php/php-fpm.sock rw,") {
		t.Fatal("UNIX socket not rendered")
	}
}

func TestRender_ReadSensitiveRoots(t *testing.T) {
	c, _ := contracts.Builtin(protectedsvc.KindNginx, protectedsvc.RoleStatic)
	c.ReadSensitiveRoots = []string{"/etc/secrets"}
	svc := &protectedsvc.ProtectedService{
		Name: "x", Kind: protectedsvc.KindNginx, Role: protectedsvc.RoleStatic,
		ExecPath: "/usr/sbin/nginx", Contract: c,
	}
	p, _ := Render(svc)
	if !strings.Contains(p.Body, "deny /etc/secrets/** r,") {
		t.Fatal("ReadSensitiveRoots not rendered")
	}
}

func TestRender_StrictReadOnlyAnnotated(t *testing.T) {
	svc := newSvc(t, protectedsvc.KindNginx, protectedsvc.RoleStatic)
	if !svc.Contract.StrictReadOnly {
		t.Fatal("test setup: nginx/static should be StrictReadOnly")
	}
	p, _ := Render(svc)
	if !strings.Contains(p.Body, "strict_read_only:") {
		t.Fatal("strict_read_only annotation missing")
	}
}

func TestRender_RejectsBadInputs(t *testing.T) {
	if _, err := Render(nil); err == nil {
		t.Fatal("nil should fail")
	}
	if _, err := Render(&protectedsvc.ProtectedService{}); err == nil {
		t.Fatal("missing name should fail")
	}
	if _, err := Render(&protectedsvc.ProtectedService{Name: "x"}); err == nil {
		t.Fatal("missing exec_path should fail")
	}
}

func TestRender_Deterministic(t *testing.T) {
	svc := newSvc(t, protectedsvc.KindNginx, protectedsvc.RoleStatic)
	a, _ := Render(svc)
	b, _ := Render(svc)
	if a.Body != b.Body {
		t.Fatal("Render should be deterministic")
	}
}

func TestProfileName_Sanitization(t *testing.T) {
	cases := []struct{ in, want string }{
		{"nginx-main", "xhelix.nginx-main"},
		{"my service", "xhelix.my_service"},
		{"weird/name:1", "xhelix.weird_name_1"},
		{"good.name_v2", "xhelix.good.name_v2"},
	}
	for _, c := range cases {
		if got := ProfileName(c.in); got != c.want {
			t.Errorf("ProfileName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRender_DangerousCapabilitiesAbsent(t *testing.T) {
	svc := newSvc(t, protectedsvc.KindNginx, protectedsvc.RoleStatic)
	p, _ := Render(svc)
	// These caps are the escape-hatch surface attackers want — must
	// NOT appear in any generated profile by default.
	forbidden := []string{
		"capability sys_admin,",
		"capability sys_ptrace,",
		"capability sys_module,",
		"capability sys_rawio,",
		"capability net_admin,",
		"capability sys_chroot,",
	}
	for _, line := range forbidden {
		if strings.Contains(p.Body, line) {
			t.Errorf("default profile MUST NOT include dangerous capability: %q", line)
		}
	}
}

func mustContain(t *testing.T, body string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(body, n) {
			t.Errorf("profile body missing: %q", n)
		}
	}
}
