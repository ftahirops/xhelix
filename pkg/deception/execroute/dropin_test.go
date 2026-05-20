package execroute

import (
	"errors"
	"strings"
	"testing"

	"github.com/xhelix/xhelix/pkg/profiles/contracts"
	"github.com/xhelix/xhelix/pkg/protectedsvc"
)

func nginxSvc(t *testing.T, deception bool) *protectedsvc.ProtectedService {
	t.Helper()
	c, err := contracts.Builtin(protectedsvc.KindNginx, protectedsvc.RoleReverseProxy)
	if err != nil {
		t.Fatal(err)
	}
	svc := &protectedsvc.ProtectedService{
		Name: "nginx-main", Kind: protectedsvc.KindNginx, Role: protectedsvc.RoleReverseProxy,
		ExecPath: "/usr/sbin/nginx",
		Unit:     "nginx.service",
		Contract: c,
	}
	if deception {
		svc.Response.Deception = protectedsvc.AllOn()
	}
	return svc
}

func TestGenerateDropIn_RedirectsShells(t *testing.T) {
	svc := nginxSvc(t, true)
	d, err := GenerateDropIn(svc, AllRedirects())
	if err != nil {
		t.Fatal(err)
	}
	must := []string{
		"[Service]",
		"PrivateMounts=yes",
		"BindReadOnlyPaths=/usr/lib/xhelix/honey-sh:/bin/sh:norbind",
		"BindReadOnlyPaths=/usr/lib/xhelix/honey-sh:/bin/bash:norbind",
		"BindReadOnlyPaths=/usr/lib/xhelix/honey-sh:/usr/bin/python3:norbind",
		"BindReadOnlyPaths=/usr/lib/xhelix/honey-sh:/usr/bin/curl:norbind",
		"BindReadOnlyPaths=/usr/lib/xhelix/honey-sh:/usr/bin/sudo:norbind",
	}
	for _, m := range must {
		if !strings.Contains(d.Body, m) {
			t.Errorf("body missing %q", m)
		}
	}
	if d.UnitName != "nginx.service" {
		t.Fatalf("UnitName=%q", d.UnitName)
	}
	if !strings.HasSuffix(d.Path, "/nginx.service.d/xhelix-deception.conf") {
		t.Fatalf("Path=%q", d.Path)
	}
}

func TestGenerateDropIn_RefusesWithoutDeception(t *testing.T) {
	svc := nginxSvc(t, false)
	_, err := GenerateDropIn(svc, AllRedirects())
	if !errors.Is(err, ErrNoDeception) {
		t.Fatalf("expected ErrNoDeception, got %v", err)
	}
}

func TestGenerateDropIn_RefusesWithoutUnit(t *testing.T) {
	svc := nginxSvc(t, true)
	svc.Unit = ""
	if _, err := GenerateDropIn(svc, AllRedirects()); err == nil {
		t.Fatal("missing Unit should fail")
	}
}

func TestGenerateDropIn_CategoryToggles(t *testing.T) {
	svc := nginxSvc(t, true)
	opts := AllRedirects()
	opts.RedirectInterpreters = false
	opts.RedirectDownloaders = false

	d, err := GenerateDropIn(svc, opts)
	if err != nil {
		t.Fatal(err)
	}
	// Shells STILL redirected.
	if !strings.Contains(d.Body, "/bin/sh:norbind") {
		t.Fatal("shells should still redirect")
	}
	// Interpreters NOT redirected.
	if strings.Contains(d.Body, "python3:norbind") {
		t.Fatal("interpreters were disabled but redirected")
	}
	// Downloaders NOT redirected.
	if strings.Contains(d.Body, "curl:norbind") {
		t.Fatal("downloaders were disabled but redirected")
	}
}

func TestGenerateDropIn_ExtraTargets(t *testing.T) {
	svc := nginxSvc(t, true)
	opts := AllRedirects()
	opts.ExtraTargets = []string{"/opt/legacy/expect"}
	d, err := GenerateDropIn(svc, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.Body, "/opt/legacy/expect:norbind") {
		t.Fatalf("extra target missing: %s", d.Body)
	}
}

func TestGenerateDropIn_Deterministic(t *testing.T) {
	svc := nginxSvc(t, true)
	a, _ := GenerateDropIn(svc, AllRedirects())
	b, _ := GenerateDropIn(svc, AllRedirects())
	if a.Body != b.Body {
		t.Fatal("drop-in should be deterministic for same input")
	}
}

func TestGenerateDropIn_MountsSorted(t *testing.T) {
	svc := nginxSvc(t, true)
	d, _ := GenerateDropIn(svc, AllRedirects())
	for i := 1; i < len(d.Mounts); i++ {
		if d.Mounts[i-1].Target >= d.Mounts[i].Target {
			t.Errorf("mounts not sorted: %s >= %s",
				d.Mounts[i-1].Target, d.Mounts[i].Target)
		}
	}
}

func TestGenerateDropIn_HoneyShPathOverride(t *testing.T) {
	svc := nginxSvc(t, true)
	opts := AllRedirects()
	opts.HoneyShPath = "/opt/xhelix/honey-sh"
	d, _ := GenerateDropIn(svc, opts)
	if !strings.Contains(d.Body, "/opt/xhelix/honey-sh:/bin/sh") {
		t.Fatal("HoneyShPath override not honored")
	}
}

func TestHoneyShProfile_ProperlyLockedDown(t *testing.T) {
	p := HoneyShProfile()
	body := p.Body
	must := []string{
		"profile xhelix.honeysh /usr/lib/xhelix/honey-sh",
		"deny network,",
		"deny capability,",
		"deny /** w,",
		"deny /etc/shadow r,",
		"deny /bin/** x,",
		"deny /proc/*/mem rw,",
		"deny ptrace,",
	}
	for _, m := range must {
		if !strings.Contains(body, m) {
			t.Errorf("honeysh profile missing: %q", m)
		}
	}
	// Honey-sh has NO capabilities — verify no "capability X," line
	// (except the "deny capability," line).
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "capability ") {
			t.Errorf("honeysh profile MUST NOT grant any capability: %q", trimmed)
		}
	}
}
