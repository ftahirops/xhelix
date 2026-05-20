package contracts

import (
	"errors"
	"strings"
	"testing"

	"github.com/xhelix/xhelix/pkg/protectedsvc"
)

func TestBuiltin_NginxRoles(t *testing.T) {
	for _, r := range []protectedsvc.ServiceRole{
		protectedsvc.RoleStatic,
		protectedsvc.RoleReverseProxy,
		protectedsvc.RoleFastCGI,
	} {
		c, err := Builtin(protectedsvc.KindNginx, r)
		if err != nil {
			t.Errorf("nginx/%s: unexpected error %v", r, err)
			continue
		}
		assertContainsAllNeverLearnable(t, "nginx/"+string(r), c)
		if len(c.WriteRoots) == 0 {
			t.Errorf("nginx/%s: WriteRoots empty", r)
		}
		if len(c.ListenPorts) == 0 {
			t.Errorf("nginx/%s: ListenPorts empty", r)
		}
	}
}

func TestBuiltin_ApacheRoles(t *testing.T) {
	for _, r := range []protectedsvc.ServiceRole{
		protectedsvc.RoleStatic,
		protectedsvc.RoleReverseProxy,
		protectedsvc.RolePHPModule,
	} {
		c, err := Builtin(protectedsvc.KindApache, r)
		if err != nil {
			t.Errorf("apache/%s: unexpected error %v", r, err)
			continue
		}
		assertContainsAllNeverLearnable(t, "apache/"+string(r), c)
	}
}

func TestBuiltin_RejectsUnsupported(t *testing.T) {
	if _, err := Builtin(protectedsvc.KindNginx, protectedsvc.RolePHPModule); !errors.Is(err, ErrUnsupportedRole) {
		t.Fatalf("nginx + php_module should be unsupported, got %v", err)
	}
	if _, err := Builtin(protectedsvc.KindApache, protectedsvc.RoleFastCGI); !errors.Is(err, ErrUnsupportedRole) {
		t.Fatalf("apache + fastcgi should be unsupported, got %v", err)
	}
	if _, err := Builtin("iis", protectedsvc.RoleStatic); !errors.Is(err, ErrUnsupportedRole) {
		t.Fatalf("unknown kind should be unsupported, got %v", err)
	}
}

func TestBuiltin_PHPModuleHasPHPWriteRoots(t *testing.T) {
	c, _ := Builtin(protectedsvc.KindApache, protectedsvc.RolePHPModule)
	found := false
	for _, w := range c.WriteRoots {
		if strings.HasPrefix(w, "/var/lib/php") {
			found = true
		}
	}
	if !found {
		t.Fatalf("apache/php_module should write to /var/lib/php; got %v", c.WriteRoots)
	}
	// php_module is the only role that's NOT strict_read_only by default.
	if c.StrictReadOnly {
		t.Fatal("apache/php_module should not be StrictReadOnly by default")
	}
}

func TestMerge_OperatorAllowReplacesBuiltin(t *testing.T) {
	builtin, _ := Builtin(protectedsvc.KindNginx, protectedsvc.RoleReverseProxy)
	override := protectedsvc.ServiceContract{
		UpstreamCIDRs: []string{"10.20.0.0/24", "10.30.0.0/24"},
		WriteRoots:    []string{"/var/log/nginx", "/srv/uploads"},
	}
	merged, err := Merge(builtin, override)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if len(merged.UpstreamCIDRs) != 2 || merged.UpstreamCIDRs[0] != "10.20.0.0/24" {
		t.Fatalf("override should replace UpstreamCIDRs: %v", merged.UpstreamCIDRs)
	}
	// WriteRoots replaced — built-in /var/cache/nginx is GONE.
	hasCache := false
	for _, w := range merged.WriteRoots {
		if w == "/var/cache/nginx" {
			hasCache = true
		}
	}
	if hasCache {
		t.Fatalf("override should replace WriteRoots; got %v", merged.WriteRoots)
	}
}

func TestMerge_DenyListsUnion(t *testing.T) {
	builtin, _ := Builtin(protectedsvc.KindNginx, protectedsvc.RoleStatic)
	override := protectedsvc.ServiceContract{
		DenySyscalls: []string{"sendmmsg", "recvmmsg"}, // custom extras
		DenyExecPaths: []string{"/usr/bin/custom-evil-tool"},
	}
	merged, err := Merge(builtin, override)
	if err != nil {
		t.Fatal(err)
	}
	hasBuiltin := false
	hasOverride := false
	for _, s := range merged.DenySyscalls {
		if s == "ptrace" {
			hasBuiltin = true
		}
		if s == "sendmmsg" {
			hasOverride = true
		}
	}
	if !hasBuiltin || !hasOverride {
		t.Fatalf("DenySyscalls should union; got %v", merged.DenySyscalls)
	}

	hasShell := false
	hasCustom := false
	for _, p := range merged.DenyExecPaths {
		if p == "/bin/sh" {
			hasShell = true
		}
		if p == "/usr/bin/custom-evil-tool" {
			hasCustom = true
		}
	}
	if !hasShell || !hasCustom {
		t.Fatalf("DenyExecPaths should union; got %v", merged.DenyExecPaths)
	}
}

func TestMerge_RejectsAllowingShell(t *testing.T) {
	builtin, _ := Builtin(protectedsvc.KindNginx, protectedsvc.RoleStatic)
	override := protectedsvc.ServiceContract{
		AllowExecPaths: []string{"/bin/sh"}, // operator tries to weaken
	}
	if _, err := Merge(builtin, override); !errors.Is(err, ErrInvariantViolation) {
		t.Fatalf("allowing /bin/sh must violate invariant; got %v", err)
	}
}

func TestMerge_RejectsAllowingInterpreter(t *testing.T) {
	builtin, _ := Builtin(protectedsvc.KindNginx, protectedsvc.RoleFastCGI)
	for _, p := range []string{"/usr/bin/python3", "/usr/bin/php", "/usr/bin/curl"} {
		override := protectedsvc.ServiceContract{AllowExecPaths: []string{p}}
		if _, err := Merge(builtin, override); !errors.Is(err, ErrInvariantViolation) {
			t.Fatalf("allowing %s must violate invariant; got %v", p, err)
		}
	}
}

func TestMerge_StrictReadOnlyOR(t *testing.T) {
	builtin, _ := Builtin(protectedsvc.KindApache, protectedsvc.RolePHPModule) // strict=false
	if builtin.StrictReadOnly {
		t.Fatal("test setup: PHP module should be strict=false")
	}
	override := protectedsvc.ServiceContract{StrictReadOnly: true}
	merged, _ := Merge(builtin, override)
	if !merged.StrictReadOnly {
		t.Fatal("override true should flip strict on")
	}

	// And once strict in builtin (e.g. nginx static), can't be turned off via override:
	builtin2, _ := Builtin(protectedsvc.KindNginx, protectedsvc.RoleStatic) // strict=true
	override2 := protectedsvc.ServiceContract{StrictReadOnly: false}
	merged2, _ := Merge(builtin2, override2)
	if !merged2.StrictReadOnly {
		t.Fatal("override false must NOT turn off strict — operator can only tighten")
	}
}

func TestMerge_DedupesLists(t *testing.T) {
	builtin := protectedsvc.ServiceContract{}
	override := protectedsvc.ServiceContract{
		WriteRoots:    []string{"/tmp", "/tmp", "/var/log"},
		UpstreamCIDRs: []string{"10.0.0.0/8", "10.0.0.0/8"},
		ListenPorts:   []uint16{80, 80, 443},
	}
	merged, _ := Merge(builtin, override)
	if len(merged.WriteRoots) != 2 {
		t.Fatalf("dedupe WriteRoots: %v", merged.WriteRoots)
	}
	if len(merged.UpstreamCIDRs) != 1 {
		t.Fatalf("dedupe UpstreamCIDRs: %v", merged.UpstreamCIDRs)
	}
	if len(merged.ListenPorts) != 2 {
		t.Fatalf("dedupe ListenPorts: %v", merged.ListenPorts)
	}
}

func TestClassifyExecAttempt(t *testing.T) {
	cases := []struct {
		path, want string
	}{
		{"/bin/sh", "shell_attempt"},
		{"/bin/bash", "shell_attempt"},
		{"/usr/local/bin/zsh", "shell_attempt"},
		{"/usr/bin/python3", "interp_attempt"},
		{"/opt/perl5/bin/perl", "interp_attempt"},
		{"/usr/bin/curl", "downloader"},
		{"/usr/local/bin/wget", "downloader"},
		{"/usr/bin/nmap", "recon_tool"},
		{"/usr/bin/ncat", "recon_tool"},
		{"/usr/bin/sudo", "priv_tool"},
		{"/usr/bin/pkexec", "priv_tool"},
		{"/usr/bin/legitimate-helper", ""},
	}
	for _, tc := range cases {
		got := ClassifyExecAttempt(tc.path)
		if got != tc.want {
			t.Errorf("ClassifyExecAttempt(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestIsNeverLearnableHelpers(t *testing.T) {
	if !IsNeverLearnableExec("/bin/sh") {
		t.Fatal("IsNeverLearnableExec(/bin/sh) should be true")
	}
	if IsNeverLearnableExec("/usr/sbin/nginx") {
		t.Fatal("IsNeverLearnableExec(/usr/sbin/nginx) should be false")
	}
	if !IsNeverLearnableSyscall("ptrace") {
		t.Fatal("ptrace must be never-learnable")
	}
	if IsNeverLearnableSyscall("read") {
		t.Fatal("read must NOT be never-learnable")
	}
	if !IsNeverLearnableMemory(protectedsvc.MemAnonRWX) {
		t.Fatal("anon_rwx must be never-learnable")
	}
}

func assertContainsAllNeverLearnable(t *testing.T, label string, c protectedsvc.ServiceContract) {
	t.Helper()
	for _, p := range NeverLearnableExec {
		found := false
		for _, dp := range c.DenyExecPaths {
			if dp == p {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: DenyExecPaths missing never-learnable %q", label, p)
		}
	}
	for _, s := range NeverLearnableSyscalls {
		found := false
		for _, ds := range c.DenySyscalls {
			if ds == s {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: DenySyscalls missing never-learnable %q", label, s)
		}
	}
	for _, m := range NeverLearnableMemory {
		found := false
		for _, dm := range c.DenyMemoryPrimitives {
			if dm == m {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: DenyMemoryPrimitives missing never-learnable %q", label, m)
		}
	}
}
