package decoyfs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xhelix/xhelix/pkg/deception/execroute"
	"github.com/xhelix/xhelix/pkg/protectedsvc"
)

func testSpec(t *testing.T) Spec {
	t.Helper()
	return Spec{
		Secret:            []byte("test-secret-deterministic-32bytes"),
		HoneyUser:         "deploy",
		IncludeRealRSAKey: false, // cheap path for tests
	}
}

func TestGenerate_Deterministic(t *testing.T) {
	spec := testSpec(t)
	a, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	if a.Shadow != b.Shadow || a.Passwd != b.Passwd ||
		a.AWSCreds != b.AWSCreds || a.SSHKey != b.SSHKey {
		t.Fatal("Generate must be deterministic for the same Spec")
	}
}

func TestGenerate_DifferentSecretDifferentDecoys(t *testing.T) {
	a, _ := Generate(Spec{Secret: []byte("AAAAAAAAAAAAAAAA"), HoneyUser: "deploy"})
	b, _ := Generate(Spec{Secret: []byte("BBBBBBBBBBBBBBBB"), HoneyUser: "deploy"})
	if a.Shadow == b.Shadow {
		t.Fatal("different secrets must produce different decoys")
	}
}

func TestGenerate_RequiresSecret(t *testing.T) {
	if _, err := Generate(Spec{Secret: []byte("short")}); err == nil {
		t.Fatal("short secret should be rejected")
	}
}

func TestShadow_HasYescryptHashesForRealUsers(t *testing.T) {
	s, _ := Generate(testSpec(t))
	mustContain(t, s.Shadow,
		"root:$y$j9T$",
		"ubuntu:$y$j9T$",
		"deploy:$y$j9T$",
		"daemon:*:",
		":19700:0:99999:7:::",
	)
}

func TestPasswd_HasHoneyUser(t *testing.T) {
	s, _ := Generate(testSpec(t))
	if !strings.Contains(s.Passwd, "deploy:x:1001:1001:Deploy User:/home/deploy:/bin/bash") {
		t.Fatalf("passwd missing honey user: %s", s.Passwd)
	}
}

func TestSudoers_HoneyUserHasNOPASSWD(t *testing.T) {
	s, _ := Generate(testSpec(t))
	if !strings.Contains(s.Sudoers, "deploy") || !strings.Contains(s.Sudoers, "NOPASSWD") {
		t.Fatalf("sudoers missing honey NOPASSWD entry: %s", s.Sudoers)
	}
}

func TestAWS_RealisticKeyFormat(t *testing.T) {
	s, _ := Generate(testSpec(t))
	if !strings.Contains(s.AWSCreds, "aws_access_key_id = AKIA") {
		t.Fatalf("AWS creds missing AKIA-prefixed key: %s", s.AWSCreds)
	}
	if !strings.Contains(s.AWSCreds, "aws_secret_access_key = ") {
		t.Fatal("AWS creds missing secret key")
	}
	if !strings.Contains(s.AWSCreds, "[default]") || !strings.Contains(s.AWSCreds, "[production]") {
		t.Fatal("AWS creds missing standard profile names")
	}
}

func TestGCPCreds_ServiceAccountShape(t *testing.T) {
	s, _ := Generate(testSpec(t))
	mustContain(t, s.GCPCreds,
		`"type": "service_account"`,
		`"client_email":`,
		`"private_key_id":`,
		`-----BEGIN PRIVATE KEY-----`,
	)
}

func TestKubeConfig_RealisticShape(t *testing.T) {
	s, _ := Generate(testSpec(t))
	mustContain(t, s.KubeConfig,
		"apiVersion: v1",
		"current-context: deploy@prod",
		"token:",
	)
}

func TestDockerCfg_AuthMap(t *testing.T) {
	s, _ := Generate(testSpec(t))
	if !strings.Contains(s.DockerCfg, "registry.internal:5000") {
		t.Fatal("docker config missing internal registry")
	}
}

func TestSSHKey_PEMFormat(t *testing.T) {
	s, _ := Generate(testSpec(t))
	if !strings.HasPrefix(s.SSHKey, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Fatalf("ssh key bad PEM header: %s", s.SSHKey[:80])
	}
	if !strings.Contains(s.SSHKey, "-----END RSA PRIVATE KEY-----") {
		t.Fatal("ssh key missing PEM footer")
	}
	if !strings.HasPrefix(s.SSHPubKey, "ssh-rsa ") {
		t.Fatal("ssh pubkey not ssh-rsa format")
	}
}

func TestSSHKey_RealRSAOptIn(t *testing.T) {
	spec := testSpec(t)
	spec.IncludeRealRSAKey = true
	s, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	// Real RSA key should be a valid PEM that PARSES — quick sanity.
	if !strings.Contains(s.SSHKey, "MII") {
		// MII prefix on PKCS1 RSA private keys (DER seq tag 0x30 0x82).
		t.Fatalf("real RSA key body doesn't look like PKCS1: %s", s.SSHKey[:80])
	}
}

// --- Install / Layout tests ---

func TestInstall_WritesAllFiles(t *testing.T) {
	dir := t.TempDir()
	s, _ := Generate(testSpec(t))
	files, err := Install(s, InstallOpts{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 9 {
		t.Fatalf("expected 9 decoy files, got %d", len(files))
	}
	for _, f := range files {
		if !strings.HasPrefix(f.Source, dir) {
			t.Errorf("source %q not under dir %q", f.Source, dir)
		}
		info, err := os.Stat(f.Source)
		if err != nil {
			t.Errorf("decoy %q not written: %v", f.Source, err)
			continue
		}
		if info.Mode().Perm() != f.Mode.Perm() {
			t.Errorf("decoy %q mode=%o want %o", f.Source, info.Mode().Perm(), f.Mode.Perm())
		}
	}
}

func TestInstall_TargetPathsMatchExpectation(t *testing.T) {
	dir := t.TempDir()
	s, _ := Generate(testSpec(t))
	files, _ := Install(s, InstallOpts{Dir: dir})
	targets := map[string]bool{}
	for _, f := range files {
		targets[f.Target] = true
	}
	for _, must := range []string{
		"/etc/shadow", "/etc/passwd", "/etc/sudoers",
		"/home/deploy/.ssh/id_rsa", "/home/deploy/.aws/credentials",
		"/home/deploy/.kube/config", "/home/deploy/.docker/config.json",
	} {
		if !targets[must] {
			t.Errorf("target %q missing from File list", must)
		}
	}
}

func TestInstall_Idempotent(t *testing.T) {
	dir := t.TempDir()
	s, _ := Generate(testSpec(t))
	_, _ = Install(s, InstallOpts{Dir: dir})

	// Capture mtime of one decoy
	shadowPath := filepath.Join(dir, "shadow")
	info1, err := os.Stat(shadowPath)
	if err != nil {
		t.Fatal(err)
	}

	// Re-install — content unchanged, so no rewrite.
	_, err = Install(s, InstallOpts{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	info2, err := os.Stat(shadowPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info1.ModTime().Equal(info2.ModTime()) {
		t.Fatal("second Install should be no-op (mtime should not change)")
	}
}

func TestInstall_OverwritesOnContentChange(t *testing.T) {
	dir := t.TempDir()
	specA := testSpec(t)
	specA.Secret = []byte("AAAAAAAAAAAAAAAAA")
	setA, _ := Generate(specA)
	_, _ = Install(setA, InstallOpts{Dir: dir})

	specB := testSpec(t)
	specB.Secret = []byte("BBBBBBBBBBBBBBBBB")
	setB, _ := Generate(specB)
	_, _ = Install(setB, InstallOpts{Dir: dir})

	body, err := os.ReadFile(filepath.Join(dir, "shadow"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != setB.Shadow {
		t.Fatal("re-Install with different content should overwrite")
	}
}

// --- MountSpec / drop-in merge ---

func TestMountSpec_SortedByTarget(t *testing.T) {
	files := []File{
		{Source: "/v/x", Target: "/zzz/last"},
		{Source: "/v/y", Target: "/etc/shadow"},
		{Source: "/v/z", Target: "/aaa/first"},
	}
	mounts := MountSpec(files)
	if mounts[0].Target != "/aaa/first" || mounts[1].Target != "/etc/shadow" || mounts[2].Target != "/zzz/last" {
		t.Fatalf("MountSpec not sorted: %+v", mounts)
	}
}

func TestMergeIntoDropIn_AddsDecoyLines(t *testing.T) {
	d := execroute.SystemdDropIn{
		UnitName: "nginx.service",
		Path:     "/etc/systemd/system/nginx.service.d/xhelix-deception.conf",
		Body: "[Service]\nPrivateMounts=yes\nBindReadOnlyPaths=/usr/lib/xhelix/honey-sh:/bin/sh:norbind\n",
		Mounts: []execroute.BindMount{
			{Source: "/usr/lib/xhelix/honey-sh", Target: "/bin/sh"},
		},
	}
	files := []File{
		{Source: "/var/lib/xhelix/decoys/shadow", Target: "/etc/shadow"},
		{Source: "/var/lib/xhelix/decoys/aws", Target: "/home/deploy/.aws/credentials"},
	}
	merged, err := MergeIntoDropIn(d, files)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, merged.Body,
		"BindReadOnlyPaths=/usr/lib/xhelix/honey-sh:/bin/sh:norbind",
		"BindReadOnlyPaths=/var/lib/xhelix/decoys/shadow:/etc/shadow:norbind",
		"BindReadOnlyPaths=/var/lib/xhelix/decoys/aws:/home/deploy/.aws/credentials:norbind",
		"# decoyfs bind-mounts",
	)
	if len(merged.Mounts) != 3 {
		t.Fatalf("merged mounts=%d want 3", len(merged.Mounts))
	}
}

func TestMergeIntoDropIn_IdempotentSkipDuplicates(t *testing.T) {
	d := execroute.SystemdDropIn{
		UnitName: "nginx.service",
		Body:     "[Service]\nBindReadOnlyPaths=/var/lib/xhelix/decoys/shadow:/etc/shadow:norbind\n",
		Mounts:   []execroute.BindMount{{Source: "/var/lib/xhelix/decoys/shadow", Target: "/etc/shadow"}},
	}
	files := []File{{Source: "/var/lib/xhelix/decoys/shadow", Target: "/etc/shadow"}}
	merged, _ := MergeIntoDropIn(d, files)
	if strings.Count(merged.Body, "/etc/shadow") != 1 {
		t.Fatalf("duplicate target should not be added again:\n%s", merged.Body)
	}
}

func TestAttachToService_DeceptionOffNoOp(t *testing.T) {
	svc := &protectedsvc.ProtectedService{
		Name: "x", Kind: protectedsvc.KindNginx, Role: protectedsvc.RoleStatic,
		ExecPath: "/usr/sbin/nginx", Unit: "nginx.service",
	}
	svc.Response.Deception = protectedsvc.AllOff()

	set, _ := Generate(testSpec(t))
	originalDropIn := execroute.SystemdDropIn{UnitName: "nginx.service", Body: "original"}
	out, files, err := AttachToService(svc, set, originalDropIn, InstallOpts{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if out.Body != "original" || files != nil {
		t.Fatalf("deception=off should be no-op")
	}
}

func TestAttachToService_HappyPath(t *testing.T) {
	svc := &protectedsvc.ProtectedService{
		Name: "nginx-main", Kind: protectedsvc.KindNginx, Role: protectedsvc.RoleStatic,
		ExecPath: "/usr/sbin/nginx", Unit: "nginx.service",
	}
	svc.Response.Deception = protectedsvc.AllOn()

	set, _ := Generate(testSpec(t))
	dropIn := execroute.SystemdDropIn{
		UnitName: "nginx.service",
		Body:     "[Service]\nPrivateMounts=yes\n",
	}
	dir := t.TempDir()
	out, files, err := AttachToService(svc, set, dropIn, InstallOpts{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 9 {
		t.Fatalf("expected 9 decoys installed, got %d", len(files))
	}
	mustContain(t, out.Body,
		"BindReadOnlyPaths=", "/etc/shadow", "/etc/passwd",
		"/home/deploy/.ssh/id_rsa",
		"/home/deploy/.aws/credentials",
	)
}

func mustContain(t *testing.T, body string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(body, n) {
			t.Errorf("missing %q", n)
		}
	}
}
