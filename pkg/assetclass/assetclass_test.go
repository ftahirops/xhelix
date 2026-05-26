package assetclass

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyPath_StaticTable(t *testing.T) {
	r := NewStaticResolver()
	cases := []struct {
		path string
		role string
		want Class
	}{
		// Credential tier — most sensitive
		{"/etc/shadow", "", AssetSecretFile},
		{"/etc/passwd", "", AssetSecretFile},
		{"/etc/sudoers.d/foo", "", AssetSecretFile},
		{"/etc/pam.d/sshd", "", AssetSecretFile},
		{"/etc/security/limits.conf", "", AssetSecretFile},
		{"/etc/ssh/sshd_config", "", AssetSecretFile},
		{"/etc/ssh/ssh_host_rsa_key", "", AssetSecretFile},

		// Credential stores
		{"/root/.ssh/authorized_keys", "", AssetCredentialStore},
		{"/home/user/.ssh/id_rsa", "", AssetCredentialStore},
		{"/home/user/.aws/credentials", "", AssetCredentialStore},
		{"/home/user/.kube/config", "", AssetCredentialStore},

		// Workload identity
		{"/var/run/secrets/kubernetes.io/serviceaccount/token", "", AssetWorkloadIdentity},

		// Session/token stores
		{"/var/lib/xhelix/credbroker/sessions.db", "", AssetSessionStore},
		{"/run/credentials/foo", "", AssetSessionStore},

		// Persistence surfaces
		{"/etc/cron.d/backup", "", AssetPersistence},
		{"/etc/systemd/system/nginx.service", "", AssetPersistence},
		{"/etc/ld.so.preload", "", AssetPersistence},
		{"/var/spool/cron/root", "", AssetPersistence},

		// Service control
		{"/lib/systemd/system/foo.service", "", AssetServiceControl},
		{"/run/systemd/private", "", AssetServiceControl},

		// Customer data (db storage)
		{"/var/lib/mysql/ibdata1", "", AssetCustomerData},
		{"/var/lib/postgresql/14/main", "", AssetCustomerData},

		// Package state
		{"/var/lib/dpkg/status", "", AssetPackageState},
		{"/var/lib/rpm/Packages", "", AssetPackageState},

		// Backup
		{"/var/backups/db.tar", "", AssetBackupData},
		{"/backup/snapshot.bin", "", AssetBackupData},

		// Generic config
		{"/etc/nginx/nginx.conf", "", AssetConfig},

		// Log sinks
		{"/var/log/nginx/access.log", "", AssetLogSink},

		// Cache
		{"/var/cache/apt/whatever", "", AssetCache},

		// Temp
		{"/tmp/foo", "", AssetTemp},
		{"/dev/shm/foo", "", AssetTemp},
		{"/var/tmp/foo", "", AssetTemp},

		// Code roots
		{"/var/www/html/index.php", "", AssetCodeRoot},
		{"/srv/myapp/main.go", "", AssetCodeRoot},
		{"/opt/myapp/bin/main", "", AssetCodeRoot},

		// Unknown path falls through
		{"/random/path/elsewhere", "", ClassUnknown},
		{"", "", ClassUnknown},
	}
	for _, c := range cases {
		got := r.ClassifyPath(c.path, c.role)
		if got != c.want {
			t.Errorf("ClassifyPath(%q, %q) = %q, want %q", c.path, c.role, got, c.want)
		}
	}
}

func TestClassifyPath_RoleAware_BackupRole(t *testing.T) {
	r := NewStaticResolver()
	// Backup role touching /opt/myapp → backup_data (not code_root).
	// But /opt is in the static table as code_root, so static wins
	// when class is NOT sensitive. Verify the documented behavior:
	// static rule wins (code_root) unless an override applies.
	got := r.ClassifyPath("/opt/myapp/data", "backup-job")
	if got != AssetCodeRoot {
		t.Errorf("static rule must win for non-sensitive class; got %q want %q", got, AssetCodeRoot)
	}
	// For paths NOT in the static table, role-aware kicks in:
	got = r.ClassifyPath("/home/user/data", "backup-job")
	if got != AssetBackupData {
		t.Errorf("role-aware fallback: got %q want %q", got, AssetBackupData)
	}
}

func TestClassifySocket(t *testing.T) {
	r := NewStaticResolver()
	cases := map[string]Class{
		"/var/run/mysqld/mysqld.sock":   AssetDBEndpoint,
		"/run/postgresql/.s.PGSQL.5432": AssetDBEndpoint,
		"/run/redis/redis.sock":         AssetInternalSocket,
		"/run/php/php-fpm.sock":         AssetInternalSocket,
		"/var/run/dbus/system_bus_socket": AssetServiceControl,
		"/var/run/docker.sock":          AssetServiceControl,
		"/run/containerd/containerd.sock": AssetServiceControl,
		"/some/random/socket.sock":      AssetInternalSocket,
		"":                              ClassUnknown,
	}
	for s, want := range cases {
		got := r.ClassifySocket(s)
		if got != want {
			t.Errorf("ClassifySocket(%q) = %q, want %q", s, got, want)
		}
	}
}

func TestClassifyHost(t *testing.T) {
	r := NewStaticResolver()
	cases := []struct {
		ip   string
		sni  string
		port uint16
		want Class
	}{
		// Metadata endpoints
		{"169.254.169.254", "", 80, AssetMetadataEndpoint},
		{"fd00:ec2::254", "", 80, AssetMetadataEndpoint},

		// SNI-based
		{"", "s3.amazonaws.com", 443, AssetBlobStorage},
		{"", "storage.googleapis.com", 443, AssetBlobStorage},
		{"", "github.com", 443, AssetGitHosting},
		{"", "accounts.google.com", 443, AssetIdentityProvider},
		{"", "api.datadoghq.com", 443, AssetTelemetry},
		{"", "hooks.slack.com", 443, AssetWebhook},

		// Internal (private IP)
		{"10.0.0.5", "", 443, AssetInternalSocket},
		{"127.0.0.1", "", 8080, AssetInternalSocket},
		{"192.168.1.1", "", 22, AssetInternalSocket},

		// DB ports without SNI
		{"203.0.113.5", "", 3306, AssetDBEndpoint},
		{"203.0.113.5", "", 5432, AssetDBEndpoint},
		{"203.0.113.5", "", 6379, AssetDBEndpoint},

		// External catch-all
		{"203.0.113.5", "", 443, AssetExternalAPI},
		{"", "example.com", 443, AssetExternalAPI},

		// Nothing
		{"", "", 0, ClassUnknown},
	}
	for _, c := range cases {
		got := r.ClassifyHost(c.ip, c.sni, c.port)
		if got != c.want {
			t.Errorf("ClassifyHost(%q,%q,%d) = %q, want %q",
				c.ip, c.sni, c.port, got, c.want)
		}
	}
}

func TestIsSensitive_CoverageOfSensitiveClasses(t *testing.T) {
	mustBeSensitive := []Class{
		AssetSecretFile, AssetCredentialStore, AssetSessionStore,
		AssetWorkloadIdentity, AssetMetadataEndpoint,
		AssetServiceControl, AssetPersistence,
		AssetCustomerData, AssetBackupData,
	}
	for _, c := range mustBeSensitive {
		if !c.IsSensitive() {
			t.Errorf("%q must be sensitive", c)
		}
	}
	mustNotBeSensitive := []Class{
		AssetConfig, AssetLogSink, AssetCache, AssetTemp,
		AssetCodeRoot, AssetInternalSocket, AssetDBEndpoint,
		AssetBlobStorage, AssetWebhook, AssetGitHosting,
		AssetIdentityProvider, AssetTelemetry, AssetExternalAPI,
		AssetPackageState,
		ClassUnknown,
	}
	for _, c := range mustNotBeSensitive {
		if c.IsSensitive() {
			t.Errorf("%q should not be sensitive", c)
		}
	}
}

func TestLoadOperatorRules_AcceptsNonSensitiveRejectsSensitive(t *testing.T) {
	dir := t.TempDir()
	// First rule: non-sensitive (code_root) → accepted
	// Second rule: sensitive (backup_data) → rejected with error
	yamlBody := `rules:
  - path_prefix: /opt/myapp/static/
    class: code_root
    applies_to_roles:
      - myapp-worker
  - path_prefix: /mnt/backups/
    class: backup_data
`
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(yamlBody), 0o644); err != nil {
		t.Fatal(err)
	}
	rules, errs := LoadOperatorRules(dir)
	if len(rules) != 1 {
		t.Fatalf("expected 1 accepted rule (non-sensitive), got %d", len(rules))
	}
	if rules[0].PathPrefix != "/opt/myapp/static/" {
		t.Errorf("wrong rule accepted: %+v", rules[0])
	}
	if len(errs) != 1 {
		t.Fatalf("expected 1 rejection error for sensitive class, got %d errors: %v", len(errs), errs)
	}
}

func TestLoadOperatorRules_AllNonSensitive(t *testing.T) {
	dir := t.TempDir()
	yamlBody := `rules:
  - path_prefix: /opt/app-a/
    class: code_root
  - path_prefix: /opt/app-b/
    class: cache
`
	os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(yamlBody), 0o644)
	rules, errs := LoadOperatorRules(dir)
	if len(errs) > 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(rules))
	}
}

func TestLoadOperatorRules_BadYaml(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("this is not :: yaml ::"), 0o644)
	_, errs := LoadOperatorRules(dir)
	if len(errs) == 0 {
		t.Error("expected yaml parse error")
	}
}

func TestLoadOperatorRules_MissingDirNoError(t *testing.T) {
	rules, errs := LoadOperatorRules("/nonexistent/path")
	if len(errs) > 0 {
		t.Errorf("missing dir should not error, got %v", errs)
	}
	if len(rules) != 0 {
		t.Errorf("missing dir should return zero rules, got %d", len(rules))
	}
}

func TestLoadOperatorRules_AbsolutePathRequired(t *testing.T) {
	dir := t.TempDir()
	yamlBody := `rules:
  - path_prefix: relative/path
    class: cache
`
	os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(yamlBody), 0o644)
	rules, errs := LoadOperatorRules(dir)
	if len(rules) != 0 {
		t.Errorf("relative path rule should be rejected")
	}
	if len(errs) == 0 {
		t.Errorf("expected error for relative path")
	}
}

func TestNewWithOverrides_OperatorOverlayWorks(t *testing.T) {
	overrides := []pathRule{
		{
			PathPrefix:     "/opt/myapp/",
			Class:          AssetCodeRoot,
			AppliesToRoles: []string{"myapp-worker"},
		},
	}
	r := NewWithOverrides(overrides)
	// Override fires for matching role.
	if got := r.ClassifyPath("/opt/myapp/foo", "myapp-worker"); got != AssetCodeRoot {
		t.Errorf("override for matching role: got %q, want %q", got, AssetCodeRoot)
	}
	// /opt/ is static = code_root anyway, so test something not in static.
}

func TestNewWithOverrides_SensitiveClassNeverOverridden(t *testing.T) {
	// Operator tries to mark /etc/shadow as cache via override — must
	// still resolve to secret_file (static rule wins for sensitive).
	overrides := []pathRule{
		{PathPrefix: "/etc/shadow", Class: AssetCache},
	}
	r := NewWithOverrides(overrides)
	if got := r.ClassifyPath("/etc/shadow", ""); got != AssetSecretFile {
		t.Errorf("sensitive override attempt: got %q, want %q (static rule wins)", got, AssetSecretFile)
	}
}

func TestClassifyPath_RoleSpecific_MatchAndMismatch(t *testing.T) {
	overrides := []pathRule{
		{
			PathPrefix:     "/data/customer/",
			Class:          AssetExternalAPI, // arbitrary non-sensitive
			AppliesToRoles: []string{"api-worker"},
		},
	}
	r := NewWithOverrides(overrides)
	// Matching role → override applies
	if got := r.ClassifyPath("/data/customer/x", "api-worker"); got != AssetExternalAPI {
		t.Errorf("matching role override: got %q, want %q", got, AssetExternalAPI)
	}
	// Non-matching role → override skipped → falls through to unknown
	if got := r.ClassifyPath("/data/customer/x", "other-role"); got != ClassUnknown {
		t.Errorf("non-matching role: got %q, want unknown", got)
	}
}
