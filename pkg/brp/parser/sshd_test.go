package brpparser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSSHD_Defaults(t *testing.T) {
	// Empty/minimal config: default port 22 + pubkey_auth.
	path := writeTmp(t, "sshd_config", `# minimal config
`)
	b, k, err := ParseSSHD(path)
	if err != nil {
		t.Fatalf("ParseSSHD: %v", err)
	}
	if !containsInt(b.ListenPorts, 22) {
		t.Errorf("default port 22 should be implied: %v", b.ListenPorts)
	}
	if !contains(b.Features, "pubkey_auth") {
		t.Errorf("default pubkey_auth expected: %v", b.Features)
	}
	if k.App != "sshd" {
		t.Errorf("App = %q, want sshd", k.App)
	}
}

func TestSSHD_Hardened(t *testing.T) {
	conf := `
Port 22000
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AllowUsers alice
AllowTcpForwarding no
X11Forwarding no
ChallengeResponseAuthentication no
`
	path := writeTmp(t, "sshd_config", conf)
	b, _, _ := ParseSSHD(path)
	if !containsInt(b.ListenPorts, 22000) {
		t.Errorf("custom port 22000 missing: %v", b.ListenPorts)
	}
	if !contains(b.Features, "deny_root_login") {
		t.Errorf("deny_root_login feature expected: %v", b.Features)
	}
	if !contains(b.Features, "pubkey_auth") {
		t.Errorf("pubkey_auth feature expected: %v", b.Features)
	}
	if contains(b.Features, "password_auth") {
		t.Errorf("password_auth should NOT be set: %v", b.Features)
	}
	if b.Role != "sshd-hardened" {
		t.Errorf("Role = %q, want sshd-hardened", b.Role)
	}
}

func TestSSHD_Permissive(t *testing.T) {
	conf := `
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
`
	path := writeTmp(t, "sshd_config", conf)
	b, _, _ := ParseSSHD(path)
	if !contains(b.Features, "permit_root_login") {
		t.Errorf("permit_root_login expected: %v", b.Features)
	}
	if !contains(b.Features, "password_auth") {
		t.Errorf("password_auth expected: %v", b.Features)
	}
	if !contains(b.Features, "empty_passwords") {
		t.Errorf("empty_passwords feature expected: %v", b.Features)
	}
	if b.Role != "sshd-permissive" {
		t.Errorf("Role = %q, want sshd-permissive", b.Role)
	}
	if len(b.ParseWarnings) == 0 {
		t.Error("PermitEmptyPasswords yes should produce a warning")
	}
}

func TestSSHD_SFTPChroot(t *testing.T) {
	conf := `
Subsystem sftp /usr/lib/openssh/sftp-server
Match Group sftponly
    ChrootDirectory /var/sftp/%u
    ForceCommand internal-sftp
    AllowTcpForwarding no
`
	path := writeTmp(t, "sshd_config", conf)
	b, _, _ := ParseSSHD(path)
	if !contains(b.Features, "subsystem_sftp") {
		t.Errorf("subsystem_sftp feature expected: %v", b.Features)
	}
	if !contains(b.Features, "chroot") {
		t.Errorf("chroot feature expected: %v", b.Features)
	}
	if !contains(b.Features, "match_block") {
		t.Errorf("match_block feature expected: %v", b.Features)
	}
	if !contains(b.ExecAllowed, "/usr/lib/openssh/sftp-server") {
		t.Errorf("sftp-server should be in ExecAllowed: %v", b.ExecAllowed)
	}
	if b.Role != "sshd-sftp-chroot" {
		t.Errorf("Role = %q, want sshd-sftp-chroot", b.Role)
	}
}

func TestSSHD_Jumphost(t *testing.T) {
	conf := `
Port 22
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication no
AllowTcpForwarding yes
GatewayPorts yes
`
	path := writeTmp(t, "sshd_config", conf)
	b, _, _ := ParseSSHD(path)
	if b.Role != "sshd-jumphost" {
		t.Errorf("Role = %q, want sshd-jumphost", b.Role)
	}
	if !contains(b.Features, "tcp_forwarding") {
		t.Errorf("tcp_forwarding expected: %v", b.Features)
	}
	if !contains(b.Features, "gateway_ports") {
		t.Errorf("gateway_ports expected: %v", b.Features)
	}
}

func TestSSHD_AuthorizedKeysFileReadRoots(t *testing.T) {
	conf := `
AuthorizedKeysFile %h/.ssh/authorized_keys .ssh/authorized_keys2
`
	path := writeTmp(t, "sshd_config", conf)
	b, _, _ := ParseSSHD(path)
	// "%h/.ssh/authorized_keys" → after stripping %h → "/.ssh" then dir
	// just becomes ".ssh" — we record it as a relative-path hint.
	found := false
	for _, r := range b.ReadRoots {
		if r == "/.ssh/" || r == ".ssh/" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an authorized_keys directory hint, got: %v", b.ReadRoots)
	}
}

func TestSSHD_AuthorizedKeysCommand(t *testing.T) {
	conf := `
AuthorizedKeysCommand /usr/local/bin/lookup-keys
AuthorizedKeysCommandUser nobody
`
	path := writeTmp(t, "sshd_config", conf)
	b, _, _ := ParseSSHD(path)
	if !contains(b.Features, "authorizedkeyscommand") {
		t.Errorf("authorizedkeyscommand feature expected: %v", b.Features)
	}
	if !contains(b.ExecAllowed, "/usr/local/bin/lookup-keys") {
		t.Errorf("AuthorizedKeysCommand should be in ExecAllowed: %v", b.ExecAllowed)
	}
}

func TestSSHD_Include(t *testing.T) {
	tmp := t.TempDir()
	extra := filepath.Join(tmp, "extra.conf")
	_ = os.WriteFile(extra, []byte("Port 2222\n"), 0o644)
	main := filepath.Join(tmp, "sshd_config")
	_ = os.WriteFile(main, []byte("Include "+extra+"\nPort 22\n"), 0o644)
	b, _, err := ParseSSHD(main)
	if err != nil {
		t.Fatalf("ParseSSHD: %v", err)
	}
	if !containsInt(b.ListenPorts, 22) || !containsInt(b.ListenPorts, 2222) {
		t.Errorf("expected both 22 and 2222: %v", b.ListenPorts)
	}
}

func TestSSHD_KeyEqualsValueForm(t *testing.T) {
	// sshd_config tolerates Key=Value form.
	conf := `Port=2200
PermitRootLogin=no
`
	path := writeTmp(t, "sshd_config", conf)
	b, _, _ := ParseSSHD(path)
	if !containsInt(b.ListenPorts, 2200) {
		t.Errorf("Key=Value form should parse: %v", b.ListenPorts)
	}
	if !contains(b.Features, "deny_root_login") {
		t.Errorf("Key=Value PermitRootLogin=no expected: %v", b.Features)
	}
}
