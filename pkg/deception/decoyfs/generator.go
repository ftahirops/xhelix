// Package decoyfs generates and installs decoy files for Ring 2.
// Sensitive paths attackers love (/etc/shadow, /etc/sudoers,
// ~/.ssh/id_rsa, ~/.aws/credentials, ...) get overlaid with
// watermarked-but-realistic-looking fakes inside the protected
// service's mount namespace.
//
// Same systemd PrivateMounts + BindReadOnlyPaths machinery as
// P-PS.6b. The decoys are pre-generated once per host at install
// time (deterministic from a host secret so re-runs produce the
// SAME files — attackers re-reading don't see contradictions).
//
// Pure Go, CGO_ENABLED=0. See PROTECTED_SERVICES_TRAP.md §4.3.
package decoyfs

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Set is the bundle of decoys we generate per host. Each field is
// the rendered file content; Install() writes them to disk.
type Set struct {
	Shadow      string // /etc/shadow decoy
	Passwd      string // /etc/passwd decoy
	Sudoers     string // /etc/sudoers decoy
	SSHKey      string // ~/<honey-user>/.ssh/id_rsa (real PEM, real key, never used for anything real)
	SSHPubKey   string // matching public key
	AWSCreds    string // ~/<honey-user>/.aws/credentials (canary-shaped)
	GCPCreds    string // ~/<honey-user>/.config/gcloud/credentials.db (canary-shaped JSON)
	KubeConfig  string // ~/<honey-user>/.kube/config (canary-shaped)
	DockerCfg   string // ~/<honey-user>/.docker/config.json (canary-shaped)

	// HoneyUser is the username that appears across the decoys —
	// stable per-host. Attacker who exfiltrates "deploy:NOPASSWD ALL"
	// will use the username we picked.
	HoneyUser string
}

// Spec controls Generate(). Provide a stable secret across runs so
// re-generation produces identical files. Random Secret → fresh
// decoys (operator-triggered "rotate decoys" workflow).
type Spec struct {
	// Secret is HMAC-seeded into every deterministic generator. 32
	// random bytes recommended. Persist this in /var/lib/xhelix/
	// alongside the daemon's other secrets.
	Secret []byte

	// HoneyUser overrides the default honey-username. Empty = derive
	// from Secret. (Stable per-host.)
	HoneyUser string

	// IncludeRealRSAKey: if true, Generate() will produce a real
	// 2048-bit RSA private key (~200ms cost). If false, ships a
	// PEM-formatted decoy that LOOKS like a real key but isn't a
	// valid private key (cheap; tests use this). Defaults true.
	IncludeRealRSAKey bool
}

// Generate builds a Set from the spec. Deterministic given the same
// Secret EXCEPT for the RSA key when IncludeRealRSAKey=true (the
// key derives from a separate crypto/rand call — making it
// deterministic would require shipping a fixed key, which is worse).
func Generate(spec Spec) (Set, error) {
	if len(spec.Secret) < 16 {
		return Set{}, errors.New("decoyfs: Secret must be ≥16 bytes")
	}
	honeyUser := spec.HoneyUser
	if honeyUser == "" {
		honeyUser = pickHoneyUser(spec.Secret)
	}

	s := Set{HoneyUser: honeyUser}
	s.Passwd = renderPasswd(spec.Secret, honeyUser)
	s.Shadow = renderShadow(spec.Secret, honeyUser)
	s.Sudoers = renderSudoers(honeyUser)
	s.AWSCreds = renderAWSCreds(spec.Secret)
	s.GCPCreds = renderGCPCreds(spec.Secret)
	s.KubeConfig = renderKubeConfig(spec.Secret)
	s.DockerCfg = renderDockerCfg(spec.Secret)

	if spec.IncludeRealRSAKey {
		priv, pub, err := generateRSAKeyPair()
		if err != nil {
			return Set{}, fmt.Errorf("decoyfs: rsa keygen: %w", err)
		}
		s.SSHKey = priv
		s.SSHPubKey = pub
	} else {
		s.SSHKey = decoyPEMKey(spec.Secret)
		s.SSHPubKey = decoySSHPubKey(spec.Secret)
	}
	return s, nil
}

// --- per-file generators ---

func renderPasswd(secret []byte, honey string) string {
	return strings.Join([]string{
		`root:x:0:0:root:/root:/bin/bash`,
		`daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin`,
		`bin:x:2:2:bin:/bin:/usr/sbin/nologin`,
		`sys:x:3:3:sys:/dev:/usr/sbin/nologin`,
		`sync:x:4:65534:sync:/bin:/bin/sync`,
		`www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin`,
		`nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin`,
		`systemd-network:x:998:998:systemd Network:/:/usr/sbin/nologin`,
		`ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash`,
		fmt.Sprintf(`%s:x:1001:1001:Deploy User:/home/%s:/bin/bash`, honey, honey),
		"",
	}, "\n")
}

// renderShadow produces yescrypt-formatted hashes. The hash bytes
// are HMAC-derived from secret + username so they look random but
// stable. NOT crackable to anything useful — these are honey.
func renderShadow(secret []byte, honey string) string {
	mkHash := func(user string) string {
		salt := deriveBase64(secret, []byte("salt/"+user), 16)
		body := deriveBase64(secret, []byte("body/"+user), 31)
		return "$y$j9T$" + salt + "$" + body
	}
	lines := []string{
		"root:" + mkHash("root") + ":19700:0:99999:7:::",
		`daemon:*:19700:0:99999:7:::`,
		`bin:*:19700:0:99999:7:::`,
		`sys:*:19700:0:99999:7:::`,
		`www-data:*:19700:0:99999:7:::`,
		"ubuntu:" + mkHash("ubuntu") + ":19700:0:99999:7:::",
		honey + ":" + mkHash(honey) + ":19700:0:99999:7:::",
		"",
	}
	return strings.Join(lines, "\n")
}

func renderSudoers(honey string) string {
	return strings.Join([]string{
		`# This file MUST be edited with the 'visudo' command as root.`,
		`Defaults env_reset`,
		`Defaults mail_badpass`,
		`Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"`,
		``,
		`root    ALL=(ALL:ALL) ALL`,
		fmt.Sprintf(`%-7s ALL=(ALL:ALL) NOPASSWD: ALL`, honey),
		`%admin  ALL=(ALL) ALL`,
		`%sudo   ALL=(ALL:ALL) ALL`,
		``,
	}, "\n")
}

// AWS keys: real format is "AKIA" + 16 uppercase alphanumerics for
// access key, 40 base64-alphabet chars for secret. Format-correct
// keys but completely fake (won't authenticate to AWS).
// If a future canary-token integration plugs in, these keys can be
// registered with canarytokens so any use anywhere alerts us.
func renderAWSCreds(secret []byte) string {
	access := "AKIA" + strings.ToUpper(deriveAlpha(secret, []byte("aws-access"), 16))
	secretKey := deriveAlpha(secret, []byte("aws-secret"), 40)
	return fmt.Sprintf(`[default]
aws_access_key_id = %s
aws_secret_access_key = %s
region = us-east-1
output = json

[production]
aws_access_key_id = %s
aws_secret_access_key = %s
region = us-east-1
`, access, secretKey,
		"AKIA"+strings.ToUpper(deriveAlpha(secret, []byte("aws-access-prod"), 16)),
		deriveAlpha(secret, []byte("aws-secret-prod"), 40))
}

func renderGCPCreds(secret []byte) string {
	id := deriveHex(secret, []byte("gcp-client-id"), 8)
	keyID := deriveHex(secret, []byte("gcp-key-id"), 20)
	return fmt.Sprintf(`{
  "type": "service_account",
  "project_id": "prod-deploy-%s",
  "private_key_id": "%s",
  "private_key": "-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----\n",
  "client_email": "deploy@prod-deploy-%s.iam.gserviceaccount.com",
  "client_id": "%s",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token"
}
`, id, keyID,
		deriveBase64(secret, []byte("gcp-priv"), 256), id,
		deriveHex(secret, []byte("gcp-cid"), 11))
}

func renderKubeConfig(secret []byte) string {
	tok := deriveBase64(secret, []byte("kube-token"), 48)
	return fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://k8s-prod.internal:6443
    certificate-authority-data: %s
  name: prod
contexts:
- context:
    cluster: prod
    user: deploy
  name: deploy@prod
current-context: deploy@prod
users:
- name: deploy
  user:
    token: %s
`, deriveBase64(secret, []byte("kube-ca"), 1024), tok)
}

func renderDockerCfg(secret []byte) string {
	tok := deriveBase64(secret, []byte("docker-auth"), 64)
	return fmt.Sprintf(`{
  "auths": {
    "registry.internal:5000": {
      "auth": "%s",
      "email": "deploy@internal"
    },
    "https://index.docker.io/v1/": {
      "auth": "%s"
    }
  }
}
`, tok, deriveBase64(secret, []byte("docker-hub"), 64))
}

// --- RSA + SSH key helpers ---

func generateRSAKeyPair() (privPEM, pubSSH string, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	privDER := x509.MarshalPKCS1PrivateKey(priv)
	privPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	}))
	pubSSH = "ssh-rsa " + marshalSSHPub(&priv.PublicKey) + " deploy@webhost\n"
	return privPEM, pubSSH, nil
}

// marshalSSHPub returns the base64 ssh-rsa public key body. This is
// a minimal implementation of the SSH wire format (RFC 4253 §6.6).
func marshalSSHPub(pub *rsa.PublicKey) string {
	// SSH wire format: <len32><"ssh-rsa"> <len32><e> <len32><N>
	algo := []byte("ssh-rsa")
	e := pub.E
	eBytes := bigIntToSSHBytes(int64ToBytes(int64(e)))
	nBytes := bigIntToSSHBytes(pub.N.Bytes())

	var buf []byte
	buf = append(buf, lenPrefix(algo)...)
	buf = append(buf, lenPrefix(eBytes)...)
	buf = append(buf, lenPrefix(nBytes)...)
	return base64Encode(buf)
}

// bigIntToSSHBytes ensures the high bit is unset (RFC 4251 §5
// mpint encoding). If the top byte has bit 7 set, prepend 0x00.
func bigIntToSSHBytes(b []byte) []byte {
	if len(b) > 0 && b[0]&0x80 != 0 {
		return append([]byte{0}, b...)
	}
	return b
}

func int64ToBytes(n int64) []byte {
	var out []byte
	for n > 0 {
		out = append([]byte{byte(n & 0xff)}, out...)
		n >>= 8
	}
	if len(out) == 0 {
		out = []byte{0}
	}
	return out
}

func lenPrefix(b []byte) []byte {
	n := uint32(len(b))
	return append([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, b...)
}

// decoyPEMKey returns a PEM-formatted blob that LOOKS like an RSA
// private key but is just deterministic random bytes. Cheap; used
// when IncludeRealRSAKey=false (tests).
func decoyPEMKey(secret []byte) string {
	body := deriveBase64(secret, []byte("ssh-priv"), 1192)
	// Wrap to 64-char lines like real PEM.
	var b strings.Builder
	b.WriteString("-----BEGIN RSA PRIVATE KEY-----\n")
	for i := 0; i < len(body); i += 64 {
		end := i + 64
		if end > len(body) {
			end = len(body)
		}
		b.WriteString(body[i:end])
		b.WriteString("\n")
	}
	b.WriteString("-----END RSA PRIVATE KEY-----\n")
	return b.String()
}

func decoySSHPubKey(secret []byte) string {
	body := deriveBase64(secret, []byte("ssh-pub"), 372)
	return "ssh-rsa " + body + " deploy@webhost\n"
}

// --- HMAC-based derivation ---

func deriveAlpha(secret, info []byte, n int) string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, n)
	stream := hmacExpand(secret, info, n)
	for i := range out {
		out[i] = alpha[int(stream[i])%len(alpha)]
	}
	return string(out)
}

func deriveBase64(secret, info []byte, n int) string {
	// base64-alphabet output of length n.
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	out := make([]byte, n)
	stream := hmacExpand(secret, info, n)
	for i := range out {
		out[i] = alpha[int(stream[i])%64]
	}
	return string(out)
}

func deriveHex(secret, info []byte, n int) string {
	stream := hmacExpand(secret, info, n)
	return hex.EncodeToString(stream)[:n]
}

// hmacExpand returns n bytes derived from HMAC-SHA256(secret, info)
// using a counter-mode expansion.
func hmacExpand(secret, info []byte, n int) []byte {
	out := make([]byte, 0, n)
	counter := 0
	for len(out) < n {
		h := hmac.New(sha256.New, secret)
		h.Write(info)
		h.Write([]byte{byte(counter)})
		out = append(out, h.Sum(nil)...)
		counter++
	}
	return out[:n]
}

// base64Encode without padding — for SSH wire format.
func base64Encode(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out strings.Builder
	for i := 0; i+3 <= len(b); i += 3 {
		v := uint(b[i])<<16 | uint(b[i+1])<<8 | uint(b[i+2])
		out.WriteByte(alphabet[(v>>18)&0x3F])
		out.WriteByte(alphabet[(v>>12)&0x3F])
		out.WriteByte(alphabet[(v>>6)&0x3F])
		out.WriteByte(alphabet[v&0x3F])
	}
	switch len(b) % 3 {
	case 1:
		v := uint(b[len(b)-1]) << 16
		out.WriteByte(alphabet[(v>>18)&0x3F])
		out.WriteByte(alphabet[(v>>12)&0x3F])
		out.WriteString("==")
	case 2:
		v := uint(b[len(b)-2])<<16 | uint(b[len(b)-1])<<8
		out.WriteByte(alphabet[(v>>18)&0x3F])
		out.WriteByte(alphabet[(v>>12)&0x3F])
		out.WriteByte(alphabet[(v>>6)&0x3F])
		out.WriteByte('=')
	}
	return out.String()
}

func pickHoneyUser(secret []byte) string {
	options := []string{"deploy", "build", "release", "ops", "ci"}
	stream := hmacExpand(secret, []byte("honey-user"), 1)
	return options[int(stream[0])%len(options)]
}
