// Package decoy implements xhelix's honeypot sensor plane.
//
// Decoys turn the *absence* of legitimate access into a high-signal
// detection: a hit on a honey file, service, DNS name, or canary
// token is by definition malicious. Phase 3 ships:
//
//   - HoneyFiles — files watched for any open
//   - HoneyServices — fake TCP services that capture connections
//   - CanaryReceiver — webhook that fires when an embedded token leaks
//   - HoneyDNS — planted internal-looking hostnames; resolution alerts
package decoy

// Persona is a curated honey-file template with a believable shape.
type Persona struct {
	Name        string
	DefaultPath string
	Render      func(token string) []byte
}

// Personas returns the bundled honey-file shapes.
func Personas() []Persona {
	return []Persona{
		{
			Name:        "aws-creds",
			DefaultPath: "/root/.aws/credentials.bak",
			Render: func(token string) []byte {
				return []byte(
					"# AWS readonly credentials, do not share\n" +
						"[default]\n" +
						"aws_access_key_id = AKIA" + token + "\n" +
						"aws_secret_access_key = " + token + "FAKE\n" +
						"region = us-east-1\n")
			},
		},
		{
			Name:        "ssh-key",
			DefaultPath: "/root/.ssh/id_rsa.bak",
			Render: func(token string) []byte {
				return []byte(
					"-----BEGIN OPENSSH PRIVATE KEY-----\n" +
						"# canary fingerprint: " + token + "\n" +
						"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdz\n" +
						"c2gtcnNhAAAAAwEAAQAAAQEA" + token + "==\n" +
						"-----END OPENSSH PRIVATE KEY-----\n")
			},
		},
		{
			Name:        "kube-config",
			DefaultPath: "/root/.kube/config.bak",
			Render: func(token string) []byte {
				return []byte(
					"apiVersion: v1\n" +
						"kind: Config\n" +
						"current-context: prod\n" +
						"clusters:\n" +
						"- cluster:\n" +
						"    server: https://k8s-prod.internal:6443\n" +
						"  name: prod\n" +
						"users:\n" +
						"- name: admin\n" +
						"  user:\n" +
						"    token: " + token + "\n")
			},
		},
		{
			Name:        "passwd-list",
			DefaultPath: "/root/credentials.txt",
			Render: func(token string) []byte {
				return []byte(
					"# Internal credentials, do not commit\n" +
						"db_user=app_ro\n" +
						"db_pass=" + token + "\n" +
						"jenkins_token=" + token + "JK\n" +
						"slack_webhook=https://hooks.slack.com/" + token + "\n")
			},
		},
		{
			Name:        "gcp-key",
			DefaultPath: "/root/gcp-service-account.json",
			Render: func(token string) []byte {
				return []byte(
					"{\n" +
						"  \"type\": \"service_account\",\n" +
						"  \"private_key_id\": \"" + token + "\",\n" +
						"  \"client_email\": \"deploy@xhelix-canary.iam.gserviceaccount.com\"\n" +
						"}\n")
			},
		},
		{
			Name:        "env-file",
			DefaultPath: "/var/www/html/.env.bak",
			Render: func(token string) []byte {
				return []byte(
					"DATABASE_URL=postgres://app:" + token + "@db.internal:5432/prod\n" +
						"JWT_SECRET=" + token + "\n" +
						"STRIPE_KEY=sk_live_" + token + "\n")
			},
		},
	}
}

// PersonaByName returns the named persona, or nil.
func PersonaByName(name string) *Persona {
	for _, p := range Personas() {
		if p.Name == name {
			pp := p
			return &pp
		}
	}
	return nil
}
