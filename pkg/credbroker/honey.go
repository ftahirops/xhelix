package credbroker

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// HoneyFactory generates plausible-looking credential content for the
// honey-on-deny path. The returned bytes look like a real credential
// (so the attacker proceeds) but contain a unique embedded marker
// that downstream sensors can detect when the honey is later used.
//
// Honey is generated per (sealed_path, deny event) so each exfil leaves
// a different marker — that gives us campaign-level attribution if the
// same attacker hits multiple sealed files.
//
// Marker format: "xhx_h_" + 26-char base32 (160 bits). Recognisable in
// HTTP, DNS, env vars, logs, etc. without colliding with anything
// legitimate.
type HoneyFactory struct {
	mu      sync.Mutex
	markers map[string]HoneyOrigin // marker → origin (forensic lookup)
}

// HoneyOrigin records where a honey credential came from. When a
// sensor later observes the marker in network traffic, we look up the
// origin to know "this attacker exfiltrated /etc/myapp/db.sealed at T".
type HoneyOrigin struct {
	Marker       string
	SealedPath   string
	Class        Class
	IssuedAt     time.Time
	RequestPID   uint32
	RequestImage string
	RequestComm  string
}

// NewHoneyFactory returns an empty factory.
func NewHoneyFactory() *HoneyFactory {
	return &HoneyFactory{markers: map[string]HoneyOrigin{}}
}

// Generate returns honey content for the given (class, sealed_path,
// requester) tuple. Marker is unique per call.
func (h *HoneyFactory) Generate(class Class, sealedPath string, req Request) ([]byte, HoneyOrigin) {
	marker := newMarker()
	origin := HoneyOrigin{
		Marker:     marker,
		SealedPath: sealedPath,
		Class:      class,
		IssuedAt:   time.Now().UTC(),
		RequestPID: req.PID,
	}
	if len(req.Lineage) > 0 {
		origin.RequestImage = req.Lineage[0].Image
		origin.RequestComm = req.Lineage[0].Comm
	}
	h.mu.Lock()
	h.markers[marker] = origin
	h.mu.Unlock()

	var content []byte
	switch class {
	case ClassAPIKey:
		content = honeyAPIKey(marker)
	case ClassCredentials:
		// Detect SSH vs AWS by sealed path heuristic.
		switch {
		case strings.Contains(sealedPath, "ssh") || strings.Contains(sealedPath, "id_"):
			content = honeySSHKey(marker)
		case strings.Contains(sealedPath, "aws") || strings.Contains(sealedPath, ".credentials"):
			content = honeyAWSCredentials(marker)
		case strings.Contains(sealedPath, "kube"):
			content = honeyKubeconfig(marker)
		default:
			content = honeyGenericToken(marker)
		}
	default:
		content = honeyGenericToken(marker)
	}
	return content, origin
}

// Lookup returns the origin for a marker, if any. Used by sensors that
// see the marker in flight.
func (h *HoneyFactory) Lookup(marker string) (HoneyOrigin, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	o, ok := h.markers[marker]
	return o, ok
}

// AllMarkers returns a snapshot of all issued markers (audit/CLI).
func (h *HoneyFactory) AllMarkers() []HoneyOrigin {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]HoneyOrigin, 0, len(h.markers))
	for _, o := range h.markers {
		out = append(out, o)
	}
	return out
}

const markerPrefix = "xhx_h_"

func newMarker() string {
	var b [20]byte
	_, _ = rand.Read(b[:])
	return markerPrefix + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]))
}

// IsHoneyMarker reports whether s contains an xhelix honey marker.
// Sensors call this to flag exfil-of-honey events.
func IsHoneyMarker(s string) (string, bool) {
	idx := strings.Index(s, markerPrefix)
	if idx < 0 {
		return "", false
	}
	// Marker is prefix + 32 base32 chars. Scan forward.
	end := idx + len(markerPrefix)
	for end < len(s) && isBase32Char(s[end]) && end-idx-len(markerPrefix) < 32 {
		end++
	}
	if end-idx < len(markerPrefix)+8 { // need at least 8 bytes to be plausible
		return "", false
	}
	return s[idx:end], true
}

func isBase32Char(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '2' && b <= '7')
}

// ─────────────────────── honey content generators ─────────────────

func honeyAWSCredentials(marker string) []byte {
	// AWS-style: AKIA + 16 uppercase alphanum. Embed marker in the
	// secret-access-key so a real attempt to use these creds beacons
	// off in CloudTrail (AWS logs the AccessKeyId on every API call,
	// which is what we'll match on).
	access := "AKIA" + randUpperAlphanum(16)
	// Encode marker into the secret so any leak (env var, file, log
	// scrape) carries the marker. 40-char secret, marker is 38 chars,
	// pad with random.
	secret := marker + randAlphanum(40-len(marker))
	if len(secret) > 40 {
		secret = secret[:40]
	}
	return []byte(fmt.Sprintf(
		"[default]\naws_access_key_id = %s\naws_secret_access_key = %s\n# xhelix-marker: %s\n",
		access, secret, marker,
	))
}

func honeySSHKey(marker string) []byte {
	// OpenSSH ed25519 format — base64 blob between BEGIN/END lines.
	// Real keys would unpack and validate; honey deliberately fails
	// validation but looks right enough to be tried. Marker embedded
	// in the comment line at the end (OpenSSH key format permits a
	// trailing comment field).
	body := randBase64(384)
	return []byte(fmt.Sprintf(
		"-----BEGIN OPENSSH PRIVATE KEY-----\n%s\n-----END OPENSSH PRIVATE KEY-----\n# xhelix-marker: %s\n",
		breakLines(body, 70), marker,
	))
}

func honeyKubeconfig(marker string) []byte {
	tok := marker + randAlphanum(32)
	return []byte(fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://kube.invalid:6443
  name: honey-cluster
contexts:
- context:
    cluster: honey-cluster
    user: honey-user
  name: honey
current-context: honey
users:
- name: honey-user
  user:
    token: %s
# xhelix-marker: %s
`, tok, marker))
}

func honeyAPIKey(marker string) []byte {
	return []byte(fmt.Sprintf(
		"# xhelix-marker: %s\nAPI_KEY=%s%s\n",
		marker, marker, randAlphanum(16),
	))
}

func honeyGenericToken(marker string) []byte {
	return []byte(marker + randAlphanum(48) + "\n")
}

// ─────────────────────── randomness helpers ──────────────────────

const upperAlphanum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const allAlphanum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const b64alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func randPick(n int, alphabet string) string {
	out := make([]byte, n)
	r := make([]byte, n)
	_, _ = rand.Read(r)
	for i := 0; i < n; i++ {
		out[i] = alphabet[int(r[i])%len(alphabet)]
	}
	return string(out)
}

func randUpperAlphanum(n int) string { return randPick(n, upperAlphanum) }
func randAlphanum(n int) string      { return randPick(n, allAlphanum) }
func randBase64(n int) string        { return randPick(n, b64alphabet) }

func breakLines(s string, width int) string {
	var b strings.Builder
	for i := 0; i < len(s); i += width {
		end := i + width
		if end > len(s) {
			end = len(s)
		}
		b.WriteString(s[i:end])
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}

// hashMarker is a debugging helper — when a sensor sees a marker we
// can stamp it into events under a short hash to keep log lines tight.
func hashMarker(m string) string {
	if len(m) < 8 {
		return m
	}
	return hex.EncodeToString([]byte(m)[:4])
}
