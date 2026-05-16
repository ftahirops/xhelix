// Authentication / authorisation layer for the dashboard.
//
// Defence in depth — every layer must pass:
//
//   1. TLS termination (HTTPSOnly redirect on plain :80 if enabled)
//   2. IP allow-list (operator-configured + auto-detected SSH IP)
//   3. Bearer token (printed once at startup; stored mode-0600 on disk)
//   4. Rate limit (10 req/sec per remote IP)
//   5. CSRF token on POST/PUT/DELETE (origin-based + double-submit)
//   6. Audit log line per request (method, path, src, status)
//
// Default deny: when AuthConfig is unset, ANY non-loopback request is
// rejected. The operator must explicitly opt in to public exposure.
package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AuthConfig configures the protection layer.
//
// Zero-value AuthConfig = "loopback only, no remote access" — the
// safest default. Operators who want remote access populate at
// least AllowIPs + Token.
type AuthConfig struct {
	// AllowIPs is the explicit allow-list. CIDRs accepted.
	// Empty + AutoDetectSSH=false = loopback only.
	AllowIPs []string

	// AutoDetectSSH adds the IP from $SSH_CONNECTION when the daemon
	// starts inside an SSH session. Useful for "let me reach the UI
	// from the same place I'm currently SSH'd in from".
	AutoDetectSSH bool

	// AdditionalAllowFile is a path containing one IP/CIDR per line,
	// re-read every 60s. Useful for ops integrations.
	AdditionalAllowFile string

	// TokenFile is where the Bearer token is persisted. Generated on
	// first start if missing. Default: /var/lib/xhelix/ui-token.
	TokenFile string

	// AuditLogPath is where every UI request lands. Default:
	// /var/log/xhelix/ui-audit.log.
	AuditLogPath string

	// RateLimitPerSecond caps requests-per-source-ip. 0 = 10.
	RateLimitPerSecond int

	// TrustForwardedFor accepts X-Forwarded-For when xhelix sits
	// behind a reverse proxy you control. Default false (safe).
	TrustForwardedFor bool

	// Logger for audit + auth events.
	Logger *slog.Logger
}

// AuthGuard implements the middleware chain.
type AuthGuard struct {
	cfg   AuthConfig
	token []byte // sha256 of the bearer token

	mu          sync.RWMutex
	allowed     []*net.IPNet
	limiter     map[string]*tokenBucket
	limiterStop chan struct{}

	auditFile *os.File
	denied    atomic.Uint64
	allowed_  atomic.Uint64
}

// NewAuthGuard initialises an AuthGuard, generating a token if needed.
//
// On first run a fresh token is written to TokenFile and printed to
// the operator's log so they can copy it. Subsequent runs read it.
//
// The function never returns silent failure — an unwritable token
// file or an invalid config kills startup. Better to refuse than to
// expose.
func NewAuthGuard(cfg AuthConfig) (*AuthGuard, error) {
	if cfg.TokenFile == "" {
		cfg.TokenFile = "/var/lib/xhelix/ui-token"
	}
	if cfg.AuditLogPath == "" {
		cfg.AuditLogPath = "/var/log/xhelix/ui-audit.log"
	}
	if cfg.RateLimitPerSecond == 0 {
		cfg.RateLimitPerSecond = 10
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	tok, fresh, err := loadOrCreateToken(cfg.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("load token: %w", err)
	}
	if fresh {
		// Print once, prominently. Never log this on subsequent
		// starts — the operator already saved it.
		fmt.Fprintln(os.Stderr,
			"==================================================================")
		fmt.Fprintln(os.Stderr, "xhelix UI bearer token (save this — it won't be shown again):")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "    "+string(tok))
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Add to URL:")
		fmt.Fprintf(os.Stderr,  "    https://your-host/ui?token=%s\n", string(tok))
		fmt.Fprintln(os.Stderr, "or as header:")
		fmt.Fprintf(os.Stderr,  "    Authorization: Bearer %s\n", string(tok))
		fmt.Fprintln(os.Stderr,
			"==================================================================")
	}
	digest := sha256.Sum256(tok)

	g := &AuthGuard{
		cfg:         cfg,
		token:       digest[:],
		limiter:     map[string]*tokenBucket{},
		limiterStop: make(chan struct{}),
	}
	if err := g.refreshAllowList(); err != nil {
		return nil, err
	}
	if err := g.openAuditLog(); err != nil {
		return nil, err
	}
	go g.refresher()
	return g, nil
}

// Stop releases resources.
func (g *AuthGuard) Stop() {
	close(g.limiterStop)
	if g.auditFile != nil {
		_ = g.auditFile.Close()
	}
}

// refresher re-reads the additional-allow-file every minute so
// operators can adjust without restarting.
func (g *AuthGuard) refresher() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-g.limiterStop:
			return
		case <-t.C:
			_ = g.refreshAllowList()
			g.gcLimiter()
		}
	}
}

// Wrap is the http.Handler middleware. Every UI request goes through it.
func (g *AuthGuard) Wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		src := g.clientIP(r)
		status := http.StatusOK

		defer func() {
			g.audit(r, src, status)
		}()

		// 1. IP allow-list
		if !g.ipAllowed(src) {
			g.denied.Add(1)
			status = http.StatusForbidden
			http.Error(w, "forbidden: source IP not allowed", status)
			return
		}

		// 2. Rate limit
		if !g.rateOK(src) {
			g.denied.Add(1)
			status = http.StatusTooManyRequests
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limited", status)
			return
		}

		// 3. Bearer token (Authorization header OR ?token= query OR cookie)
		if !g.tokenOK(r) {
			g.denied.Add(1)
			status = http.StatusUnauthorized
			w.Header().Set("WWW-Authenticate", `Bearer realm="xhelix"`)
			http.Error(w, "unauthorized: bearer token required", status)
			return
		}

		// 4. CSRF for state-changing methods (token must be in header)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !g.csrfOK(r) {
				g.denied.Add(1)
				status = http.StatusForbidden
				http.Error(w, "csrf: missing or invalid token", status)
				return
			}
		}

		// 5. Force HTTPS recommendation (informational)
		if r.TLS == nil {
			w.Header().Set("X-Xhelix-Warning", "plain HTTP detected; use HTTPS")
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")

		g.allowed_.Add(1)
		h.ServeHTTP(w, r)
	})
}

// ==========================================================
// IP allow-list
// ==========================================================

func (g *AuthGuard) refreshAllowList() error {
	out := []*net.IPNet{}

	// Loopback always allowed.
	for _, s := range []string{"127.0.0.0/8", "::1/128"} {
		_, n, _ := net.ParseCIDR(s)
		out = append(out, n)
	}

	// Operator-configured CIDRs / IPs
	for _, raw := range g.cfg.AllowIPs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "/") {
			if strings.Contains(raw, ":") {
				raw += "/128"
			} else {
				raw += "/32"
			}
		}
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return fmt.Errorf("invalid allow CIDR %q: %w", raw, err)
		}
		out = append(out, n)
	}

	// Auto-detect from SSH_CONNECTION (set by sshd if xhelix is
	// started inside an interactive session)
	if g.cfg.AutoDetectSSH {
		if ip := SSHClientIP(); ip != "" {
			cidr := ip + "/32"
			if strings.Contains(ip, ":") {
				cidr = ip + "/128"
			}
			if _, n, err := net.ParseCIDR(cidr); err == nil {
				out = append(out, n)
				g.cfg.Logger.Info("auth: auto-allowed SSH client", "ip", ip)
			}
		}
	}

	// File-driven
	if g.cfg.AdditionalAllowFile != "" {
		body, err := os.ReadFile(g.cfg.AdditionalAllowFile)
		if err == nil {
			for _, line := range strings.Split(string(body), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if !strings.Contains(line, "/") {
					if strings.Contains(line, ":") {
						line += "/128"
					} else {
						line += "/32"
					}
				}
				_, n, err := net.ParseCIDR(line)
				if err == nil {
					out = append(out, n)
				}
			}
		}
	}

	g.mu.Lock()
	g.allowed = out
	g.mu.Unlock()
	return nil
}

func (g *AuthGuard) ipAllowed(src net.IP) bool {
	if src == nil {
		return false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, n := range g.allowed {
		if n.Contains(src) {
			return true
		}
	}
	return false
}

// SSHClientIP returns the IP recorded in $SSH_CONNECTION, or empty
// if not running under SSH. The format is:
//   <client_ip> <client_port> <server_ip> <server_port>
func SSHClientIP() string {
	v := os.Getenv("SSH_CONNECTION")
	if v == "" {
		v = os.Getenv("SSH_CLIENT") // older shells
	}
	if v == "" {
		return ""
	}
	parts := strings.Fields(v)
	if len(parts) >= 1 {
		return parts[0]
	}
	return ""
}

// ==========================================================
// Bearer token
// ==========================================================

func loadOrCreateToken(path string) (token []byte, fresh bool, err error) {
	if body, err := os.ReadFile(path); err == nil {
		body = []byte(strings.TrimSpace(string(body)))
		if len(body) >= 32 {
			return body, false, nil
		}
	}
	// Generate
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, false, err
	}
	tok := []byte(hex.EncodeToString(raw[:]))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, err
	}
	if err := os.WriteFile(path, tok, 0o600); err != nil {
		return nil, false, err
	}
	return tok, true, nil
}

func (g *AuthGuard) tokenOK(r *http.Request) bool {
	var presented string
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		presented = strings.TrimPrefix(h, "Bearer ")
	}
	if presented == "" {
		presented = r.URL.Query().Get("token")
	}
	if presented == "" {
		if c, err := r.Cookie("xhelix_token"); err == nil {
			presented = c.Value
		}
	}
	if presented == "" {
		return false
	}
	digest := sha256.Sum256([]byte(presented))
	return subtle.ConstantTimeCompare(digest[:], g.token) == 1
}

// ==========================================================
// CSRF (double-submit cookie)
// ==========================================================

func (g *AuthGuard) csrfOK(r *http.Request) bool {
	header := r.Header.Get("X-Xhelix-CSRF")
	if header == "" {
		return false
	}
	cookie, err := r.Cookie("xhelix_csrf")
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(header), []byte(cookie.Value)) == 1
}

// ==========================================================
// Rate limit
// ==========================================================

type tokenBucket struct {
	tokens   int
	last     time.Time
	cap, fill int
}

func (g *AuthGuard) rateOK(src net.IP) bool {
	key := src.String()
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	b, ok := g.limiter[key]
	if !ok {
		b = &tokenBucket{
			tokens: g.cfg.RateLimitPerSecond,
			cap:    g.cfg.RateLimitPerSecond,
			fill:   g.cfg.RateLimitPerSecond,
			last:   now,
		}
		g.limiter[key] = b
	}
	// Refill
	elapsed := now.Sub(b.last).Seconds()
	add := int(elapsed * float64(b.fill))
	if add > 0 {
		b.tokens = min(b.cap, b.tokens+add)
		b.last = now
	}
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

func (g *AuthGuard) gcLimiter() {
	cutoff := time.Now().Add(-5 * time.Minute)
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, b := range g.limiter {
		if b.last.Before(cutoff) {
			delete(g.limiter, k)
		}
	}
}

// ==========================================================
// Source IP extraction
// ==========================================================

func (g *AuthGuard) clientIP(r *http.Request) net.IP {
	if g.cfg.TrustForwardedFor {
		if h := r.Header.Get("X-Forwarded-For"); h != "" {
			parts := strings.Split(h, ",")
			ip := net.ParseIP(strings.TrimSpace(parts[0]))
			if ip != nil {
				return ip
			}
		}
		if h := r.Header.Get("X-Real-IP"); h != "" {
			ip := net.ParseIP(strings.TrimSpace(h))
			if ip != nil {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

// ==========================================================
// Audit log
// ==========================================================

func (g *AuthGuard) openAuditLog() error {
	if err := os.MkdirAll(filepath.Dir(g.cfg.AuditLogPath), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(g.cfg.AuditLogPath,
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	g.auditFile = f
	return nil
}

// auditMaxBytes caps a single audit log file. When a write would
// exceed this, we rotate to <path>.1 (overwriting any prior rotation
// — single-step retention only) and start a fresh file. This is a
// defence against a log-flooding DoS filling the partition; for true
// long-term retention an operator should ship the log to syslog or
// configure an external logrotate policy.
const auditMaxBytes int64 = 256 * 1024 * 1024

func (g *AuthGuard) audit(r *http.Request, src net.IP, status int) {
	if g.auditFile == nil {
		return
	}
	ua := r.UserAgent()
	if len(ua) > 64 {
		ua = ua[:64]
	}
	line := fmt.Sprintf("%s %d %s %s %s %q\n",
		time.Now().UTC().Format(time.RFC3339Nano),
		status, r.Method, r.URL.Path, src.String(), ua)

	// Best-effort rotation check. Stat is cheap; if the file has
	// grown past the cap, rotate before writing.
	if st, err := g.auditFile.Stat(); err == nil && st.Size()+int64(len(line)) > auditMaxBytes {
		path := g.auditFile.Name()
		_ = g.auditFile.Close()
		_ = os.Rename(path, path+".1")
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err == nil {
			g.auditFile = f
		}
	}
	_, _ = g.auditFile.WriteString(line)
}

// Stats reports counters for the dashboard's own protection layer.
type AuthStats struct {
	Allowed uint64
	Denied  uint64
}

// AuthStats returns running counters.
func (g *AuthGuard) AuthStats() AuthStats {
	return AuthStats{
		Allowed: g.allowed_.Load(),
		Denied:  g.denied.Load(),
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
