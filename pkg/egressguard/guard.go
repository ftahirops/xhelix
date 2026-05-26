package egressguard

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

// guard implements the Guard interface.
//
// Decision flow (per Build Spec §3.3):
//
//  1. Allow loopback + private destinations unconditionally (internal traffic
//     is governed by other layers, not by egressguard)
//  2. If actor role is in ProtectedRoles AND destination is a raw IP (no
//     SNI/DNS) → Deny — protected infra services should reach declared peers
//     by name, never raw IPs
//  3. If secret_taint == "outbound_restricted" or "containment_required" →
//     Deny — lineage already promoted by an earlier event
//  4. If actor role is profiled AND destination matches profile UpstreamHosts
//     → Allow (this is the declared peer set)
//  5. If actor role is profiled but destination is NOT declared → Verify
//     (routes to BRP verifier for multi-domain scoring)
//  6. Otherwise → Allow (unprofiled roles get observe-only treatment; pipeline
//     still emits brp.verify_protected_path when verifier promotes)
//
// The guard is intentionally narrow: only deny on clear violations,
// route ambiguous cases to the verifier. Hard-deny FP cost on protected
// roles is very high (would break production traffic) so the bar is
// conservative.
type guard struct {
	backend  Backend
	mode     Mode
	cache    *denyCache
	profiles ProfileLookup

	// ProtectedRoles lists the roles for which raw-IP egress is denied
	// by default (infra services that should always egress to declared
	// peers). Operator-tunable; default set covers common server roles.
	protectedRoles map[string]bool

	mu sync.RWMutex
}

// ProfileLookup is the abstraction the guard uses to fetch declared
// peers for a role. Implementations adapt brp.Matcher → []string for
// allowed destinations. Kept as an interface so guard tests can use
// a fake profile lookup.
type ProfileLookup interface {
	// UpstreamHostsForRole returns the list of declared upstream hosts
	// (format: "host:port" or "host:*" or "host") for a given role.
	// Returns nil/empty if role is unprofiled.
	UpstreamHostsForRole(role string) []string
}

// NewGuard returns a Guard with the given backend + profile lookup.
// Mode is locked at construction time; switch backends to change mode
// (so a downgrade from enforce → shadow forces operator awareness).
func NewGuard(backend Backend, profiles ProfileLookup, mode Mode) Guard {
	if backend == nil {
		backend = newObserveBackend(mode)
	}
	backend.SetMode(mode)
	g := &guard{
		backend:        backend,
		mode:           mode,
		cache:          newDenyCache(),
		profiles:       profiles,
		protectedRoles: defaultProtectedRoles(),
	}
	return g
}

// defaultProtectedRoles is the default set of roles for which raw-IP
// egress is denied by default. Operator can override at runtime.
func defaultProtectedRoles() map[string]bool {
	return map[string]bool{
		"nginx-static":         true,
		"nginx-reverse-proxy":  true,
		"nginx-fastcgi":        true,
		"nginx-lua":            true,
		"nginx-njs":            true,
		"nginx-grpc-proxy":     true,
		"apache-static":        true,
		"apache-reverse-proxy": true,
		"apache-cgi":           true,
		"apache-fastcgi":       true,
		"apache-wsgi":          true,
		"mysql-default":        true,
		"mysql-primary":        true,
		"mysql-replica":        true,
		"mysql-galera":         true,
		"postgres-default":     true,
		"redis-default":        true,
		"sshd-permissive":      true,
		"sshd-strict":          true,
	}
}

func (g *guard) Mode() Mode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.mode
}

func (g *guard) BackendName() string {
	return g.backend.Name()
}

// Decide is the per-event verdict. Read-mostly; takes RLock.
func (g *guard) Decide(r Request) (Decision, string) {
	// (1) Loopback + private: always allow. Internal traffic is governed
	// by other layers; egressguard is for external/raw-IP control.
	if isLoopbackOrPrivate(r.DestIP) {
		return EgressAllow, "private/loopback"
	}

	g.mu.RLock()
	protected := g.protectedRoles[r.AppRole]
	g.mu.RUnlock()

	// (2) Protected role + raw IP (no SNI/DNS context) → Deny.
	if protected && r.SNI == "" && r.DNSName == "" && r.DestIP != "" {
		return EgressDeny,
			fmt.Sprintf("protected role %q egressing to raw IP %s", r.AppRole, r.DestIP)
	}

	// (3) Secret-taint promoted state → Deny.
	switch r.SecretTaint {
	case "outbound_restricted", "containment_required":
		return EgressDeny,
			fmt.Sprintf("secret-tainted lineage (state=%s) attempting outbound", r.SecretTaint)
	}

	// (4) + (5): profile-declared peer check.
	if g.profiles != nil && r.AppRole != "" {
		declared := g.profiles.UpstreamHostsForRole(r.AppRole)
		if len(declared) > 0 {
			if matchesDeclaredPeer(declared, r) {
				return EgressAllow, "destination matches declared upstream"
			}
			// Profiled role + undeclared destination → Verify, not Deny.
			// Hard-deny FP cost on protected roles is high; let the
			// verifier multi-domain score the deviation.
			return EgressVerify,
				fmt.Sprintf("profiled role %q egress to undeclared %s",
					r.AppRole, destKey(r))
		}
	}

	// (6) Unprofiled or no role: observe-only at egressguard layer.
	// The verifier still scores via its own domains.
	return EgressAllow, "unprofiled or unrestricted role"
}

// ApplyDeny pushes a deny rule to the backend. In shadow mode this is
// logged but not pushed to kernel. Deny cache prevents duplicate pushes
// for the same lineage+dest within TTL.
func (g *guard) ApplyDeny(lineageID uint64, destKey string, ttl time.Duration) error {
	if g.cache.has(lineageID, destKey) {
		return nil // already denied within TTL
	}
	g.cache.add(lineageID, destKey, ttl)

	if g.mode != ModeEnforce {
		slog.Info("egressguard shadow deny",
			"lineage", lineageID, "dest", destKey,
			"mode", g.mode.String(), "backend", g.backend.Name())
		return nil
	}
	// Enforce: push to kernel backend.
	dest := destKeyToIP(destKey)
	if dest == "" {
		return fmt.Errorf("egressguard: dest %q is not an IP", destKey)
	}
	if err := g.backend.Push(lineageID, dest, ttl); err != nil {
		slog.Warn("egressguard backend Push failed",
			"backend", g.backend.Name(), "err", err)
		return err
	}
	slog.Warn("egressguard real deny pushed to backend",
		"lineage", lineageID, "dest", destKey,
		"backend", g.backend.Name(), "ttl", ttl.String())
	return nil
}

// SetProtectedRoles replaces the protected-role allowlist at runtime.
// Operator surface (xhelixctl egress protected-roles set ...).
func (g *guard) SetProtectedRoles(roles []string) {
	m := map[string]bool{}
	for _, r := range roles {
		m[r] = true
	}
	g.mu.Lock()
	g.protectedRoles = m
	g.mu.Unlock()
}

// ProtectedRoles returns a copy of the current allowlist.
func (g *guard) ProtectedRoles() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]string, 0, len(g.protectedRoles))
	for r := range g.protectedRoles {
		out = append(out, r)
	}
	return out
}

// ─────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────

func isLoopbackOrPrivate(ipStr string) bool {
	if ipStr == "" {
		return false
	}
	// Cloud metadata endpoints sit in link-local space but are
	// high-value secret-touch surfaces. Never treat them as private.
	// Discovered by Phase C.3 soak (2026-05-26): metadata curl produced
	// 0 shadow denies because IsLinkLocalUnicast was returning true for
	// 169.254.169.254 and the guard returned Allow before higher tiers
	// could fire.
	if ipStr == "169.254.169.254" || strings.HasPrefix(ipStr, "fd00:ec2::") {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// matchesDeclaredPeer checks if the request's destination matches any
// declared upstream entry. Match semantics:
//
//	"host:port" exact match against (DestIP|DNSName|SNI):DestPort
//	"host:*" matches any port for that host
//	"host" matches any port for that host
//	IP-literal entries match DestIP
//	DNS entries match SNI or DNSName
func matchesDeclaredPeer(declared []string, r Request) bool {
	for _, d := range declared {
		if d == "" {
			continue
		}
		host, port := splitHostPort(d)
		// Host comparison: try each name source.
		for _, name := range []string{r.DestIP, r.DNSName, r.SNI} {
			if name == "" {
				continue
			}
			if !hostMatch(host, name) {
				continue
			}
			if port == "" || port == "*" {
				return true
			}
			if port == fmt.Sprintf("%d", r.DestPort) {
				return true
			}
		}
	}
	return false
}

func splitHostPort(decl string) (host, port string) {
	if idx := strings.LastIndex(decl, ":"); idx >= 0 {
		// Avoid splitting IPv6 — IPv6 declarations should be in
		// [addr]:port form. If brackets are absent, treat as host-only.
		if strings.Count(decl, ":") == 1 {
			return decl[:idx], decl[idx+1:]
		}
	}
	return decl, ""
}

func hostMatch(declared, observed string) bool {
	if declared == observed {
		return true
	}
	// Trailing wildcards (e.g. "*.example.com" matches "api.example.com").
	if strings.HasPrefix(declared, "*.") &&
		strings.HasSuffix(observed, declared[1:]) {
		return true
	}
	return false
}

func destKey(r Request) string {
	switch {
	case r.SNI != "":
		return fmt.Sprintf("%s:%d", r.SNI, r.DestPort)
	case r.DNSName != "":
		return fmt.Sprintf("%s:%d", r.DNSName, r.DestPort)
	case r.DestIP != "":
		return fmt.Sprintf("%s:%d", r.DestIP, r.DestPort)
	}
	return ""
}

func destKeyToIP(key string) string {
	if idx := strings.LastIndex(key, ":"); idx >= 0 {
		return key[:idx]
	}
	return key
}
