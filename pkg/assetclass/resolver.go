package assetclass

import (
	"strings"
)

// staticResolver implements Resolver against a hardcoded rule table
// plus an optional operator-override layer. Static rules apply
// universally; the override layer narrows classifications further
// (operator can RESTRICT but not RELAX classes that ship as sensitive).
//
// The static table is the source of truth for known system paths.
// Operator overrides at `/etc/xhelix/assetclass.d/*.yaml` add
// site-specific classifications (e.g. a custom backup mount point).
type staticResolver struct {
	overrides []pathRule
}

// pathRule is one operator-supplied classification rule.
// PathPrefix is matched against the full path with strings.HasPrefix.
// AppliesToRoles, if non-empty, narrows the rule to actors with one of
// those roles (empty matches any role).
type pathRule struct {
	PathPrefix     string
	Class          Class
	AppliesToRoles []string
}

// NewStaticResolver returns a Resolver with the built-in rule table
// only. Operator overrides can be layered via NewWithOverrides.
func NewStaticResolver() Resolver {
	return &staticResolver{}
}

// NewWithOverrides returns a Resolver layering operator-supplied rules
// over the static table. Overrides take precedence over static rules
// for sensitive classes only when they CONSTRAIN further; relax
// attempts are rejected silently to preserve the protect-our-own
// guarantee.
func NewWithOverrides(rules []pathRule) Resolver {
	return &staticResolver{overrides: rules}
}

// ClassifyPath returns the asset class for a filesystem path.
//
// Resolution order:
//
//	1. Static built-in classes (immutable) — these define the floor;
//	   the operator override cannot relax them
//	2. Operator overrides matching path + role
//	3. Role-aware refinement (e.g. log paths under backup role)
//	4. Fallback to ClassUnknown
func (r *staticResolver) ClassifyPath(path, role string) Class {
	if path == "" {
		return ClassUnknown
	}

	// (1) Static immutable rules — these are the protect-our-own floor.
	if c := staticPathClass(path); c != ClassUnknown {
		// Sensitive class — never relax via override.
		if c.IsSensitive() {
			return c
		}
		// Non-sensitive: still return static unless an override
		// upgrades to a more specific class.
		if override := r.matchOverride(path, role); override != ClassUnknown {
			return override
		}
		return c
	}

	// (2) Operator overrides.
	if c := r.matchOverride(path, role); c != ClassUnknown {
		return c
	}

	// (3) Role-aware refinement.
	if c := roleAwarePathClass(path, role); c != ClassUnknown {
		return c
	}

	return ClassUnknown
}

func (r *staticResolver) ClassifySocket(socketPath string) Class {
	if socketPath == "" {
		return ClassUnknown
	}
	return staticSocketClass(socketPath)
}

func (r *staticResolver) ClassifyHost(ip, sni string, port uint16) Class {
	return staticHostClass(ip, sni, port)
}

func (r *staticResolver) matchOverride(path, role string) Class {
	for _, rule := range r.overrides {
		if !strings.HasPrefix(path, rule.PathPrefix) {
			continue
		}
		if len(rule.AppliesToRoles) > 0 {
			match := false
			for _, allowed := range rule.AppliesToRoles {
				if role == allowed {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		return rule.Class
	}
	return ClassUnknown
}
