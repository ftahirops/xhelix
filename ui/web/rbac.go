package web

import (
	"context"
	"net/http"
)

// Role is the access level a bearer token grants. Ordered: a higher role
// implicitly satisfies a lower requirement (admin ≥ operator ≥ viewer).
type Role int

const (
	RoleNone     Role = iota // unauthenticated / unknown
	RoleViewer               // read-only
	RoleOperator             // routine mutations (create, mode, arm, disarm)
	RoleAdmin                // disruptive ops (restart, delete, sealed-arm)
)

// String renders the role name used in tokens, config, and audit records.
func (r Role) String() string {
	switch r {
	case RoleViewer:
		return "viewer"
	case RoleOperator:
		return "operator"
	case RoleAdmin:
		return "admin"
	default:
		return "none"
	}
}

// ParseRole maps a config/token-file role name to a Role. Unknown → RoleNone.
func ParseRole(s string) Role {
	switch s {
	case "viewer":
		return RoleViewer
	case "operator":
		return RoleOperator
	case "admin":
		return RoleAdmin
	default:
		return RoleNone
	}
}

// Identity is the authenticated principal attached to a request by the
// AuthGuard. TokenName is the role name of the credential used; it doubles
// as the actor label in the audit trail (the system is credential-, not
// person-, identified).
type Identity struct {
	Role      Role
	TokenName string
	SourceIP  string
}

type ctxKey int

const identityKey ctxKey = 1

// WithIdentity returns a context carrying the identity.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

// IdentityFrom extracts the identity. When auth is disabled (NoAuth) or no
// identity was attached, it returns an admin identity so single-token and
// no-auth deployments keep working unchanged (backward compatible).
func IdentityFrom(ctx context.Context) Identity {
	if id, ok := ctx.Value(identityKey).(Identity); ok {
		return id
	}
	return Identity{Role: RoleAdmin, TokenName: "admin", SourceIP: ""}
}

// requireRole enforces a minimum role for a request. On insufficient
// privilege it writes 403 and returns false; the caller must return.
func requireRole(w http.ResponseWriter, r *http.Request, min Role) bool {
	id := IdentityFrom(r.Context())
	if id.Role < min {
		apiErr(w, "forbidden: "+min.String()+" role required (have "+id.Role.String()+")",
			http.StatusForbidden)
		return false
	}
	return true
}
