package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRoleOrdering(t *testing.T) {
	if !(RoleViewer < RoleOperator && RoleOperator < RoleAdmin) {
		t.Fatal("role ordering must be viewer < operator < admin")
	}
}

func TestParseRole(t *testing.T) {
	cases := map[string]Role{
		"viewer": RoleViewer, "operator": RoleOperator, "admin": RoleAdmin,
		"": RoleNone, "root": RoleNone,
	}
	for s, want := range cases {
		if got := ParseRole(s); got != want {
			t.Errorf("ParseRole(%q)=%v want %v", s, got, want)
		}
	}
}

func TestIdentityFrom_DefaultsToAdmin(t *testing.T) {
	// No identity in context (NoAuth / pre-RBAC) → admin, preserving the
	// single-principal behavior.
	id := IdentityFrom(context.Background())
	if id.Role != RoleAdmin {
		t.Errorf("default identity role = %v, want admin (backward compat)", id.Role)
	}
}

func TestRequireRole_Enforced(t *testing.T) {
	mkReq := func(role Role) *http.Request {
		r := httptest.NewRequest("POST", "/x", nil)
		return r.WithContext(WithIdentity(r.Context(), Identity{Role: role, TokenName: role.String()}))
	}
	// viewer must NOT pass an operator gate.
	w := httptest.NewRecorder()
	if requireRole(w, mkReq(RoleViewer), RoleOperator) {
		t.Error("viewer should be denied operator gate")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", w.Code)
	}
	// operator must NOT pass an admin gate (e.g. restart).
	w = httptest.NewRecorder()
	if requireRole(w, mkReq(RoleOperator), RoleAdmin) {
		t.Error("operator should be denied admin gate (restart/delete)")
	}
	// operator passes an operator gate (arm).
	w = httptest.NewRecorder()
	if !requireRole(w, mkReq(RoleOperator), RoleOperator) {
		t.Error("operator should pass operator gate")
	}
	// admin passes everything.
	w = httptest.NewRecorder()
	if !requireRole(w, mkReq(RoleAdmin), RoleAdmin) {
		t.Error("admin should pass admin gate")
	}
}
