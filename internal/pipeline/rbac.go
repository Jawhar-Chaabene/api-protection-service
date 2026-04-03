package pipeline

import (
	"context"
	"strings"
)

// RBACStep enforces role and object-level authorization.
type RBACStep struct {
	cfg Config
}

func NewRBACStep(cfg Config) *RBACStep {
	return &RBACStep{cfg: cfg}
}

func (s *RBACStep) Name() string { return "rbac_object_level" }

func (s *RBACStep) Execute(_ context.Context, sc *SecurityContext) {
	path := sc.Request.GetPath()
	method := strings.ToUpper(sc.Request.GetMethod())

	if isPublicPath(path, s.cfg.PublicPaths) {
		return
	}

	if strings.HasPrefix(path, "/admin") || strings.HasPrefix(path, "/internal") || strings.HasPrefix(path, "/debug") {
		if !hasRole(sc.Roles, "admin") {
			sc.Deny(403, denyReasonRBAC, "admin role required")
		}
		return
	}

	// BFLA: destructive operations on users require admin.
	if method == "DELETE" && strings.HasPrefix(path, "/api/v1/users/") && !hasRole(sc.Roles, "admin") {
		sc.Deny(403, denyReasonRBAC, "insufficient role for delete action")
		return
	}

	// Owner-only path: /api/v1/accounts/{accountId}/transactions
	if strings.HasPrefix(path, "/api/v1/accounts/") && strings.Contains(path, "/transactions") {
		accountID := segmentAfter(path, "/api/v1/accounts/")
		if accountID == "" {
			sc.Deny(403, denyReasonRBAC, "account ownership check failed")
			return
		}
		if hasRole(sc.Roles, "admin") {
			return
		}
		if sc.UserID == "" || sc.UserID != accountID {
			sc.Deny(403, denyReasonRBAC, "object-level: access denied to another account")
			return
		}
		return
	}

	// Owner-only generic: /users/{id}
	if strings.HasPrefix(path, "/users/") {
		target := segmentAfter(path, "/users/")
		if hasRole(sc.Roles, "admin") {
			return
		}
		if sc.UserID == "" || sc.UserID != target {
			sc.Deny(403, denyReasonRBAC, "object-level: access denied to another user's resource")
		}
		return
	}

	// Authenticated area fallback.
	if strings.HasPrefix(path, "/api/v1/") && sc.UserID == "" && !hasRole(sc.Roles, "admin") && !hasRole(sc.Roles, "user") {
		sc.Deny(403, denyReasonRBAC, "authenticated role required")
	}
}

func segmentAfter(path, prefix string) string {
	s := strings.TrimPrefix(path, prefix)
	if s == path {
		return ""
	}
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		return s[:idx]
	}
	return s
}

func hasRole(roles []string, candidate string) bool {
	for _, role := range roles {
		if strings.EqualFold(strings.TrimSpace(role), candidate) {
			return true
		}
	}
	return false
}
