package service

import (
	"path"
	"strings"
)

// RBACChecker verifies if a user can access a resource.
type RBACChecker interface {
	CanAccess(userID string, roles []string, resourcePath, method string) (allowed bool, reason string)
}

// DefaultRBAC implements RBACChecker with in-memory rules.
type DefaultRBAC struct{}

// CanAccess checks RBAC and object-level authorization.
func (r *DefaultRBAC) CanAccess(userID string, roles []string, resourcePath, method string) (bool, string) {
	resourcePath = normalizePath(resourcePath)
	roleSet := make(map[string]bool)
	for _, role := range roles {
		roleSet[strings.TrimSpace(role)] = true
	}

	// Anonymous: /api/public/*, /health (no roles or explicit anonymous)
	if roleSet["anonymous"] || len(roles) == 0 {
		if strings.HasPrefix(resourcePath, "/api/public") || resourcePath == "/health" {
			return true, ""
		}
	}

	// Admin: /admin/*, /users/*
	if roleSet["admin"] {
		if strings.HasPrefix(resourcePath, "/admin") || strings.HasPrefix(resourcePath, "/users") {
			return true, ""
		}
	}

	// User: /api/*, /users/{own_id}
	if roleSet["user"] {
		if strings.HasPrefix(resourcePath, "/api") {
			return true, ""
		}
		// Object-level: /users/:id
		if strings.HasPrefix(resourcePath, "/users/") {
			resourceID := extractResourceID(resourcePath, "/users/")
			if resourceID == userID {
				return true, ""
			}
			return false, "object-level: access denied to another user's resource"
		}
	}

	// No matching rule
	return false, "rbac: no role grants access to this resource"
}

func normalizePath(p string) string {
	p = path.Clean(p)
	if p == "." {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

func extractResourceID(fullPath, prefix string) string {
	rest := strings.TrimPrefix(fullPath, prefix)
	idx := strings.Index(rest, "/")
	if idx >= 0 {
		return rest[:idx]
	}
	return rest
}
