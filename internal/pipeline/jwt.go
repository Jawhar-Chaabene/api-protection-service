package pipeline

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTStep validates bearer tokens and extracts identity claims.
type JWTStep struct {
	cfg Config
}

func NewJWTStep(cfg Config) *JWTStep { return &JWTStep{cfg: cfg} }

func (s *JWTStep) Name() string { return "jwt_validator" }

func (s *JWTStep) Execute(_ context.Context, sc *SecurityContext) {
	path := sc.Request.GetPath()
	authHeader := headerValue(sc.Request.GetHeaders(), "authorization")
	tokenStr := extractBearer(authHeader)
	if tokenStr == "" {
		if isPublicPath(path, s.cfg.PublicPaths) {
			return
		}
		sc.Deny(401, denyReasonJWT, "missing bearer token")
		return
	}

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() == jwt.SigningMethodNone.Alg() {
			return nil, errors.New("alg none is not allowed")
		}
		if !contains(s.cfg.JWTAlgorithms, t.Method.Alg()) {
			return nil, errors.New("unexpected signing algorithm")
		}
		return []byte(s.cfg.JWTSecret), nil
	}, jwt.WithValidMethods(s.cfg.JWTAlgorithms))
	if err != nil || !token.Valid {
		sc.Deny(401, denyReasonJWT, "invalid bearer token")
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		sc.Deny(401, denyReasonJWT, "invalid token claims")
		return
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil || exp.Time.Before(time.Now()) {
		sc.Deny(401, denyReasonJWT, "token expired")
		return
	}
	if s.cfg.JWTIssuer != "" {
		issuer, err := claims.GetIssuer()
		if err != nil || issuer != s.cfg.JWTIssuer {
			sc.Deny(401, denyReasonJWT, "invalid token issuer")
			return
		}
	}
	if sub, ok := claims["sub"].(string); ok && sub != "" {
		sc.UserID = sub
	}
	if rawRoles, ok := claims["roles"].([]interface{}); ok {
		roles := make([]string, 0, len(rawRoles))
		for _, r := range rawRoles {
			if role, ok := r.(string); ok && strings.TrimSpace(role) != "" {
				roles = append(roles, strings.ToLower(strings.TrimSpace(role)))
			}
		}
		if len(roles) > 0 {
			sc.Roles = roles
		}
	}
}

func extractBearer(authHeader string) string {
	if authHeader == "" {
		return ""
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(authHeader, prefix))
}

func contains(items []string, candidate string) bool {
	for _, item := range items {
		if strings.EqualFold(item, candidate) {
			return true
		}
	}
	return false
}
