package interceptor

import (
	"context"
	"strings"

	"api-protection/pkg/sanitize"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type contextKey string

const (
	keyClientIP contextKey = "client_ip"
	keyUserID   contextKey = "user_id"
	keyRoles    contextKey = "roles"
)

// MetadataKeys for extracting auth info from context.
const (
	MetaClientIP = "x-client-ip"
	MetaUserID   = "x-user-id"
	MetaRoles    = "x-roles"
)

// MetadataInterceptor extracts and sanitizes gRPC metadata, then injects into context.
func MetadataInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		ctx = injectMetadata(ctx)
		return handler(ctx, req)
	}
}

func injectMetadata(ctx context.Context) context.Context {
	md, _ := metadata.FromIncomingContext(ctx)
	clientIP := sanitizeFirst(md, MetaClientIP)
	userID := sanitizeFirst(md, MetaUserID)
	roles := parseRoles(sanitizeFirst(md, MetaRoles))

	if clientIP != "" {
		ctx = context.WithValue(ctx, keyClientIP, clientIP)
	}
	if userID != "" {
		ctx = context.WithValue(ctx, keyUserID, userID)
	}
	if len(roles) > 0 {
		ctx = context.WithValue(ctx, keyRoles, roles)
	}
	return ctx
}

func sanitizeFirst(md metadata.MD, key string) string {
	vals := md.Get(key)
	if len(vals) == 0 {
		return ""
	}
	return sanitize.Metadata(vals[0])
}

func parseRoles(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if r := strings.TrimSpace(p); r != "" {
			out = append(out, r)
		}
	}
	return out
}

// ClientIPFromContext returns the sanitized client IP from context.
func ClientIPFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(keyClientIP).(string); ok {
		return v
	}
	return ""
}

// UserIDFromContext returns the sanitized user ID from context.
func UserIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(keyUserID).(string); ok {
		return v
	}
	return ""
}

// RolesFromContext returns the sanitized roles from context.
func RolesFromContext(ctx context.Context) []string {
	if v, ok := ctx.Value(keyRoles).([]string); ok {
		return v
	}
	return nil
}
