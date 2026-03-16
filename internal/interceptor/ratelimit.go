package interceptor

import (
	"context"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"golang.org/x/time/rate"
)

// RateLimitConfig holds token bucket parameters.
type RateLimitConfig struct {
	RPS   rate.Limit
	Burst int
}

// DefaultRateLimitConfig returns a sensible default (10 req/s, burst 20).
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{RPS: 10, Burst: 20}
}

type rateLimiter struct {
	limiters sync.Map
	config   RateLimitConfig
}

// NewRateLimitInterceptor returns a unary interceptor that limits requests per client IP.
func NewRateLimitInterceptor(config RateLimitConfig) grpc.UnaryServerInterceptor {
	rl := &rateLimiter{config: config}
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		ip := clientIPFromContext(ctx)
		limiter := rl.getLimiter(ip)
		if !limiter.Allow() {
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded for %s", ip)
		}
		return handler(ctx, req)
	}
}

func (rl *rateLimiter) getLimiter(ip string) *rate.Limiter {
	if v, ok := rl.limiters.Load(ip); ok {
		return v.(*rate.Limiter)
	}
	l := rate.NewLimiter(rl.config.RPS, rl.config.Burst)
	rl.limiters.Store(ip, l)
	return l
}

func clientIPFromContext(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get("x-client-ip"); len(vals) > 0 && vals[0] != "" {
			return vals[0]
		}
	}
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		return p.Addr.String()
	}
	return "unknown"
}
