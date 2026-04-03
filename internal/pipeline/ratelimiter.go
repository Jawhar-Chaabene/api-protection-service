package pipeline

import (
	"context"
	"strings"
	"sync"

	"golang.org/x/time/rate"
)

// RateLimiterStep enforces token-bucket limits per client identity.
type RateLimiterStep struct {
	cfg      Config
	limiters sync.Map
}

// NewRateLimiterStep creates a rate limiter step.
func NewRateLimiterStep(cfg Config) *RateLimiterStep {
	return &RateLimiterStep{cfg: cfg}
}

func (s *RateLimiterStep) Name() string { return "rate_limiter" }

func (s *RateLimiterStep) Execute(_ context.Context, sc *SecurityContext) {
	ip := strings.TrimSpace(sc.Request.GetClientIp())
	if ip == "" {
		ip = "unknown"
	}
	user := strings.TrimSpace(sc.Request.GetUserId())
	fingerprint := strings.TrimSpace(sc.Request.GetHeaders()["user-agent"])
	key := ip + "|" + user + "|" + fingerprint
	limiter := s.getLimiter(key)
	if !limiter.Allow() {
		sc.Deny(429, denyReasonRateLimit, "rate limit exceeded")
	}
}

func (s *RateLimiterStep) getLimiter(key string) *rate.Limiter {
	if v, ok := s.limiters.Load(key); ok {
		return v.(*rate.Limiter)
	}
	l := rate.NewLimiter(rate.Limit(s.cfg.RateLimitRPS), s.cfg.RateLimitBurst)
	s.limiters.Store(key, l)
	return l
}
