package pipeline

import (
	"context"
	"testing"

	pb "api-protection/proto/genProto"
)

func TestRateLimiterStep_DeniesWhenExceeded(t *testing.T) {
	cfg := Config{RateLimitRPS: 1, RateLimitBurst: 1}
	step := NewRateLimiterStep(cfg)

	req := &pb.VerifyRequest{Path: "/api/v1/login", Method: "POST", ClientIp: "1.2.3.4"}
	first := NewSecurityContext(req)
	step.Execute(context.Background(), first)
	if first.Denied {
		t.Fatalf("first request should pass")
	}

	second := NewSecurityContext(req)
	step.Execute(context.Background(), second)
	if !second.Denied {
		t.Fatalf("second request should be denied")
	}
	if second.Response.GetHttpStatus() != 429 {
		t.Fatalf("expected 429, got %d", second.Response.GetHttpStatus())
	}
}
