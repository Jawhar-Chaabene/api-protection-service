package pipeline

import (
	"context"
	"testing"
	"time"

	pb "api-protection/proto/genProto"

	"github.com/golang-jwt/jwt/v5"
)

func TestPipeline_AllowFlow(t *testing.T) {
	cfg := Config{
		JWTSecret:      "secret",
		JWTAlgorithms:  []string{"HS256"},
		RequireAPIKey:  true,
		PublicPaths:    []string{"/healthz", "/api/v1/login"},
		MaxBodyBytes:   1024,
		UploadMaxBytes: 1024,
		RateLimitRPS:   100,
		RateLimitBurst: 100,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "1001",
		"roles": []string{"user"},
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
	})
	signed, _ := token.SignedString([]byte("secret"))

	pipe := BuildDefaultPipeline(cfg, &fakeAPIKeyRepo{
		record: &APIKeyRecord{ID: "key1", Status: "active", OwnerID: "1001", ExpiresAt: time.Now().Add(time.Hour)},
	})
	req := &pb.VerifyRequest{
		Path:     "/api/v1/accounts/1001/transactions",
		Method:   "GET",
		ClientIp: "1.2.3.4",
		Headers:  map[string]string{"authorization": "Bearer " + signed, "x-api-key": "test-api-key"},
		ApiKey:   "test-api-key",
	}
	sc := NewSecurityContext(req)
	pipe.Run(context.Background(), sc)
	if sc.Denied || sc.Response.GetVerdict() != pb.Verdict_ALLOW {
		t.Fatalf("expected allow, got denied: %s", sc.Response.GetReason())
	}
}

func TestPipeline_DenyFlow(t *testing.T) {
	cfg := Config{
		JWTSecret:      "secret",
		JWTAlgorithms:  []string{"HS256"},
		RequireAPIKey:  true,
		PublicPaths:    []string{"/healthz", "/api/v1/login"},
		MaxBodyBytes:   1024,
		UploadMaxBytes: 1024,
		RateLimitRPS:   100,
		RateLimitBurst: 100,
	}

	pipe := BuildDefaultPipeline(cfg, &fakeAPIKeyRepo{err: ErrAPIKeyNotFound})
	req := &pb.VerifyRequest{
		Path:     "/api/v1/orders",
		Method:   "GET",
		ClientIp: "1.2.3.4",
		Headers:  map[string]string{},
	}
	sc := NewSecurityContext(req)
	pipe.Run(context.Background(), sc)
	if !sc.Denied || sc.Response.GetVerdict() != pb.Verdict_DENY {
		t.Fatalf("expected deny")
	}
}
