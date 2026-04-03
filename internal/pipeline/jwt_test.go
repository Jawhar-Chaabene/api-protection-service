package pipeline

import (
	"context"
	"testing"
	"time"

	pb "api-protection/proto/genProto"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWTStep_ValidToken(t *testing.T) {
	cfg := Config{
		JWTSecret:     "secret",
		JWTAlgorithms: []string{"HS256"},
		PublicPaths:   []string{"/healthz"},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "u-123",
		"roles": []string{"user"},
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
	})
	signed, err := token.SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	step := NewJWTStep(cfg)
	sc := NewSecurityContext(&pb.VerifyRequest{
		Path:    "/api/v1/orders",
		Method:  "GET",
		Headers: map[string]string{"authorization": "Bearer " + signed},
	})
	step.Execute(context.Background(), sc)
	if sc.Denied {
		t.Fatalf("expected allow, got deny=%s", sc.Response.GetReason())
	}
	if sc.UserID != "u-123" {
		t.Fatalf("expected user id from token")
	}
}

func TestJWTStep_RejectsAlgNone(t *testing.T) {
	cfg := Config{
		JWTSecret:     "secret",
		JWTAlgorithms: []string{"HS256"},
		PublicPaths:   []string{"/healthz"},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub": "admin",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})
	unsigned, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	step := NewJWTStep(cfg)
	sc := NewSecurityContext(&pb.VerifyRequest{
		Path:    "/api/v1/orders",
		Method:  "GET",
		Headers: map[string]string{"authorization": "Bearer " + unsigned},
	})
	step.Execute(context.Background(), sc)
	if !sc.Denied {
		t.Fatalf("expected deny for alg=none")
	}
	if sc.Response.GetHttpStatus() != 401 {
		t.Fatalf("expected 401, got %d", sc.Response.GetHttpStatus())
	}
}
