package tests

import (
	"context"
	"net"
	"testing"
	"time"

	"api-protection/internal/handler"
	"api-protection/internal/pipeline"
	"api-protection/internal/service"
	"api-protection/internal/store"
	"api-protection/pkg/kafka"
	pb "api-protection/proto/genProto"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type fakeStore struct {
	logs []*pb.VerifyResponse
}

func (f *fakeStore) SaveLog(_ context.Context, _ *pb.VerifyRequest, response *pb.VerifyResponse) error {
	f.logs = append(f.logs, response)
	return nil
}

func (f *fakeStore) ValidateAPIKey(_ context.Context, _ string) (*pipeline.APIKeyRecord, error) {
	return &pipeline.APIKeyRecord{
		ID:        "seed-test-key",
		Status:    "active",
		OwnerID:   "1001",
		ExpiresAt: time.Now().Add(time.Hour),
	}, nil
}

func (f *fakeStore) GetPolicy(_ context.Context, _ string, _ string) (*store.Policy, error) {
	return nil, nil
}

type fakePublisher struct{}

func (f *fakePublisher) PublishAlert(_ context.Context, _ *kafka.AlertRecord) error { return nil }

func startSecurityServer(t *testing.T, cfg pipeline.Config) (pb.SecurityServiceClient, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fs := &fakeStore{}
	pipe := pipeline.BuildDefaultPipeline(cfg, fs)
	svc := service.NewSecurityService(fs, &fakePublisher{}, pipe)
	s := grpc.NewServer()
	pb.RegisterSecurityServiceServer(s, handler.NewSecurityGRPCHandler(svc))
	go s.Serve(lis)

	conn, err := grpc.Dial(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	client := pb.NewSecurityServiceClient(conn)
	cleanup := func() {
		conn.Close()
		s.Stop()
		lis.Close()
	}
	return client, cleanup
}

func signedToken(t *testing.T, userID string, roles []string, secret string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   userID,
		"roles": roles,
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	s, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func baseConfig() pipeline.Config {
	return pipeline.Config{
		JWTSecret:      "secret",
		JWTAlgorithms:  []string{"HS256"},
		RequireAPIKey:  true,
		PublicPaths:    []string{"/healthz", "/api/v1/login"},
		MaxBodyBytes:   2048,
		UploadMaxBytes: 2048,
		RateLimitRPS:   100,
		RateLimitBurst: 100,
	}
}

func TestVerify_AllowFlow(t *testing.T) {
	client, cleanup := startSecurityServer(t, baseConfig())
	defer cleanup()

	resp, err := client.Verify(context.Background(), &pb.VerifyRequest{
		Path:     "/api/v1/accounts/1001/transactions",
		Method:   "GET",
		ClientIp: "1.2.3.4",
		ApiKey:   "test-api-key",
		Headers: map[string]string{
			"authorization": "Bearer " + signedToken(t, "1001", []string{"user"}, "secret"),
			"x-api-key":     "test-api-key",
		},
		RequestId: "req-allow",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetVerdict() != pb.Verdict_ALLOW {
		t.Fatalf("expected ALLOW, got %v (%s)", resp.GetVerdict(), resp.GetReason())
	}
}

func TestVerify_DenyInvalidToken(t *testing.T) {
	client, cleanup := startSecurityServer(t, baseConfig())
	defer cleanup()

	resp, err := client.Verify(context.Background(), &pb.VerifyRequest{
		Path:      "/api/v1/orders",
		Method:    "GET",
		ClientIp:  "1.2.3.4",
		ApiKey:    "test-api-key",
		RequestId: "req-invalid-token",
		Headers: map[string]string{
			"authorization": "Bearer invalid.token.here",
			"x-api-key":     "test-api-key",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetVerdict() != pb.Verdict_DENY || resp.GetHttpStatus() != 401 {
		t.Fatalf("expected 401 deny, got verdict=%v status=%d reason=%s", resp.GetVerdict(), resp.GetHttpStatus(), resp.GetReason())
	}
}

func TestVerify_BOLAOwnerDenied(t *testing.T) {
	client, cleanup := startSecurityServer(t, baseConfig())
	defer cleanup()

	resp, err := client.Verify(context.Background(), &pb.VerifyRequest{
		Path:      "/api/v1/accounts/9999/transactions",
		Method:    "GET",
		ClientIp:  "1.2.3.4",
		ApiKey:    "test-api-key",
		RequestId: "req-bola",
		Headers: map[string]string{
			"authorization": "Bearer " + signedToken(t, "1001", []string{"user"}, "secret"),
			"x-api-key":     "test-api-key",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetVerdict() != pb.Verdict_DENY || resp.GetHttpStatus() != 403 {
		t.Fatalf("expected 403 deny, got verdict=%v status=%d reason=%s", resp.GetVerdict(), resp.GetHttpStatus(), resp.GetReason())
	}
}

func TestVerify_RateLimit429(t *testing.T) {
	cfg := baseConfig()
	cfg.RateLimitRPS = 1
	cfg.RateLimitBurst = 1
	client, cleanup := startSecurityServer(t, cfg)
	defer cleanup()

	req := &pb.VerifyRequest{
		Path:      "/api/v1/login",
		Method:    "POST",
		ClientIp:  "1.2.3.4",
		RequestId: "req-rate-limit",
	}
	_, _ = client.Verify(context.Background(), req)
	resp, err := client.Verify(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetVerdict() != pb.Verdict_DENY || resp.GetHttpStatus() != 429 {
		t.Fatalf("expected 429 deny, got verdict=%v status=%d reason=%s", resp.GetVerdict(), resp.GetHttpStatus(), resp.GetReason())
	}
}

func TestVerify_InvalidAPIKeyDenied(t *testing.T) {
	cfg := baseConfig()
	client, cleanup := startSecurityServer(t, cfg)
	defer cleanup()

	// Missing API key in protected route.
	resp, err := client.Verify(context.Background(), &pb.VerifyRequest{
		Path:      "/api/v1/orders",
		Method:    "GET",
		ClientIp:  "1.2.3.4",
		RequestId: "req-no-api-key",
		Headers: map[string]string{
			"authorization": "Bearer " + signedToken(t, "1001", []string{"user"}, "secret"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetVerdict() != pb.Verdict_DENY || resp.GetHttpStatus() != 403 {
		t.Fatalf("expected 403 deny for api key, got verdict=%v status=%d reason=%s", resp.GetVerdict(), resp.GetHttpStatus(), resp.GetReason())
	}
}
