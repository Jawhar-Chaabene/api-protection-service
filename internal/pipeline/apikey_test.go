package pipeline

import (
	"context"
	"testing"
	"time"

	pb "api-protection/proto/genProto"
)

type fakeAPIKeyRepo struct {
	record *APIKeyRecord
	err    error
}

func (f *fakeAPIKeyRepo) ValidateAPIKey(_ context.Context, _ string) (*APIKeyRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.record, nil
}

func TestAPIKeyStep_DeniesInvalidKey(t *testing.T) {
	cfg := Config{RequireAPIKey: true, PublicPaths: []string{"/healthz"}}
	step := NewAPIKeyStep(cfg, &fakeAPIKeyRepo{err: ErrAPIKeyNotFound})
	sc := NewSecurityContext(&pb.VerifyRequest{
		Path:    "/api/v1/orders",
		Method:  "GET",
		ApiKey:  "bad",
		Headers: map[string]string{"x-api-key": "bad"},
	})
	step.Execute(context.Background(), sc)
	if !sc.Denied {
		t.Fatalf("expected deny for invalid key")
	}
}

func TestAPIKeyStep_AllowsActiveKey(t *testing.T) {
	cfg := Config{RequireAPIKey: true, PublicPaths: []string{"/healthz"}}
	step := NewAPIKeyStep(cfg, &fakeAPIKeyRepo{
		record: &APIKeyRecord{
			ID:        "key-1",
			Status:    "active",
			OwnerID:   "1001",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		},
	})
	sc := NewSecurityContext(&pb.VerifyRequest{
		Path:   "/api/v1/orders",
		Method: "GET",
		ApiKey: "test-api-key",
	})
	step.Execute(context.Background(), sc)
	if sc.Denied {
		t.Fatalf("expected active key allow")
	}
	if sc.APIKeyID != "key-1" {
		t.Fatalf("expected api key id set")
	}
}
