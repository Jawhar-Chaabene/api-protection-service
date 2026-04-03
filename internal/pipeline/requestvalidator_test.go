package pipeline

import (
	"context"
	"testing"

	pb "api-protection/proto/genProto"
)

func TestRequestValidatorStep_RejectsNoSQLInjection(t *testing.T) {
	step := NewRequestValidatorStep(Config{MaxBodyBytes: 1024, UploadMaxBytes: 1024})
	sc := NewSecurityContext(&pb.VerifyRequest{
		Path:   "/api/v1/login",
		Method: "POST",
		Body:   []byte(`{"username":{"$ne":null},"password":{"$ne":null}}`),
	})
	step.Execute(context.Background(), sc)
	if !sc.Denied {
		t.Fatalf("expected deny for NoSQL injection payload")
	}
}

func TestRequestValidatorStep_RejectsDuplicateQueryParams(t *testing.T) {
	step := NewRequestValidatorStep(Config{MaxBodyBytes: 1024, UploadMaxBytes: 1024})
	sc := NewSecurityContext(&pb.VerifyRequest{
		Path:   "/api/v1/products?id=1&id=2",
		Method: "GET",
	})
	step.Execute(context.Background(), sc)
	if !sc.Denied {
		t.Fatalf("expected deny for duplicate params")
	}
}
