package pipeline

import (
	"context"
	"testing"

	pb "api-protection/proto/genProto"
)

func TestRBACStep_BOLADeniedForDifferentAccount(t *testing.T) {
	step := NewRBACStep(Config{PublicPaths: []string{"/healthz", "/api/v1/login"}})
	sc := NewSecurityContext(&pb.VerifyRequest{
		Path:   "/api/v1/accounts/9999/transactions",
		Method: "GET",
	})
	sc.UserID = "1001"
	sc.Roles = []string{"user"}
	step.Execute(context.Background(), sc)
	if !sc.Denied {
		t.Fatalf("expected BOLA deny")
	}
	if sc.Response.GetHttpStatus() != 403 {
		t.Fatalf("expected 403")
	}
}

func TestRBACStep_AllowsAdminDeleteUser(t *testing.T) {
	step := NewRBACStep(Config{PublicPaths: []string{"/healthz", "/api/v1/login"}})
	sc := NewSecurityContext(&pb.VerifyRequest{
		Path:   "/api/v1/users/2",
		Method: "DELETE",
	})
	sc.UserID = "admin-1"
	sc.Roles = []string{"admin"}
	step.Execute(context.Background(), sc)
	if sc.Denied {
		t.Fatalf("admin delete should pass")
	}
}
