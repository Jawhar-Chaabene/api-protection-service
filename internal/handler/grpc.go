package handler

import (
	"context"

	pb "api-protection/proto/genProto"
	"api-protection/internal/service"
)

// SecurityGRPCHandler adapts the gRPC SecurityServiceServer interface to our business logic.
type SecurityGRPCHandler struct {
	pb.UnimplementedSecurityServiceServer
	svc *service.SecurityService
}

// NewSecurityGRPCHandler builds a handler that delegates to the given service.
func NewSecurityGRPCHandler(svc *service.SecurityService) *SecurityGRPCHandler {
	return &SecurityGRPCHandler{svc: svc}
}

// Verify forwards the gRPC call to the security service.
func (h *SecurityGRPCHandler) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	return h.svc.Verify(ctx, req)
}
