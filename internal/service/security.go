package service

import (
	"context"
	"log"
	"strings"
	"time"

	"api-protection/internal/interceptor"
	"api-protection/internal/store"
	"api-protection/pkg/kafka"
	pb "api-protection/proto/genProto"
)

// AlertPublisher publishes security alerts to a messaging system.
type AlertPublisher interface {
	PublishAlert(ctx context.Context, record *kafka.AlertRecord) error
}

// SecurityService holds the business logic for request verification.
type SecurityService struct {
	store          store.Store
	alertPublisher AlertPublisher
	rbac           RBACChecker
}

// NewSecurityService creates a new security service instance.
func NewSecurityService(store store.Store, alertPublisher AlertPublisher, rbac RBACChecker) *SecurityService {
	if rbac == nil {
		rbac = &DefaultRBAC{}
	}
	return &SecurityService{
		store:          store,
		alertPublisher: alertPublisher,
		rbac:           rbac,
	}
}

// Verify decides whether to allow or deny a request.
func (s *SecurityService) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	resp := &pb.VerifyResponse{
		Verdict: pb.Verdict_ALLOW,
		Reason:  "",
	}

	// 1. Validation (fail-fast)
	if err := ValidateRequest(req); err != nil {
		resp.Verdict = pb.Verdict_DENY
		resp.Reason = "validation: " + formatValidationError(err)
		return s.finishVerify(ctx, req, resp), nil
	}

	// 2. RBAC + Object-level
	userID := interceptor.UserIDFromContext(ctx)
	roles := interceptor.RolesFromContext(ctx)
	if allowed, reason := s.rbac.CanAccess(userID, roles, req.GetPath(), req.GetMethod()); !allowed {
		resp.Verdict = pb.Verdict_DENY
		resp.Reason = reason
		return s.finishVerify(ctx, req, resp), nil
	}

	return s.finishVerify(ctx, req, resp), nil
}

func (s *SecurityService) finishVerify(ctx context.Context, req *pb.VerifyRequest, resp *pb.VerifyResponse) *pb.VerifyResponse {
	if err := s.store.SaveLog(ctx, req, resp); err != nil {
		log.Printf("service: SaveLog failed (verdict still returned): %v", err)
	}

	if resp.Verdict == pb.Verdict_DENY && s.alertPublisher != nil {
		record := &kafka.AlertRecord{
			Path:      req.GetPath(),
			Method:    req.GetMethod(),
			ClientIP:  req.GetClientIp(),
			Verdict:   resp.GetVerdict().String(),
			Reason:    resp.GetReason(),
			Timestamp: time.Now().UTC(),
		}
		go func() {
			if err := s.alertPublisher.PublishAlert(context.Background(), record); err != nil {
				log.Printf("service: PublishAlert failed: %v", err)
			}
		}()
	}

	return resp
}

func formatValidationError(err error) string {
	if err == nil {
		return ""
	}
	return strings.ReplaceAll(err.Error(), "\n", "; ")
}
