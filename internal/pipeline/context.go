package pipeline

import (
	"strings"

	pb "api-protection/proto/genProto"
)

const (
	denyUnknown          = "unknown"
	denyReasonRateLimit  = "rate_limit"
	denyReasonJWT        = "jwt"
	denyReasonAPIKey     = "api_key"
	denyReasonValidation = "validation"
	denyReasonRBAC       = "rbac"
)

// SecurityContext stores shared state across pipeline steps.
type SecurityContext struct {
	Request      *pb.VerifyRequest
	Response     *pb.VerifyResponse
	UserID       string
	Roles        []string
	APIKeyID     string
	RequestID    string
	ClientIP     string
	DecisionCode string
	Denied       bool
}

// NewSecurityContext initializes context with ALLOW by default.
func NewSecurityContext(req *pb.VerifyRequest) *SecurityContext {
	resp := &pb.VerifyResponse{
		Verdict:       pb.Verdict_ALLOW,
		Reason:        "",
		HttpStatus:    200,
		CorrelationId: req.GetRequestId(),
	}
	return &SecurityContext{
		Request:   req,
		Response:  resp,
		RequestID: req.GetRequestId(),
		ClientIP:  req.GetClientIp(),
		UserID:    req.GetUserId(),
		Roles:     append([]string(nil), req.GetRoles()...),
	}
}

// Deny marks the request as denied and sets response details.
func (sc *SecurityContext) Deny(status int32, code, reason string) {
	sc.Denied = true
	sc.DecisionCode = code
	sc.Response.Verdict = pb.Verdict_DENY
	sc.Response.HttpStatus = status
	sc.Response.Reason = strings.TrimSpace(reason)
	sc.Response.UserId = sc.UserID
	sc.Response.Roles = append([]string(nil), sc.Roles...)
	if sc.Response.CorrelationId == "" {
		sc.Response.CorrelationId = sc.RequestID
	}
}

// FinalizeAllow keeps ALLOW response fields consistent.
func (sc *SecurityContext) FinalizeAllow() {
	sc.Response.Verdict = pb.Verdict_ALLOW
	sc.Response.HttpStatus = 200
	sc.Response.Reason = ""
	sc.Response.UserId = sc.UserID
	sc.Response.Roles = append([]string(nil), sc.Roles...)
	if sc.Response.CorrelationId == "" {
		sc.Response.CorrelationId = sc.RequestID
	}
}
