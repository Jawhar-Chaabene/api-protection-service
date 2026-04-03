package pipeline

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

var mongoOperatorPattern = regexp.MustCompile(`"\s*\$[a-zA-Z0-9_]+\s*"\s*:`)

// RequestValidatorStep validates path/method/headers and suspicious payloads.
type RequestValidatorStep struct {
	cfg Config
}

func NewRequestValidatorStep(cfg Config) *RequestValidatorStep {
	return &RequestValidatorStep{cfg: cfg}
}

func (s *RequestValidatorStep) Name() string { return "request_validator" }

func (s *RequestValidatorStep) Execute(_ context.Context, sc *SecurityContext) {
	path := sc.Request.GetPath()
	method := strings.ToUpper(sc.Request.GetMethod())

	if path == "" || !strings.HasPrefix(path, "/") {
		sc.Deny(400, denyReasonValidation, "invalid path")
		return
	}
	if !isAllowedMethod(method) {
		sc.Deny(400, denyReasonValidation, "invalid method")
		return
	}
	if hasDuplicateQueryKeys(path) {
		sc.Deny(400, denyReasonValidation, "duplicate query parameters not allowed")
		return
	}

	if isHiddenPath(path) && !hasRole(sc.Roles, "admin") {
		sc.Deny(403, denyReasonValidation, "hidden endpoint is not accessible")
		return
	}

	contentType := strings.ToLower(headerValue(sc.Request.GetHeaders(), "content-type"))
	contentLength := len(sc.Request.GetBody())
	if strings.Contains(contentType, "multipart/form-data") && int64(contentLength) > s.cfg.UploadMaxBytes {
		sc.Deny(400, denyReasonValidation, "upload payload exceeds size limit")
		return
	}
	if int64(contentLength) > s.cfg.MaxBodyBytes {
		sc.Deny(400, denyReasonValidation, "request body too large")
		return
	}

	// NoSQL and basic auth bypass payload checks.
	body := string(sc.Request.GetBody())
	if strings.Contains(path, "/api/v1/login") && body != "" {
		if mongoOperatorPattern.MatchString(body) || strings.Contains(body, "' || '1'=='1") {
			sc.Deny(400, denyReasonValidation, "suspicious login payload")
			return
		}
	}

	// Mass assignment protection at gateway layer for users creation.
	if method == "POST" && strings.HasPrefix(path, "/api/v1/users") && body != "" {
		var payload map[string]any
		if err := json.Unmarshal(sc.Request.GetBody(), &payload); err == nil {
			for field := range payload {
				if field != "email" && field != "password" {
					sc.Deny(400, denyReasonValidation, "mass assignment field denied: "+field)
					return
				}
			}
		}
	}
}

func isAllowedMethod(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}

func hasDuplicateQueryKeys(path string) bool {
	idx := strings.Index(path, "?")
	if idx < 0 || idx == len(path)-1 {
		return false
	}
	values, err := url.ParseQuery(path[idx+1:])
	if err != nil {
		return true
	}
	for _, list := range values {
		if len(list) > 1 {
			return true
		}
	}
	return false
}

func isHiddenPath(path string) bool {
	hidden := []string{"/admin", "/internal", "/debug", "/v2/api-docs"}
	for _, prefix := range hidden {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
