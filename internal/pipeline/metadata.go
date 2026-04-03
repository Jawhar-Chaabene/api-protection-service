package pipeline

import (
	"context"
	"strings"

	"api-protection/pkg/sanitize"
)

// MetadataStep extracts and sanitizes request metadata.
type MetadataStep struct{}

func NewMetadataStep() *MetadataStep { return &MetadataStep{} }

func (s *MetadataStep) Name() string { return "metadata_extractor" }

func (s *MetadataStep) Execute(_ context.Context, sc *SecurityContext) {
	headers := sc.Request.GetHeaders()
	if headers == nil {
		return
	}
	if v := sanitize.Metadata(headers["x-user-id"]); v != "" {
		sc.UserID = v
	}
	if v := sanitize.Metadata(headers["x-client-ip"]); v != "" && sc.Request.GetClientIp() == "" {
		sc.ClientIP = v
	}
	if sc.Request.GetApiKey() == "" {
		if v := sanitize.Metadata(headers["x-api-key"]); v != "" {
			sc.Request.ApiKey = v
		}
	}
	if len(sc.Roles) == 0 {
		roleVal := sanitize.Metadata(headers["x-roles"])
		sc.Roles = parseRoles(roleVal)
	}
}

func parseRoles(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
