package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

// APIKeyRecord is the normalized key document returned by storage.
type APIKeyRecord struct {
	ID        string
	Status    string
	OwnerID   string
	ExpiresAt time.Time
}

// APIKeyRepository validates API keys against storage.
type APIKeyRepository interface {
	ValidateAPIKey(ctx context.Context, keyHash string) (*APIKeyRecord, error)
}

// APIKeyStep validates x-api-key values for protected paths.
type APIKeyStep struct {
	cfg   Config
	store APIKeyRepository
}

func NewAPIKeyStep(cfg Config, store APIKeyRepository) *APIKeyStep {
	return &APIKeyStep{cfg: cfg, store: store}
}

func (s *APIKeyStep) Name() string { return "api_key_validator" }

func (s *APIKeyStep) Execute(ctx context.Context, sc *SecurityContext) {
	if !s.cfg.RequireAPIKey || isPublicPath(sc.Request.GetPath(), s.cfg.PublicPaths) {
		return
	}
	key := sc.Request.GetApiKey()
	if key == "" {
		key = headerValue(sc.Request.GetHeaders(), "x-api-key")
	}
	if key == "" {
		sc.Deny(403, denyReasonAPIKey, "missing api key")
		return
	}
	if s.store == nil {
		sc.Deny(403, denyReasonAPIKey, "api key store unavailable")
		return
	}

	hash := sha256.Sum256([]byte(key))
	record, err := s.store.ValidateAPIKey(ctx, hex.EncodeToString(hash[:]))
	if err != nil {
		if errors.Is(err, ErrAPIKeyNotFound) {
			sc.Deny(403, denyReasonAPIKey, "invalid api key")
			return
		}
		sc.Deny(403, denyReasonAPIKey, "api key validation failed")
		return
	}
	if record.Status != "active" {
		sc.Deny(403, denyReasonAPIKey, "api key inactive")
		return
	}
	if !record.ExpiresAt.IsZero() && record.ExpiresAt.Before(time.Now().UTC()) {
		sc.Deny(403, denyReasonAPIKey, "api key expired")
		return
	}
	sc.APIKeyID = record.ID
	if sc.UserID == "" && record.OwnerID != "" {
		sc.UserID = record.OwnerID
	}
}

// ErrAPIKeyNotFound indicates no API key matched the supplied hash.
var ErrAPIKeyNotFound = errors.New("api key not found")
