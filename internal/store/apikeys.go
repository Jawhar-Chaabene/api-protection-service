package store

import (
	"context"

	"api-protection/internal/pipeline"
)

// APIKeyStore abstracts API key reads for the security pipeline.
type APIKeyStore interface {
	ValidateAPIKey(ctx context.Context, keyHash string) (*pipeline.APIKeyRecord, error)
}
