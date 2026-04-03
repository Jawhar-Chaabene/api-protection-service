package store

import "context"

// PolicyStore abstracts policy reads for optional route policy checks.
type PolicyStore interface {
	GetPolicy(ctx context.Context, path, method string) (*Policy, error)
}
