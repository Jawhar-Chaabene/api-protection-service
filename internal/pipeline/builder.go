package pipeline

// BuildDefaultPipeline returns the ordered 7-step security pipeline.
func BuildDefaultPipeline(cfg Config, store APIKeyRepository) *Pipeline {
	return New(
		NewRateLimiterStep(cfg),
		NewMetadataStep(),
		NewJWTStep(cfg),
		NewAPIKeyStep(cfg, store),
		NewRequestValidatorStep(cfg),
		NewRBACStep(cfg),
		NewDecisionStep(),
	)
}
