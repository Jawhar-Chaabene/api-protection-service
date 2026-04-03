package pipeline

import (
	"os"
	"strconv"
	"strings"
)

// Config defines runtime options for security checks.
type Config struct {
	JWTSecret        string
	JWTIssuer        string
	JWTAlgorithms    []string
	RequireAPIKey    bool
	MaxBodyBytes     int64
	UploadMaxBytes   int64
	TrustedProxy     bool
	RateLimitRPS     float64
	RateLimitBurst   int
	RequireAuthPaths []string
	PublicPaths      []string
}

// FromEnv loads pipeline config from environment variables.
func FromEnv() Config {
	cfg := Config{
		JWTSecret:      getEnv("JWT_SECRET", "change-me"),
		JWTIssuer:      getEnv("JWT_ISSUER", ""),
		JWTAlgorithms:  splitCSV(getEnv("JWT_ALGORITHMS", "HS256")),
		RequireAPIKey:  getEnv("REQUIRE_API_KEY", "true") == "true",
		MaxBodyBytes:   getInt64Env("MAX_BODY_BYTES", 1048576),
		UploadMaxBytes: getInt64Env("UPLOAD_MAX_BYTES", 10485760),
		TrustedProxy:   getEnv("TRUST_PROXY", "false") == "true",
		RateLimitRPS:   getFloat64Env("RATE_LIMIT_RPS", 10),
		RateLimitBurst: getIntEnv("RATE_LIMIT_BURST", 20),
		RequireAuthPaths: []string{
			"/api/v1/",
			"/graphql",
		},
		PublicPaths: []string{
			"/health",
			"/healthz",
			"/readyz",
			"/api/public/",
			"/api/v1/login",
		},
	}
	return cfg
}

func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getIntEnv(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func getInt64Env(key string, fallback int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fallback
	}
	return n
}

func getFloat64Env(key string, fallback float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return n
}
