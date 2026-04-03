package gateway

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port                string
	SecurityServiceAddr string
	BackendURL          string
	RequestTimeout      time.Duration
	MaxForwardBodyBytes int64
}

func LoadConfig() Config {
	return Config{
		Port:                getEnv("GATEWAY_PORT", "8080"),
		SecurityServiceAddr: getEnv("SECURITY_SERVICE_ADDR", "localhost:50051"),
		BackendURL:          getEnv("BACKEND_URL", "http://localhost:3000"),
		RequestTimeout:      time.Duration(getInt("GATEWAY_TIMEOUT_SECONDS", 30)) * time.Second,
		MaxForwardBodyBytes: int64(getInt("GATEWAY_MAX_BODY_BYTES", 1048576)),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getInt(key string, fallback int) int {
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
