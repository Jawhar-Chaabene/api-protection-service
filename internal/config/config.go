package config

import "os"

type Config struct {
	Port        string
	ServiceName string
}

func Load() Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	serviceName := os.Getenv("SERVICE_NAME")
	if serviceName == "" {
		serviceName = "api-protection-service"
	}

	return Config{
		Port:        port,
		ServiceName: serviceName,
	}
}