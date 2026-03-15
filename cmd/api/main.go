package main

import (
	"log"
	"net/http"

	"github.com/jawhar-chaabene/api-protection-service/internal/config"
	"github.com/jawhar-chaabene/api-protection-service/internal/handler"
)

func main() {
	cfg := config.Load()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handler.Health(cfg.ServiceName))

	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: mux,
	}

	log.Printf("%s running on http://localhost:%s", cfg.ServiceName, cfg.Port)
	log.Printf("Health endpoint: http://localhost:%s/health", cfg.Port)

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}