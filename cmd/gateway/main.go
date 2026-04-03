package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"api-protection/internal/gateway"
	"api-protection/internal/middleware"
	pb "api-protection/proto/genProto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	cfg := gateway.LoadConfig()

	conn, err := grpc.Dial(cfg.SecurityServiceAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("gateway: failed to connect to security service: %v", err)
	}
	defer conn.Close()
	securityClient := pb.NewSecurityServiceClient(conn)

	proxy, err := gateway.NewReverseProxy(cfg.BackendURL)
	if err != nil {
		log.Fatalf("gateway: invalid BACKEND_URL: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		_, err := securityClient.Verify(r.Context(), &pb.VerifyRequest{
			Path:      "/healthz",
			Method:    "GET",
			ClientIp:  clientIPFromRequest(r),
			RequestId: middleware.GetRequestID(r.Context()),
			Headers:   map[string]string{},
		})
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "not_ready"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	})

	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, cfg.MaxForwardBodyBytes))
		if err != nil {
			respondDenied(w, http.StatusBadRequest, "failed to read request body", middleware.GetRequestID(r.Context()))
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))

		verifyReq := &pb.VerifyRequest{
			Path:      r.URL.RequestURI(),
			Method:    r.Method,
			ClientIp:  clientIPFromRequest(r),
			Headers:   flattenHeaders(r.Header),
			UserId:    r.Header.Get("x-user-id"),
			Roles:     splitRoles(r.Header.Get("x-roles")),
			ApiKey:    r.Header.Get("x-api-key"),
			RequestId: middleware.GetRequestID(r.Context()),
			Body:      body,
		}

		verifyResp, err := securityClient.Verify(r.Context(), verifyReq)
		if err != nil {
			respondDenied(w, http.StatusBadGateway, "security service unavailable", verifyReq.GetRequestId())
			return
		}
		if verifyResp.GetVerdict() == pb.Verdict_DENY {
			status := int(verifyResp.GetHttpStatus())
			if status == 0 {
				status = http.StatusForbidden
			}
			respondDenied(w, status, verifyResp.GetReason(), verifyResp.GetCorrelationId())
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		proxy.ServeHTTP(w, r)
	}))

	handler := middleware.Recovery(
		middleware.Timeout(cfg.RequestTimeout)(
			middleware.Logging(
				middleware.RequestID(mux),
			),
		),
	)

	addr := ":" + cfg.Port
	log.Printf("gateway listening on %s", addr)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("gateway: listen failed: %v", err)
	}
}

func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, values := range h {
		if len(values) == 0 {
			continue
		}
		out[strings.ToLower(k)] = values[0]
	}
	return out
}

func splitRoles(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func clientIPFromRequest(r *http.Request) string {
	hostPort := strings.TrimSpace(r.RemoteAddr)
	if hostPort == "" {
		return "unknown"
	}
	if idx := strings.LastIndex(hostPort, ":"); idx > 0 {
		return hostPort[:idx]
	}
	return hostPort
}

func respondDenied(w http.ResponseWriter, status int, reason, correlationID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":          reason,
		"correlation_id": correlationID,
		"status":         status,
	})
}
