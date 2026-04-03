package middleware

import (
	"log"
	"net/http"
	"time"
)

type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.status = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

// Logging logs request method/path/status/latency.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Printf("gateway request_id=%s method=%s path=%s status=%d duration_ms=%d",
			GetRequestID(r.Context()),
			r.Method,
			r.URL.RequestURI(),
			rec.status,
			time.Since(start).Milliseconds(),
		)
	})
}
