package app

import (
	"net/http"
	"strings"
	"time"

	"secure-code-retrieval-mcp/internal/metrics"
)

func withMetrics(next http.Handler, m *metrics.Metrics) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", m.Handler())
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		sourceType := "unknown"
		switch r.URL.Path {
		case "/mcp":
			sourceType = "mcp"
		}
		if strings.HasPrefix(r.URL.Path, "/v1/audit/") {
			sourceType = "audit"
		}
		m.RequestTotal.WithLabelValues("http", sourceType, http.StatusText(recorder.status)).Inc()
		m.RequestDuration.WithLabelValues("http", sourceType).Observe(time.Since(start).Seconds())
	}))
	return mux
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}
