package app

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"secure-code-retrieval-mcp/internal/auth"
	"secure-code-retrieval-mcp/internal/domain"
	"secure-code-retrieval-mcp/internal/gateway"
	"secure-code-retrieval-mcp/internal/mcp"
)

func NewHTTPHandler(service *gateway.Service, authn *auth.Service, readiness *readinessProbe, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		results := readiness.Check(ctx)
		if err := readinessError(results); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status":       "not_ready",
				"dependencies": results,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":       "ready",
			"dependencies": results,
		})
	})
	mux.Handle("/v1/audit/", authenticate(authn, logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/v1/audit/")
		if id == "" {
			writeAPIError(w, http.StatusBadRequest, apiError{Code: "invalid_request", Message: "missing audit request id", RequestID: domain.RequestIDFromContext(r.Context())})
			return
		}
		bundle, err := service.GetAudit(r.Context(), id)
		if err != nil {
			status, payload := classifyError(err)
			payload.RequestID = domain.RequestIDFromContext(r.Context())
			logger.Error("audit request failed", "err", err, "request_id", payload.RequestID)
			writeAPIError(w, status, payload)
			return
		}
		writeJSON(w, http.StatusOK, bundle)
	})))
	mux.Handle("/mcp", authenticate(authn, logger, mcp.NewServer(service, logger)))

	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, status int, payload apiError) {
	writeJSON(w, status, payload)
}

func authenticate(authn *auth.Service, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-Id")
		if requestID == "" {
			requestID = "http_" + strconv.FormatInt(time.Now().UnixNano(), 10)
		}
		if r.URL.Path == "/mcp" {
			if err := validateMCPOrigin(r); err != nil {
				logger.Error("origin validation failed", "err", err, "request_id", requestID)
				writeAPIError(w, http.StatusForbidden, apiError{Code: "forbidden", Message: "origin not allowed", RequestID: requestID})
				return
			}
		}
		claims, err := authn.AuthenticateHTTPRequest(r)
		if err != nil {
			logger.Error("authentication failed", "err", err, "request_id", requestID)
			writeAPIError(w, http.StatusUnauthorized, apiError{Code: "unauthorized", Message: "authentication required", RequestID: requestID})
			return
		}
		ctx := domain.WithRequestMetadata(r.Context(), requestID, claims.Subject, claims.Roles)
		ctx = auth.WithClaims(ctx, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func validateMCPOrigin(r *http.Request) error {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return nil
	}
	if strings.EqualFold(origin, "null") {
		return domain.ErrForbidden
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return domain.ErrForbidden
	}
	requestHost := forwardedHost(r)
	if !sameOriginHostPort(u.Host, requestHost, forwardedProto(r, u.Scheme)) {
		return domain.ErrForbidden
	}
	return nil
}

func forwardedHost(r *http.Request) string {
	if host := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0]); host != "" {
		return host
	}
	return r.Host
}

func forwardedProto(r *http.Request, fallback string) string {
	if proto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); proto != "" {
		return proto
	}
	if r.TLS != nil {
		return "https"
	}
	if fallback != "" {
		return fallback
	}
	return "http"
}

func sameOriginHostPort(originHost, requestHost, scheme string) bool {
	originName, originPort := splitHostPort(originHost)
	requestName, requestPort := splitHostPort(requestHost)
	if !strings.EqualFold(originName, requestName) {
		return false
	}
	if originPort == "" || requestPort == "" {
		return true
	}
	defaultPort := "80"
	if strings.EqualFold(scheme, "https") {
		defaultPort = "443"
	}
	if originPort == defaultPort {
		originPort = ""
	}
	if requestPort == defaultPort {
		requestPort = ""
	}
	return originPort == requestPort
}

func splitHostPort(host string) (string, string) {
	if strings.HasPrefix(host, "[") {
		if parsedHost, parsedPort, err := net.SplitHostPort(host); err == nil {
			return parsedHost, parsedPort
		}
	}
	if strings.Count(host, ":") == 1 {
		if parsedHost, parsedPort, err := net.SplitHostPort(host); err == nil {
			return parsedHost, parsedPort
		}
	}
	return host, ""
}
