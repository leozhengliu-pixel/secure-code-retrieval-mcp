package app

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"secure-code-retrieval-mcp/internal/auth"
	"secure-code-retrieval-mcp/internal/domain"
	"secure-code-retrieval-mcp/internal/gateway"
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
	mux.Handle("/v1/search", authenticate(authn, logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAPIError(w, http.StatusMethodNotAllowed, apiError{Code: "invalid_request", Message: "method not allowed", RequestID: domain.RequestIDFromContext(r.Context())})
			return
		}
		var req gateway.SearchInput
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			writeAPIError(w, http.StatusBadRequest, apiError{Code: "invalid_request", Message: "invalid json body", RequestID: domain.RequestIDFromContext(r.Context())})
			return
		}
		if req.CallerPrincipal != "" {
			writeAPIError(w, http.StatusBadRequest, apiError{Code: "invalid_request", Message: "caller_principal must not be supplied", RequestID: domain.RequestIDFromContext(r.Context())})
			return
		}
		claims, _ := auth.ClaimsFromContext(r.Context())
		req.CallerPrincipal = claims.Subject
		req.CallerRoles = claims.Roles
		resp, err := service.Search(r.Context(), req)
		if err != nil {
			status, payload := classifyError(err)
			payload.RequestID = domain.RequestIDFromContext(r.Context())
			logger.Error("search request failed", "err", err, "request_id", payload.RequestID)
			writeAPIError(w, status, payload)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})))

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
