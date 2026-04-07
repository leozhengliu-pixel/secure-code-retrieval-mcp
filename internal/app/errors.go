package app

import (
	"errors"

	"secure-code-retrieval-mcp/internal/domain"
)

type apiError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

func classifyError(err error) (int, apiError) {
	switch {
	case errors.Is(err, domain.ErrInvalidRequest), errors.Is(err, domain.ErrMissingPrincipal):
		return 400, apiError{Code: "invalid_request", Message: "invalid request"}
	case errors.Is(err, domain.ErrUnauthorized):
		return 401, apiError{Code: "unauthorized", Message: "authentication required"}
	case errors.Is(err, domain.ErrForbidden):
		return 403, apiError{Code: "forbidden", Message: "access denied"}
	case errors.Is(err, domain.ErrNotFound):
		return 404, apiError{Code: "not_found", Message: "resource not found"}
	case errors.Is(err, domain.ErrUnsupportedFilter):
		return 422, apiError{Code: "unsupported_filter", Message: "unsupported filter"}
	case errors.Is(err, domain.ErrConnector), errors.Is(err, domain.ErrProxyAuth), errors.Is(err, domain.ErrProxyTimeout), errors.Is(err, domain.ErrProxyConnect):
		return 502, apiError{Code: "connector_error", Message: "connector request failed"}
	case errors.Is(err, domain.ErrPolicyEvaluation):
		return 500, apiError{Code: "policy_error", Message: "policy evaluation failed"}
	case errors.Is(err, domain.ErrSanitization):
		return 500, apiError{Code: "sanitize_error", Message: "sanitization failed"}
	case errors.Is(err, domain.ErrAuditPersistence):
		return 500, apiError{Code: "audit_error", Message: "audit persistence failed"}
	case errors.Is(err, domain.ErrNotReady):
		return 503, apiError{Code: "not_ready", Message: "service is not ready"}
	default:
		return 500, apiError{Code: "internal_error", Message: "internal server error"}
	}
}
