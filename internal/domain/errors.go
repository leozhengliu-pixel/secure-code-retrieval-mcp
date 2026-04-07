package domain

import "errors"

var (
	ErrInvalidRequest    = errors.New("invalid request")
	ErrMissingTenant     = errors.New("missing tenant context")
	ErrMissingPrincipal  = errors.New("missing caller principal")
	ErrConnector         = errors.New("connector error")
	ErrProxyConfig       = errors.New("proxy configuration error")
	ErrProxyConnect      = errors.New("proxy connection error")
	ErrProxyAuth         = errors.New("proxy authentication error")
	ErrProxyTimeout      = errors.New("proxy timeout")
	ErrPolicyEvaluation  = errors.New("policy evaluation error")
	ErrSanitization      = errors.New("sanitization error")
	ErrAuditPersistence  = errors.New("audit persistence error")
	ErrUnsupportedFilter = errors.New("unsupported filter")
	ErrUnauthorized      = errors.New("unauthorized")
)
