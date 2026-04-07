package domain

import "context"

type contextKey string

const (
	requestIDKey contextKey = "request_id"
	tenantIDKey  contextKey = "tenant_id"
	principalKey contextKey = "caller_principal"
)

func WithRequestMetadata(ctx context.Context, requestID, tenantID, principal string) context.Context {
	ctx = context.WithValue(ctx, requestIDKey, requestID)
	ctx = context.WithValue(ctx, tenantIDKey, tenantID)
	ctx = context.WithValue(ctx, principalKey, principal)
	return ctx
}
