package domain

import "context"

type contextKey string

const (
	requestIDKey contextKey = "request_id"
	principalKey contextKey = "caller_principal"
	rolesKey     contextKey = "roles"
)

func WithRequestMetadata(ctx context.Context, requestID, principal string, roles []string) context.Context {
	ctx = context.WithValue(ctx, requestIDKey, requestID)
	ctx = context.WithValue(ctx, principalKey, principal)
	ctx = context.WithValue(ctx, rolesKey, roles)
	return ctx
}

func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

func PrincipalFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(principalKey).(string); ok {
		return v
	}
	return ""
}

func RolesFromContext(ctx context.Context) []string {
	if v, ok := ctx.Value(rolesKey).([]string); ok {
		return v
	}
	return nil
}
