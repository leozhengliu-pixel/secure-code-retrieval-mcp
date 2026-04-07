package auth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"secure-code-retrieval-mcp/internal/config"
	"secure-code-retrieval-mcp/internal/domain"
)

type Claims struct {
	Subject string
	Roles   []string
}

type Service struct {
	issuer    string
	audience  string
	adminRole string
	publicKey *rsa.PublicKey
}

func New(cfg config.AuthConfig) (*Service, error) {
	publicKeyPEM := cfg.PublicKeyPEM
	if publicKeyPEM == "" && cfg.PublicKeyEnv != "" {
		publicKeyPEM = os.Getenv(cfg.PublicKeyEnv)
	}
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("invalid jwt public key pem")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse jwt public key: %w", err)
	}
	publicKey, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("jwt public key must be RSA")
	}
	return &Service{
		issuer:    cfg.Issuer,
		audience:  cfg.Audience,
		adminRole: cfg.AdminRole,
		publicKey: publicKey,
	}, nil
}

func (s *Service) AuthenticateHTTPRequest(r *http.Request) (Claims, error) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return Claims{}, domain.ErrUnauthorized
	}
	tokenString := strings.TrimSpace(header[len("Bearer "):])
	return s.ParseToken(tokenString)
}

func (s *Service) ParseToken(tokenString string) (Claims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, domain.ErrUnauthorized
		}
		return s.publicKey, nil
	}, jwt.WithIssuer(s.issuer), jwt.WithAudience(s.audience))
	if err != nil || !token.Valid {
		return Claims{}, domain.ErrUnauthorized
	}
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return Claims{}, domain.ErrUnauthorized
	}
	subject, _ := mapClaims["sub"].(string)
	if subject == "" {
		return Claims{}, domain.ErrUnauthorized
	}
	return Claims{Subject: subject, Roles: rolesFromClaims(mapClaims["roles"])}, nil
}

func (s *Service) IsAdmin(roles []string) bool {
	for _, role := range roles {
		if role == s.adminRole {
			return true
		}
	}
	return false
}

type claimsContextKey string

const claimsKey claimsContextKey = "auth_claims"

func WithClaims(ctx context.Context, claims Claims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

func ClaimsFromContext(ctx context.Context) (Claims, bool) {
	claims, ok := ctx.Value(claimsKey).(Claims)
	return claims, ok
}

func rolesFromClaims(raw any) []string {
	switch value := raw.(type) {
	case []string:
		return value
	case []any:
		roles := make([]string, 0, len(value))
		for _, item := range value {
			if role, ok := item.(string); ok && role != "" {
				roles = append(roles, role)
			}
		}
		return roles
	case string:
		if value == "" {
			return nil
		}
		return []string{value}
	default:
		return nil
	}
}
