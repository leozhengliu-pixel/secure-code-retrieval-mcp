package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"secure-code-retrieval-mcp/internal/auth"
	"secure-code-retrieval-mcp/internal/config"
	"secure-code-retrieval-mcp/internal/domain"
	"secure-code-retrieval-mcp/internal/gateway"
	"secure-code-retrieval-mcp/internal/metrics"
)

func TestSearchRequiresJWT(t *testing.T) {
	handler := newTestHTTPHandler(t, testAuditor{})
	req := httptest.NewRequest(http.MethodPost, "/v1/search", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestSearchRejectsCallerPrincipalInBody(t *testing.T) {
	handler := newTestHTTPHandler(t, testAuditor{})
	req := httptest.NewRequest(http.MethodPost, "/v1/search", bytes.NewBufferString(`{"policy_profile":"default","caller_principal":"mallory","source_type":"github","source_host":"github.example.com","query_text":"hello","max_results":1,"response_mode":"snippet"}`))
	req.Header.Set("Authorization", "Bearer "+testJWT(t, "alice", nil))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestAuditAllowsCallerAndAdmin(t *testing.T) {
	auditor := testAuditor{
		bundle: domain.AuditBundle{
			Request: domain.AuditRequestRecord{
				RequestID:       "req_1",
				CallerPrincipal: "alice",
				PolicyProfile:   "default",
			},
		},
	}
	handler := newTestHTTPHandler(t, auditor)

	callerReq := httptest.NewRequest(http.MethodGet, "/v1/audit/req_1", nil)
	callerReq.Header.Set("Authorization", "Bearer "+testJWT(t, "alice", nil))
	callerRec := httptest.NewRecorder()
	handler.ServeHTTP(callerRec, callerReq)
	if callerRec.Code != http.StatusOK {
		t.Fatalf("expected caller to pass, got %d", callerRec.Code)
	}

	otherReq := httptest.NewRequest(http.MethodGet, "/v1/audit/req_1", nil)
	otherReq.Header.Set("Authorization", "Bearer "+testJWT(t, "bob", nil))
	otherRec := httptest.NewRecorder()
	handler.ServeHTTP(otherRec, otherReq)
	if otherRec.Code != http.StatusForbidden {
		t.Fatalf("expected non-owner forbidden, got %d", otherRec.Code)
	}

	adminReq := httptest.NewRequest(http.MethodGet, "/v1/audit/req_1", nil)
	adminReq.Header.Set("Authorization", "Bearer "+testJWT(t, "admin", []string{"scrm_admin"}))
	adminRec := httptest.NewRecorder()
	handler.ServeHTTP(adminRec, adminReq)
	if adminRec.Code != http.StatusOK {
		t.Fatalf("expected admin to pass, got %d", adminRec.Code)
	}
}

func TestReadyzReturnsStructuredFailure(t *testing.T) {
	handler := newTestHTTPHandlerWithReadiness(t, testAuditor{}, map[string]readinessCheck{
		"database": func(context.Context) error { return io.EOF },
	})
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["status"] != "not_ready" {
		t.Fatalf("expected not_ready payload, got %#v", payload)
	}
}

func newTestHTTPHandler(t *testing.T, auditor testAuditor) http.Handler {
	return newTestHTTPHandlerWithReadiness(t, auditor, map[string]readinessCheck{"database": func(context.Context) error { return nil }})
}

func newTestHTTPHandlerWithReadiness(t *testing.T, auditor testAuditor, checks map[string]readinessCheck) http.Handler {
	t.Helper()
	authService, err := auth.New(testAuthConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	service := gateway.NewService(gateway.Dependencies{
		Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		Timeout:              time.Second,
		DefaultPolicyProfile: "default",
		AdminRole:            "scrm_admin",
		Metrics:              metrics.New(),
		GitHub:               testConnector{},
		GitLab:               testConnector{},
		Policy:               testPolicy{},
		Sanitizer:            testSanitizer{},
		Auditor:              auditor,
	})
	return NewHTTPHandler(service, authService, newReadinessProbe(metrics.New(), checks), slog.New(slog.NewTextHandler(io.Discard, nil)))
}

type testConnector struct{}

func (testConnector) Search(context.Context, domain.SearchRequest) ([]domain.SearchResult, error) {
	return []domain.SearchResult{{Repository: "repo", FilePath: "main.go", SnippetTextRaw: "hello"}}, nil
}

type testPolicy struct{}

func (testPolicy) Evaluate(context.Context, domain.SearchRequest, domain.SearchResult) (domain.PolicyDecision, error) {
	return domain.PolicyDecision{Decision: domain.DecisionAllow, ExportAllowed: true}, nil
}

type testSanitizer struct{}

func (testSanitizer) Sanitize(context.Context, domain.SearchRequest, domain.SearchResult, domain.PolicyDecision) (domain.SanitizedResult, bool, error) {
	return domain.SanitizedResult{ReleaseMode: "snippet", SnippetText: "hello"}, false, nil
}

type testAuditor struct {
	bundle domain.AuditBundle
}

func (a testAuditor) RecordRequest(context.Context, domain.AuditRequestRecord) (string, error) {
	return "audit_1", nil
}

func (testAuditor) RecordDecision(context.Context, domain.AuditDecisionRecord) error { return nil }
func (testAuditor) RecordDelivery(context.Context, domain.AuditDeliveryRecord) error { return nil }
func (a testAuditor) GetBundle(context.Context, string) (domain.AuditBundle, error) {
	return a.bundle, nil
}

var testPrivateKey *rsa.PrivateKey

func testJWT(t *testing.T, subject string, roles []string) string {
	t.Helper()
	if testPrivateKey == nil {
		var err error
		testPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   "issuer",
		"aud":   "aud",
		"sub":   subject,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"roles": roles,
	})
	signed, err := token.SignedString(testPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func testAuthConfig(t *testing.T) config.AuthConfig {
	t.Helper()
	if testPrivateKey == nil {
		var err error
		testPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&testPrivateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return config.AuthConfig{
		Issuer:       "issuer",
		Audience:     "aud",
		PublicKeyPEM: string(pubPEM),
		AdminRole:    "scrm_admin",
	}
}
