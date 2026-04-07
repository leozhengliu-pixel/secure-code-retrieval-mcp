package gateway_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"secure-code-retrieval-mcp/internal/domain"
	"secure-code-retrieval-mcp/internal/gateway"
)

func TestSearchRejectsMissingPolicyProfile(t *testing.T) {
	svc := gateway.NewService(gateway.Dependencies{Logger: slog.Default(), Timeout: time.Second, GitHub: stubConnector{}, GitLab: stubConnector{}, Policy: stubPolicy{}, Sanitizer: stubSanitizer{}, Auditor: stubAuditor{}})
	_, err := svc.Search(context.Background(), domain.SearchRequest{CallerPrincipal: "alice", SourceType: domain.SourceTypeGitHub, SourceHost: "github.example.com", QueryText: "token", MaxResults: 1, ResponseMode: domain.ResponseModeSnippet})
	if err != domain.ErrInvalidRequest {
		t.Fatalf("expected invalid request error, got %v", err)
	}
}

type stubConnector struct{}

func (stubConnector) Search(context.Context, domain.SearchRequest) ([]domain.SearchResult, error) {
	return []domain.SearchResult{{Repository: "repo", FilePath: "main.go", SnippetTextRaw: `token = "abc"`}}, nil
}

type stubPolicy struct{}

func (stubPolicy) Evaluate(context.Context, domain.SearchRequest, domain.SearchResult) (domain.PolicyDecision, error) {
	return domain.PolicyDecision{Decision: domain.DecisionMask, ExportAllowed: true}, nil
}

type stubSanitizer struct{}

func (stubSanitizer) Sanitize(context.Context, domain.SearchRequest, domain.SearchResult, domain.PolicyDecision) (domain.SanitizedResult, bool, error) {
	return domain.SanitizedResult{ReleaseMode: "snippet", SnippetText: "[REDACTED]"}, false, nil
}

type stubAuditor struct{}

func (stubAuditor) RecordRequest(context.Context, domain.AuditRequestRecord) (string, error) {
	return "audit_1", nil
}
func (stubAuditor) RecordDecision(context.Context, domain.AuditDecisionRecord) error { return nil }
func (stubAuditor) RecordDelivery(context.Context, domain.AuditDeliveryRecord) error { return nil }
func (stubAuditor) GetBundle(context.Context, string) (domain.AuditBundle, error) {
	return domain.AuditBundle{}, nil
}
