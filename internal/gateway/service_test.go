package gateway_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
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

func TestSearchSummaryBuildsDigestAndCitations(t *testing.T) {
	svc := gateway.NewService(gateway.Dependencies{
		Logger:               slog.Default(),
		Timeout:              time.Second,
		DefaultPolicyProfile: "default",
		GitHub:               summaryConnector{},
		GitLab:               summaryConnector{},
		Policy:               summaryPolicy{},
		Sanitizer:            stubSanitizer{},
		Auditor:              stubAuditor{},
		DigestBuilder:        gateway.NewDigestBuilder(),
	})
	resp, err := svc.Search(context.Background(), domain.SearchRequest{
		CallerPrincipal: "alice",
		SourceType:      domain.SourceTypeGitHub,
		SourceHost:      "github.example.com",
		QueryText:       "token",
		MaxResults:      3,
		PolicyProfile:   "default",
		ResponseMode:    domain.ResponseModeSummary,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Digest == nil {
		t.Fatal("expected digest")
	}
	if len(resp.Digest.Citations) == 0 {
		t.Fatal("expected digest citations")
	}
	if !strings.Contains(resp.Digest.SummaryText, "safe evidence items") {
		t.Fatalf("unexpected summary text: %s", resp.Digest.SummaryText)
	}
	if len(resp.Results) == 0 || resp.Results[0].EvidenceID == "" {
		t.Fatalf("expected evidence ids in results: %#v", resp.Results)
	}
}

func TestSearchSnippetModeDoesNotReturnDigest(t *testing.T) {
	svc := gateway.NewService(gateway.Dependencies{
		Logger:               slog.Default(),
		Timeout:              time.Second,
		DefaultPolicyProfile: "default",
		GitHub:               stubConnector{},
		GitLab:               stubConnector{},
		Policy:               stubPolicy{},
		Sanitizer:            stubSanitizer{},
		Auditor:              stubAuditor{},
		DigestBuilder:        gateway.NewDigestBuilder(),
	})
	resp, err := svc.Search(context.Background(), domain.SearchRequest{
		CallerPrincipal: "alice",
		SourceType:      domain.SourceTypeGitHub,
		SourceHost:      "github.example.com",
		QueryText:       "token",
		MaxResults:      1,
		PolicyProfile:   "default",
		ResponseMode:    domain.ResponseModeSnippet,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Digest != nil {
		t.Fatalf("expected no digest in snippet mode, got %#v", resp.Digest)
	}
}

func TestSearchSummaryOmitsSuppressedEvidenceFromCitations(t *testing.T) {
	svc := gateway.NewService(gateway.Dependencies{
		Logger:               slog.Default(),
		Timeout:              time.Second,
		DefaultPolicyProfile: "default",
		GitHub:               summaryConnector{},
		GitLab:               summaryConnector{},
		Policy:               suppressFirstPolicy{},
		Sanitizer:            suppressingSanitizer{},
		Auditor:              stubAuditor{},
		DigestBuilder:        gateway.NewDigestBuilder(),
	})
	resp, err := svc.Search(context.Background(), domain.SearchRequest{
		CallerPrincipal: "alice",
		SourceType:      domain.SourceTypeGitHub,
		SourceHost:      "github.example.com",
		QueryText:       "token",
		MaxResults:      2,
		PolicyProfile:   "default",
		ResponseMode:    domain.ResponseModeSummary,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Digest == nil {
		t.Fatal("expected digest")
	}
	for _, citation := range resp.Digest.Citations {
		if citation.EvidenceID == "e1" {
			t.Fatalf("suppressed evidence should not be cited: %#v", resp.Digest.Citations)
		}
	}
}

func TestSearchAppliesEvidenceBudgetTruncation(t *testing.T) {
	svc := gateway.NewService(gateway.Dependencies{
		Logger:               slog.Default(),
		Timeout:              time.Second,
		DefaultPolicyProfile: "default",
		GitHub:               budgetConnector{},
		GitLab:               budgetConnector{},
		Policy:               summaryPolicy{},
		Sanitizer:            passthroughSanitizer{},
		Auditor:              stubAuditor{},
		DigestBuilder:        gateway.NewDigestBuilder(),
	})
	resp, err := svc.Search(context.Background(), domain.SearchRequest{
		CallerPrincipal: "alice",
		SourceType:      domain.SourceTypeGitHub,
		SourceHost:      "github.example.com",
		QueryText:       "token",
		MaxResults:      12,
		PolicyProfile:   "default",
		ResponseMode:    domain.ResponseModeSummary,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Truncation == nil || !resp.Truncation.ResultsTruncated {
		t.Fatalf("expected truncation, got %#v", resp.Truncation)
	}
	if len(resp.Results) >= 12 {
		t.Fatalf("expected results to be budgeted, got %d", len(resp.Results))
	}
}

func TestReadFileWindowRejectsInvalidLineCount(t *testing.T) {
	svc := gateway.NewService(gateway.Dependencies{
		Logger:               slog.Default(),
		Timeout:              time.Second,
		DefaultPolicyProfile: "default",
		GitHub:               stubConnector{},
		GitLab:               stubConnector{},
		Policy:               stubPolicy{},
		Sanitizer:            stubSanitizer{},
		Auditor:              stubAuditor{},
	})
	_, err := svc.ReadFileWindow(context.Background(), domain.FileReadRequest{
		CallerPrincipal: "alice",
		SourceType:      domain.SourceTypeGitHub,
		SourceHost:      "github.example.com",
		Repository:      "acme/repo",
		FilePath:        "main.go",
		Ref:             "main",
		StartLine:       1,
		LineCount:       81,
		PolicyProfile:   "default",
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("expected invalid request, got %v", err)
	}
}

func TestReadFileWindowReturnsWindowedEvidence(t *testing.T) {
	svc := gateway.NewService(gateway.Dependencies{
		Logger:               slog.Default(),
		Timeout:              time.Second,
		DefaultPolicyProfile: "default",
		GitHub:               stubConnector{},
		GitLab:               stubConnector{},
		Policy:               stubPolicy{},
		Sanitizer:            stubSanitizer{},
		Auditor:              stubAuditor{},
	})
	resp, err := svc.ReadFileWindow(context.Background(), domain.FileReadRequest{
		CallerPrincipal: "alice",
		SourceType:      domain.SourceTypeGitHub,
		SourceHost:      "github.example.com",
		Repository:      "acme/repo",
		FilePath:        "main.go",
		Ref:             "main",
		StartLine:       2,
		LineCount:       2,
		PolicyProfile:   "default",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Result.EvidenceID == "" {
		t.Fatalf("expected evidence id, got %#v", resp.Result)
	}
	if resp.Result.LineStart != 1 || resp.Result.LineEnd != 1 {
		t.Fatalf("expected sanitizer line metadata from stub, got %d-%d", resp.Result.LineStart, resp.Result.LineEnd)
	}
}

func TestReadFileWindowRejectsStartLinePastEOF(t *testing.T) {
	svc := gateway.NewService(gateway.Dependencies{
		Logger:               slog.Default(),
		Timeout:              time.Second,
		DefaultPolicyProfile: "default",
		GitHub:               stubConnector{},
		GitLab:               stubConnector{},
		Policy:               stubPolicy{},
		Sanitizer:            stubSanitizer{},
		Auditor:              stubAuditor{},
	})
	_, err := svc.ReadFileWindow(context.Background(), domain.FileReadRequest{
		CallerPrincipal: "alice",
		SourceType:      domain.SourceTypeGitHub,
		SourceHost:      "github.example.com",
		Repository:      "acme/repo",
		FilePath:        "main.go",
		Ref:             "main",
		StartLine:       99,
		LineCount:       2,
		PolicyProfile:   "default",
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("expected invalid request, got %v", err)
	}
}

type stubConnector struct{}

func (stubConnector) Search(context.Context, domain.SearchRequest) ([]domain.SearchResult, error) {
	return []domain.SearchResult{{Repository: "repo", FilePath: "main.go", SnippetTextRaw: `token = "abc"`}}, nil
}

func (stubConnector) ReadFile(context.Context, domain.FileReadRequest) (domain.FileContentResult, error) {
	return domain.FileContentResult{
		Repository:  "acme/repo",
		FilePath:    "main.go",
		Ref:         "main",
		Language:    "Go",
		FullTextRaw: "line1\nline2\nline3\nline4",
		SourceURL:   "https://example/repo/blob/main/main.go",
	}, nil
}

type summaryConnector struct{}

func (summaryConnector) Search(context.Context, domain.SearchRequest) ([]domain.SearchResult, error) {
	return []domain.SearchResult{
		{Repository: "repo-a", FilePath: "a.go", SnippetTextRaw: "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9", MatchRanges: []domain.MatchRange{{StartLine: 10, EndLine: 10}}},
		{Repository: "repo-b", FilePath: "b.go", SnippetTextRaw: "alpha\nbeta\ngamma", MatchRanges: []domain.MatchRange{{StartLine: 20, EndLine: 20}}},
	}, nil
}

func (summaryConnector) ReadFile(context.Context, domain.FileReadRequest) (domain.FileContentResult, error) {
	return domain.FileContentResult{
		Repository:  "repo-a",
		FilePath:    "a.go",
		Ref:         "main",
		Language:    "Go",
		FullTextRaw: "line1\nline2\nline3",
		SourceURL:   "https://example/repo-a/blob/main/a.go",
	}, nil
}

type budgetConnector struct{}

func (budgetConnector) Search(context.Context, domain.SearchRequest) ([]domain.SearchResult, error) {
	results := make([]domain.SearchResult, 0, 12)
	for i := 0; i < 12; i++ {
		results = append(results, domain.SearchResult{
			Repository:     "repo-budget",
			FilePath:       "f.go",
			SnippetTextRaw: strings.Repeat("content\n", 4) + strings.Repeat("x", 300),
			MatchRanges:    []domain.MatchRange{{StartLine: i + 1, EndLine: i + 1}},
		})
	}
	return results, nil
}

func (budgetConnector) ReadFile(context.Context, domain.FileReadRequest) (domain.FileContentResult, error) {
	return domain.FileContentResult{
		Repository:  "repo-budget",
		FilePath:    "f.go",
		Ref:         "main",
		Language:    "Go",
		FullTextRaw: strings.Repeat("content\n", 20),
		SourceURL:   "https://example/repo-budget/blob/main/f.go",
	}, nil
}

type stubPolicy struct{}

func (stubPolicy) Evaluate(context.Context, domain.SearchRequest, domain.SearchResult) (domain.PolicyDecision, error) {
	return domain.PolicyDecision{Decision: domain.DecisionMask, ExportAllowed: true, SummaryAllowed: true}, nil
}

type summaryPolicy struct{}

func (summaryPolicy) Evaluate(_ context.Context, _ domain.SearchRequest, result domain.SearchResult) (domain.PolicyDecision, error) {
	return domain.PolicyDecision{Decision: domain.DecisionAllow, ExportAllowed: true, SummaryAllowed: true, Reason: result.Repository}, nil
}

type suppressFirstPolicy struct{}

func (suppressFirstPolicy) Evaluate(_ context.Context, _ domain.SearchRequest, result domain.SearchResult) (domain.PolicyDecision, error) {
	if result.Repository == "repo-a" {
		return domain.PolicyDecision{Decision: domain.DecisionSuppress, ExportAllowed: false, SummaryAllowed: false}, nil
	}
	return domain.PolicyDecision{Decision: domain.DecisionAllow, ExportAllowed: true, SummaryAllowed: true}, nil
}

type stubSanitizer struct{}

func (stubSanitizer) Sanitize(context.Context, domain.SearchRequest, domain.SearchResult, domain.PolicyDecision) (domain.SanitizedResult, bool, error) {
	return domain.SanitizedResult{ReleaseMode: "snippet", SnippetText: "[REDACTED]", SummaryAllowed: true, LineStart: 1, LineEnd: 1}, false, nil
}

type suppressingSanitizer struct{}

func (suppressingSanitizer) Sanitize(_ context.Context, _ domain.SearchRequest, result domain.SearchResult, decision domain.PolicyDecision) (domain.SanitizedResult, bool, error) {
	if decision.Decision == domain.DecisionSuppress {
		return domain.SanitizedResult{ReleaseMode: "suppressed", SuppressionReason: "blocked", SummaryAllowed: false, Repository: result.Repository, FilePath: result.FilePath, Ref: result.Ref, LineStart: 1, LineEnd: 1}, false, nil
	}
	return domain.SanitizedResult{ReleaseMode: "summary", SnippetText: result.SnippetTextRaw, SummaryAllowed: true, Repository: result.Repository, FilePath: result.FilePath, Ref: result.Ref, LineStart: 1, LineEnd: 2}, false, nil
}

type passthroughSanitizer struct{}

func (passthroughSanitizer) Sanitize(_ context.Context, _ domain.SearchRequest, result domain.SearchResult, _ domain.PolicyDecision) (domain.SanitizedResult, bool, error) {
	return domain.SanitizedResult{ReleaseMode: "summary", SnippetText: result.SnippetTextRaw, SummaryAllowed: true, Repository: result.Repository, FilePath: result.FilePath, Ref: result.Ref, LineStart: 1, LineEnd: 4}, false, nil
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
