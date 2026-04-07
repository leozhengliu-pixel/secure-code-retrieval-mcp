package mcp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"secure-code-retrieval-mcp/internal/domain"
	"secure-code-retrieval-mcp/internal/gateway"
)

func TestToolsCallReturnsStructuredContent(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"code_search_secure","arguments":{"policy_profile":"default","source_type":"github","source_host":"github.example.com","query_text":"hello","max_results":1,"response_mode":"snippet"}}}`
	framed := []byte(fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(input), input))
	in := bytes.NewBuffer(framed)
	out := bytes.NewBuffer(nil)
	server := &Server{
		service: gateway.NewService(gateway.Dependencies{
			Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
			Timeout:   time.Second,
			GitHub:    fakeConnector{},
			GitLab:    fakeConnector{},
			Policy:    fakePolicy{},
			Sanitizer: fakeSanitizer{},
			Auditor:   fakeAuditor{},
		}),
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		defaultUser: "mcp_stdio",
		in:          in,
		out:         out,
	}
	if err := server.Serve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"structuredContent"`)) {
		t.Fatalf("expected structured content response, got %s", out.String())
	}
}

func TestToolsCallRejectsLegacyTenantField(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"code_search_secure","arguments":{"tenant_id":"legacy","policy_profile":"default","source_type":"github","source_host":"github.example.com","query_text":"hello","max_results":1,"response_mode":"snippet"}}}`
	framed := []byte(fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(input), input))
	in := bytes.NewBuffer(framed)
	out := bytes.NewBuffer(nil)
	server := &Server{
		service: gateway.NewService(gateway.Dependencies{
			Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
			Timeout:              time.Second,
			DefaultPolicyProfile: "default",
			GitHub:               fakeConnector{},
			GitLab:               fakeConnector{},
			Policy:               fakePolicy{},
			Sanitizer:            fakeSanitizer{},
			Auditor:              fakeAuditor{},
		}),
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		defaultUser: "mcp_stdio",
		in:          in,
		out:         out,
	}
	if err := server.Serve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"invalid tool arguments"`)) {
		t.Fatalf("expected legacy field rejection, got %s", out.String())
	}
}

func TestToolsListIncludesFileViewTool(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	framed := []byte(fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(input), input))
	in := bytes.NewBuffer(framed)
	out := bytes.NewBuffer(nil)
	server := &Server{
		service: gateway.NewService(gateway.Dependencies{
			Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
			Timeout:              time.Second,
			DefaultPolicyProfile: "default",
			GitHub:               fakeConnector{},
			GitLab:               fakeConnector{},
			Policy:               fakePolicy{},
			Sanitizer:            fakeSanitizer{},
			Auditor:              fakeAuditor{},
		}),
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		defaultUser: "mcp_stdio",
		in:          in,
		out:         out,
	}
	if err := server.Serve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"code_view_secure"`)) {
		t.Fatalf("expected code_view_secure in tools list, got %s", out.String())
	}
}

func TestFileViewToolReturnsStructuredContent(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"code_view_secure","arguments":{"policy_profile":"default","source_type":"github","source_host":"github.example.com","repository":"acme/repo","file_path":"main.go","ref":"main","start_line":1,"line_count":5}}}`
	framed := []byte(fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(input), input))
	in := bytes.NewBuffer(framed)
	out := bytes.NewBuffer(nil)
	server := &Server{
		service: gateway.NewService(gateway.Dependencies{
			Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
			Timeout:              time.Second,
			DefaultPolicyProfile: "default",
			GitHub:               fakeConnector{},
			GitLab:               fakeConnector{},
			Policy:               fakePolicy{},
			Sanitizer:            fakeSanitizer{},
			Auditor:              fakeAuditor{},
		}),
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		defaultUser: "mcp_stdio",
		in:          in,
		out:         out,
	}
	if err := server.Serve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"result"`)) {
		t.Fatalf("expected file view structured content, got %s", out.String())
	}
}

type fakeConnector struct{}

func (fakeConnector) Search(context.Context, domain.SearchRequest) ([]domain.SearchResult, error) {
	return []domain.SearchResult{{Repository: "repo", FilePath: "main.go", SnippetTextRaw: "hello"}}, nil
}

func (fakeConnector) ReadFile(context.Context, domain.FileReadRequest) (domain.FileContentResult, error) {
	return domain.FileContentResult{
		Repository:  "acme/repo",
		FilePath:    "main.go",
		Ref:         "main",
		Language:    "Go",
		FullTextRaw: "line1\nline2\nline3\nline4",
		SourceURL:   "https://example/repo/blob/main/main.go",
	}, nil
}

type fakePolicy struct{}

func (fakePolicy) Evaluate(context.Context, domain.SearchRequest, domain.SearchResult) (domain.PolicyDecision, error) {
	return domain.PolicyDecision{Decision: domain.DecisionAllow, ExportAllowed: true}, nil
}

type fakeSanitizer struct{}

func (fakeSanitizer) Sanitize(context.Context, domain.SearchRequest, domain.SearchResult, domain.PolicyDecision) (domain.SanitizedResult, bool, error) {
	return domain.SanitizedResult{ReleaseMode: "snippet", SnippetText: "hello"}, false, nil
}

type fakeAuditor struct{}

func (fakeAuditor) RecordRequest(context.Context, domain.AuditRequestRecord) (string, error) {
	return "audit_1", nil
}

func (fakeAuditor) RecordDecision(context.Context, domain.AuditDecisionRecord) error { return nil }
func (fakeAuditor) RecordDelivery(context.Context, domain.AuditDeliveryRecord) error { return nil }
func (fakeAuditor) GetBundle(context.Context, string) (domain.AuditBundle, error) {
	return domain.AuditBundle{}, nil
}
