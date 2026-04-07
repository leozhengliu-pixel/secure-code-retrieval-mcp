package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"secure-code-retrieval-mcp/internal/domain"
	"secure-code-retrieval-mcp/internal/gateway"
)

func TestInitializeReturnsCapabilities(t *testing.T) {
	server := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	req.Header.Set("Accept", "application/json, text/event-stream")
	req = req.WithContext(domain.WithRequestMetadata(req.Context(), "req_1", "alice", nil))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"protocolVersion"`)) {
		t.Fatalf("expected initialize payload, got %s", rec.Body.String())
	}
}

func TestToolsListIncludesFileViewTool(t *testing.T) {
	server := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Accept", "application/json, text/event-stream")
	req = req.WithContext(domain.WithRequestMetadata(req.Context(), "req_1", "alice", nil))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"code_view_secure"`)) {
		t.Fatalf("expected code_view_secure in tools list, got %s", rec.Body.String())
	}
}

func TestToolsCallReturnsStructuredContent(t *testing.T) {
	server := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"code_search_secure","arguments":{"policy_profile":"default","source_type":"github","source_host":"github.example.com","query_text":"hello","max_results":1,"response_mode":"snippet"}}}`))
	req.Header.Set("Accept", "application/json, text/event-stream")
	req = req.WithContext(domain.WithRequestMetadata(req.Context(), "req_1", "alice", []string{"dev"}))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"structuredContent"`)) {
		t.Fatalf("expected structured content response, got %s", rec.Body.String())
	}
}

func TestToolsCallRejectsLegacyTenantField(t *testing.T) {
	server := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"code_search_secure","arguments":{"tenant_id":"legacy","policy_profile":"default","source_type":"github","source_host":"github.example.com","query_text":"hello","max_results":1,"response_mode":"snippet"}}}`))
	req.Header.Set("Accept", "application/json, text/event-stream")
	req = req.WithContext(domain.WithRequestMetadata(req.Context(), "req_1", "alice", nil))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"invalid tool arguments"`)) {
		t.Fatalf("expected legacy field rejection, got %s", rec.Body.String())
	}
}

func TestFileViewToolReturnsStructuredContent(t *testing.T) {
	server := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"code_view_secure","arguments":{"policy_profile":"default","source_type":"github","source_host":"github.example.com","repository":"acme/repo","file_path":"main.go","ref":"main","start_line":1,"line_count":5}}}`))
	req.Header.Set("Accept", "application/json, text/event-stream")
	req = req.WithContext(domain.WithRequestMetadata(req.Context(), "req_1", "alice", nil))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"result"`)) {
		t.Fatalf("expected file view structured content, got %s", rec.Body.String())
	}
}

func TestMethodNotAllowed(t *testing.T) {
	server := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req = req.WithContext(domain.WithRequestMetadata(req.Context(), "req_1", "alice", nil))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestRejectsMissingStreamableAcceptHeader(t *testing.T) {
	server := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Accept", "application/json")
	req = req.WithContext(domain.WithRequestMetadata(req.Context(), "req_1", "alice", nil))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotAcceptable {
		t.Fatalf("expected 406, got %d", rec.Code)
	}
}

func TestNotificationReturnsAcceptedWithoutBody(t *testing.T) {
	server := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","method":"ping"}`))
	req.Header.Set("Accept", "application/json, text/event-stream")
	req = req.WithContext(domain.WithRequestMetadata(req.Context(), "req_1", "alice", nil))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("expected empty body, got %s", rec.Body.String())
	}
}

func TestBatchReturnsOnlyRequestResponses(t *testing.T) {
	server := newTestServer()
	body := `[{"jsonrpc":"2.0","method":"ping"},{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Accept", "application/json, text/event-stream")
	req = req.WithContext(domain.WithRequestMetadata(req.Context(), "req_1", "alice", nil))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !bytes.HasPrefix(bytes.TrimSpace(rec.Body.Bytes()), []byte("[")) {
		t.Fatalf("expected batch response, got %s", rec.Body.String())
	}
}

func newTestServer() *Server {
	return NewServer(gateway.NewService(gateway.Dependencies{
		Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		Timeout:              time.Second,
		DefaultPolicyProfile: "default",
		GitHub:               fakeConnector{},
		GitLab:               fakeConnector{},
		Policy:               fakePolicy{},
		Sanitizer:            fakeSanitizer{},
		Auditor:              fakeAuditor{},
	}), slog.New(slog.NewTextHandler(io.Discard, nil)))
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

func TestResponseIsValidJSON(t *testing.T) {
	server := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Accept", "application/json, text/event-stream")
	req = req.WithContext(domain.WithRequestMetadata(req.Context(), "req_1", "alice", nil))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected valid json, got %v", err)
	}
}
