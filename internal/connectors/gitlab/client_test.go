package gitlab

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"secure-code-retrieval-mcp/internal/config"
	"secure-code-retrieval-mcp/internal/domain"
)

func TestSearchNormalizesResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"path":"app/main.go","startline":12,"project_id":42,"data":"fmt.Println(\"hello\")","ref":"main"}]`))
	}))
	defer server.Close()

	client, err := New(config.ConnectorConfig{Enabled: true, BaseURL: server.URL}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	results, err := client.Search(context.Background(), domain.SearchRequest{SourceHost: "gitlab.example.com", QueryText: "hello", MaxResults: 10, SourceType: domain.SourceTypeGitLab, ResponseMode: domain.ResponseModeSnippet})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Repository != "42" {
		t.Fatalf("unexpected repository: %s", results[0].Repository)
	}
	if results[0].SourceURL != server.URL+"/-/project/42/blob/main/app/main.go" {
		t.Fatalf("unexpected source url: %s", results[0].SourceURL)
	}
}

func TestGitlabSourceURLStripsAPIPrefix(t *testing.T) {
	got := gitlabSourceURL("https://gitlab.example.com/api/v4", 42, "main", "app/main.go")
	want := "https://gitlab.example.com/-/project/42/blob/main/app/main.go"
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestSearchUsesProxy(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		http.Error(w, "should not be called directly", http.StatusInternalServerError)
	}))
	defer upstream.Close()

	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		_, _ = w.Write([]byte(`[{"path":"app/main.go","startline":12,"project_id":42,"data":"fmt.Println(\"hello\")","ref":"main"}]`))
	}))
	defer proxy.Close()

	enabled := true
	client, err := New(config.ConnectorConfig{
		Enabled: true,
		BaseURL: upstream.URL,
		Proxy:   &config.ProxyConfig{Enabled: &enabled, URL: proxy.URL},
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	results, err := client.Search(context.Background(), domain.SearchRequest{
		SourceHost:   "gitlab.example.com",
		QueryText:    "hello",
		MaxResults:   10,
		SourceType:   domain.SourceTypeGitLab,
		ResponseMode: domain.ResponseModeSnippet,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if proxyHits.Load() != 1 {
		t.Fatalf("expected proxy hit, got %d", proxyHits.Load())
	}
	if upstreamHits.Load() != 0 {
		t.Fatalf("expected upstream to be bypassed in test proxy mode, got %d", upstreamHits.Load())
	}
}

func TestSearchProxyAuthError(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "proxy auth required", http.StatusProxyAuthRequired)
	}))
	defer proxy.Close()

	enabled := true
	client, err := New(config.ConnectorConfig{
		Enabled: true,
		BaseURL: "http://example.invalid",
		Proxy:   &config.ProxyConfig{Enabled: &enabled, URL: proxy.URL},
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Search(context.Background(), domain.SearchRequest{
		SourceHost:   "gitlab.example.com",
		QueryText:    "hello",
		MaxResults:   1,
		SourceType:   domain.SourceTypeGitLab,
		ResponseMode: domain.ResponseModeSnippet,
	})
	if err == nil || !strings.Contains(err.Error(), domain.ErrProxyAuth.Error()) {
		t.Fatalf("expected proxy auth error, got %v", err)
	}
}
