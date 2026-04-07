package github

import (
	"context"
	"encoding/base64"
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
		_, _ = w.Write([]byte(`{"items":[{"path":"cmd/main.go","html_url":"https://example/repo/blob/main/cmd/main.go","repository":{"full_name":"acme/repo","default_branch":"main"},"text_matches":[{"fragment":"fmt.Println(\"hello\")"}]}]}`))
	}))
	defer server.Close()

	client, err := New(config.ConnectorConfig{Enabled: true, BaseURL: server.URL}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	results, err := client.Search(context.Background(), domain.SearchRequest{SourceHost: "github.example.com", QueryText: "hello", MaxResults: 10, SourceType: domain.SourceTypeGitHub, ResponseMode: domain.ResponseModeSnippet})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Repository != "acme/repo" {
		t.Fatalf("unexpected repository: %s", results[0].Repository)
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
		if r.URL.Host == "" {
			t.Fatalf("expected absolute proxy request URL, got %s", r.URL.String())
		}
		_, _ = w.Write([]byte(`{"items":[{"path":"cmd/main.go","html_url":"https://example/repo/blob/main/cmd/main.go","repository":{"full_name":"acme/repo","default_branch":"main"},"text_matches":[{"fragment":"fmt.Println(\"hello\")"}]}]}`))
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
		SourceHost:   "github.example.com",
		QueryText:    "hello",
		MaxResults:   10,
		SourceType:   domain.SourceTypeGitHub,
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
		SourceHost:   "github.example.com",
		QueryText:    "hello",
		MaxResults:   1,
		SourceType:   domain.SourceTypeGitHub,
		ResponseMode: domain.ResponseModeSnippet,
	})
	if err == nil || !strings.Contains(err.Error(), domain.ErrProxyAuth.Error()) {
		t.Fatalf("expected proxy auth error, got %v", err)
	}
}

func TestReadFileRejectsBinaryContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"type":"file","path":"bin.dat","html_url":"https://example/repo/blob/main/bin.dat","content":"` + base64.StdEncoding.EncodeToString([]byte{0x00, 0x01, 0x02}) + `","encoding":"base64"}`))
	}))
	defer server.Close()

	client, err := New(config.ConnectorConfig{Enabled: true, BaseURL: server.URL}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ReadFile(context.Background(), domain.FileReadRequest{
		SourceType: domain.SourceTypeGitHub,
		SourceHost: "github.example.com",
		Repository: "acme/repo",
		FilePath:   "bin.dat",
		Ref:        "main",
	})
	if err == nil || !strings.Contains(err.Error(), domain.ErrInvalidRequest.Error()) {
		t.Fatalf("expected invalid request, got %v", err)
	}
}
