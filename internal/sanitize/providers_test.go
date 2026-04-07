package sanitize

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"secure-code-retrieval-mcp/internal/config"
)

func TestProviderUsesProxyOverride(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		http.Error(w, "should not be called directly", http.StatusInternalServerError)
	}))
	defer upstream.Close()

	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"sanitized"}}]}`))
	}))
	defer proxy.Close()

	enabled := true
	provider := newProvider(config.ModelEndpoint{
		Name:         "openai-proxy",
		ProviderKind: "openai_compatible",
		BaseURL:      upstream.URL,
		Model:        "gpt-test",
		Timeout:      time.Second,
		Proxy:        &config.ProxyConfig{Enabled: &enabled, URL: proxy.URL},
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if provider == nil {
		t.Fatal("expected provider to be created")
	}
	out, err := provider.Rewrite(context.Background(), "hello")
	if err != nil {
		t.Fatal(err)
	}
	if out != "sanitized" {
		t.Fatalf("expected sanitized output, got %q", out)
	}
	if proxyHits.Load() != 1 {
		t.Fatalf("expected proxy hit, got %d", proxyHits.Load())
	}
	if upstreamHits.Load() != 0 {
		t.Fatalf("expected upstream bypass in proxy test, got %d", upstreamHits.Load())
	}
}
