package httpclient

import (
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"secure-code-retrieval-mcp/internal/config"
)

func TestResolveProxyUsesEnvironmentFallback(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.env:8080")
	fn, usesProxy, info, err := ResolveProxy(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://service.internal/path", nil)
	proxyURL, err := fn(req)
	if err != nil {
		t.Fatal(err)
	}
	if proxyURL == nil || proxyURL.String() != "http://proxy.env:8080" {
		t.Fatalf("expected environment proxy, got %v", proxyURL)
	}
	if info.Source != "environment" {
		t.Fatalf("expected environment source, got %s", info.Source)
	}
	if !info.Enabled {
		t.Fatalf("expected environment proxy to be reported as enabled, got %#v", info)
	}
	if !usesProxy(req) {
		t.Fatal("expected request to be classified as proxied")
	}
}

func TestResolveProxyGlobalOverridesEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.env:8080")
	enabled := true
	global := &config.ProxyConfig{Enabled: &enabled, URL: "http://proxy.global:8080"}
	fn, usesProxy, info, err := ResolveProxy(nil, global)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://service.internal/path", nil)
	proxyURL, err := fn(req)
	if err != nil {
		t.Fatal(err)
	}
	if proxyURL == nil || proxyURL.String() != "http://proxy.global:8080" {
		t.Fatalf("expected global proxy, got %v", proxyURL)
	}
	if info.Source != "global" {
		t.Fatalf("expected global source, got %s", info.Source)
	}
	if !usesProxy(req) {
		t.Fatal("expected request to be classified as proxied")
	}
}

func TestResolveProxyEndpointOverridesGlobal(t *testing.T) {
	enabled := true
	global := &config.ProxyConfig{Enabled: &enabled, URL: "http://proxy.global:8080"}
	endpoint := &config.ProxyConfig{Enabled: &enabled, URL: "http://proxy.endpoint:8080"}
	fn, usesProxy, info, err := ResolveProxy(endpoint, global)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://service.internal/path", nil)
	proxyURL, err := fn(req)
	if err != nil {
		t.Fatal(err)
	}
	if proxyURL == nil || proxyURL.String() != "http://proxy.endpoint:8080" {
		t.Fatalf("expected endpoint proxy, got %v", proxyURL)
	}
	if info.Source != "endpoint" {
		t.Fatalf("expected endpoint source, got %s", info.Source)
	}
	if !usesProxy(req) {
		t.Fatal("expected request to be classified as proxied")
	}
}

func TestResolveProxyDisabledByEndpoint(t *testing.T) {
	disabled := false
	globalEnabled := true
	global := &config.ProxyConfig{Enabled: &globalEnabled, URL: "http://proxy.global:8080"}
	endpoint := &config.ProxyConfig{Enabled: &disabled}
	fn, usesProxy, info, err := ResolveProxy(endpoint, global)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://service.internal/path", nil)
	proxyURL, err := fn(req)
	if err != nil {
		t.Fatal(err)
	}
	if proxyURL != nil {
		t.Fatalf("expected no proxy, got %v", proxyURL)
	}
	if info.Enabled {
		t.Fatalf("expected proxy to be disabled, got %#v", info)
	}
	if usesProxy(req) {
		t.Fatal("expected request to be classified as direct")
	}
}

func TestResolveProxyHonorsNoProxy(t *testing.T) {
	enabled := true
	global := &config.ProxyConfig{Enabled: &enabled, URL: "http://proxy.global:8080", NoProxy: ".internal,127.0.0.1"}
	fn, usesProxy, _, err := ResolveProxy(nil, global)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://service.internal/path", nil)
	proxyURL, err := fn(req)
	if err != nil {
		t.Fatal(err)
	}
	if proxyURL != nil {
		t.Fatalf("expected no proxy due to no_proxy, got %v", proxyURL)
	}
	if usesProxy(req) {
		t.Fatal("expected request to be classified as direct due to no_proxy")
	}
}

func TestResolveProxyEnvironmentHonorsNoProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.env:8080")
	t.Setenv("NO_PROXY", "service.internal")
	fn, usesProxy, info, err := ResolveProxy(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://service.internal/path", nil)
	proxyURL, err := fn(req)
	if err != nil {
		t.Fatal(err)
	}
	if proxyURL != nil {
		t.Fatalf("expected no proxy due to environment no_proxy, got %v", proxyURL)
	}
	if usesProxy(req) {
		t.Fatal("expected environment no_proxy to classify request as direct")
	}
	if !info.Enabled {
		t.Fatalf("expected environment proxy to still be reported as configured, got %#v", info)
	}
}

func TestBuildTransportAddsProxyAuthorizationAndSanitizesLogs(t *testing.T) {
	t.Setenv("PROXY_USER", "alice")
	t.Setenv("PROXY_PASS", "secret")
	enabled := true
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	result, err := BuildTransport(BuildOptions{
		TargetName: "github",
		Logger:     logger,
		DefaultProxy: &config.ProxyConfig{
			Enabled:     &enabled,
			URL:         "http://proxy.global:8080",
			UsernameEnv: "PROXY_USER",
			PasswordEnv: "PROXY_PASS",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ProxyInfo.URL != "http://alice:REDACTED@proxy.global:8080" {
		t.Fatalf("expected sanitized proxy url, got %s", result.ProxyInfo.URL)
	}
	got := result.Transport.ProxyConnectHeader.Get("Proxy-Authorization")
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	if got != want {
		t.Fatalf("expected proxy auth header %q, got %q", want, got)
	}
}
