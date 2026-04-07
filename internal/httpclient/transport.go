package httpclient

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"secure-code-retrieval-mcp/internal/config"
	"secure-code-retrieval-mcp/internal/domain"
)

type BuildOptions struct {
	TargetName    string
	AllowInsecure bool
	EndpointProxy *config.ProxyConfig
	DefaultProxy  *config.ProxyConfig
	Logger        *slog.Logger
}

type BuildResult struct {
	Transport *http.Transport
	ProxyInfo ProxyInfo
	UsesProxy func(*http.Request) bool
}

type ProxyInfo struct {
	Enabled bool
	Source  string
	URL     string
}

func BuildTransport(opts BuildOptions) (BuildResult, error) {
	proxyFunc, usesProxy, info, err := ResolveProxy(opts.EndpointProxy, opts.DefaultProxy)
	if err != nil {
		return BuildResult{}, fmt.Errorf("%w: %v", domain.ErrProxyConfig, err)
	}
	if opts.Logger != nil {
		opts.Logger.Info("configured outbound transport",
			"target", opts.TargetName,
			"proxy_enabled", info.Enabled,
			"proxy_source", info.Source,
			"proxy_url", info.URL,
		)
	}
	return BuildResult{
		Transport: &http.Transport{
			Proxy:                 proxyFunc,
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			ProxyConnectHeader:    buildProxyConnectHeader(opts.EndpointProxy, opts.DefaultProxy),
			TLSClientConfig:       tlsConfig(opts.AllowInsecure),
		},
		ProxyInfo: info,
		UsesProxy: usesProxy,
	}, nil
}

func ResolveProxy(endpointProxy, defaultProxy *config.ProxyConfig) (func(*http.Request) (*url.URL, error), func(*http.Request) bool, ProxyInfo, error) {
	effective, source, disabled, err := resolveEffectiveProxy(endpointProxy, defaultProxy)
	if err != nil {
		return nil, nil, ProxyInfo{}, err
	}
	if disabled {
		return noProxyFunc(), func(*http.Request) bool { return false }, ProxyInfo{Enabled: false, Source: source, URL: ""}, nil
	}
	if effective == nil {
		envURL := firstEnvironmentProxyURL()
		noProxy := selectNoProxy(nil, nil)
		proxyFunc := func(req *http.Request) (*url.URL, error) {
			return environmentProxyURL(req, noProxy)
		}
		return proxyFunc, func(req *http.Request) bool {
				return environmentUsesProxy(req, noProxy)
			}, ProxyInfo{
				Enabled: envURL != nil,
				Source:  "environment",
				URL:     sanitizeOptionalURL(envURL),
			}, nil
	}
	parsed, err := buildProxyURL(effective)
	if err != nil {
		return nil, nil, ProxyInfo{}, err
	}
	noProxy := selectNoProxy(endpointProxy, defaultProxy)
	usesProxy := func(req *http.Request) bool {
		if req == nil || req.URL == nil {
			return true
		}
		return !shouldBypassProxy(req.URL, noProxy)
	}
	return func(req *http.Request) (*url.URL, error) {
		if req == nil || req.URL == nil {
			return parsed, nil
		}
		if shouldBypassProxy(req.URL, noProxy) {
			return nil, nil
		}
		return parsed, nil
	}, usesProxy, ProxyInfo{Enabled: true, Source: source, URL: SanitizeURL(parsed.String())}, nil
}

func resolveEffectiveProxy(endpointProxy, defaultProxy *config.ProxyConfig) (*config.ProxyConfig, string, bool, error) {
	if endpointProxy != nil {
		if endpointProxy.Enabled != nil && !*endpointProxy.Enabled {
			return nil, "endpoint", true, nil
		}
		if endpointProxy.URL != "" || (endpointProxy.Enabled != nil && *endpointProxy.Enabled) {
			return endpointProxy, "endpoint", false, nil
		}
	}
	if defaultProxy != nil {
		if defaultProxy.Enabled != nil && !*defaultProxy.Enabled {
			return nil, "global", true, nil
		}
		if defaultProxy.URL != "" || (defaultProxy.Enabled != nil && *defaultProxy.Enabled) {
			return defaultProxy, "global", false, nil
		}
	}
	return nil, "environment", false, nil
}

func buildProxyURL(cfg *config.ProxyConfig) (*url.URL, error) {
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy url: %w", err)
	}
	if cfg.UsernameEnv != "" {
		parsed.User = url.UserPassword(os.Getenv(cfg.UsernameEnv), os.Getenv(cfg.PasswordEnv))
	}
	return parsed, nil
}

func selectNoProxy(endpointProxy, defaultProxy *config.ProxyConfig) string {
	if endpointProxy != nil && endpointProxy.NoProxy != "" {
		return endpointProxy.NoProxy
	}
	if defaultProxy != nil && defaultProxy.NoProxy != "" {
		return defaultProxy.NoProxy
	}
	noProxy := os.Getenv("NO_PROXY")
	if noProxy == "" {
		noProxy = os.Getenv("no_proxy")
	}
	return noProxy
}

func shouldBypassProxy(target *url.URL, noProxy string) bool {
	host := strings.ToLower(target.Hostname())
	if host == "" {
		return false
	}
	if noProxy == "" {
		return false
	}
	for _, token := range strings.Split(noProxy, ",") {
		pattern := strings.TrimSpace(strings.ToLower(token))
		if pattern == "" {
			continue
		}
		if pattern == "*" {
			return true
		}
		if _, cidr, err := net.ParseCIDR(pattern); err == nil {
			if ip := net.ParseIP(host); ip != nil && cidr.Contains(ip) {
				return true
			}
			continue
		}
		if strings.HasPrefix(pattern, "*.") {
			pattern = strings.TrimPrefix(pattern, "*")
		}
		if strings.HasPrefix(pattern, ".") {
			if strings.HasSuffix(host, pattern) || host == strings.TrimPrefix(pattern, ".") {
				return true
			}
			continue
		}
		if strings.Contains(pattern, ":") {
			if strings.EqualFold(target.Host, pattern) {
				return true
			}
			continue
		}
		if host == pattern || strings.HasSuffix(host, "."+pattern) {
			return true
		}
	}
	return false
}

func SanitizeURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if parsed.User != nil {
		username := parsed.User.Username()
		if username != "" {
			parsed.User = url.UserPassword(username, "REDACTED")
		} else {
			parsed.User = url.User("REDACTED")
		}
	}
	return parsed.String()
}

func sanitizeOptionalURL(raw *url.URL) string {
	if raw == nil {
		return ""
	}
	return SanitizeURL(raw.String())
}

func noProxyFunc() func(*http.Request) (*url.URL, error) {
	return func(*http.Request) (*url.URL, error) { return nil, nil }
}

func tlsConfig(allowInsecure bool) *tls.Config {
	return &tls.Config{InsecureSkipVerify: allowInsecure} //nolint:gosec
}

func buildProxyConnectHeader(endpointProxy, defaultProxy *config.ProxyConfig) http.Header {
	effective, _, disabled, err := resolveEffectiveProxy(endpointProxy, defaultProxy)
	if err != nil || disabled || effective == nil {
		return nil
	}
	parsed, err := buildProxyURL(effective)
	if err != nil || parsed.User == nil {
		return nil
	}
	password, ok := parsed.User.Password()
	if !ok {
		return nil
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(parsed.User.Username() + ":" + password))
	header := make(http.Header)
	header.Set("Proxy-Authorization", "Basic "+encoded)
	return header
}

func environmentUsesProxy(req *http.Request, noProxy string) bool {
	proxyURL, err := environmentProxyURL(req, noProxy)
	return err == nil && proxyURL != nil
}

func firstEnvironmentProxyURL() *url.URL {
	for _, scheme := range []string{"https", "http"} {
		if proxyURL := environmentProxyURLForScheme(scheme); proxyURL != nil {
			return proxyURL
		}
	}
	return nil
}

func environmentProxyURL(req *http.Request, noProxy string) (*url.URL, error) {
	if req != nil && req.URL != nil && shouldBypassProxy(req.URL, noProxy) {
		return nil, nil
	}
	scheme := "http"
	if req != nil && req.URL != nil && req.URL.Scheme != "" {
		scheme = strings.ToLower(req.URL.Scheme)
	}
	return environmentProxyURLForScheme(scheme), nil
}

func environmentProxyURLForScheme(scheme string) *url.URL {
	keys := []string{"ALL_PROXY", "all_proxy"}
	switch strings.ToLower(scheme) {
	case "https":
		keys = append([]string{"HTTPS_PROXY", "https_proxy"}, keys...)
	case "http":
		keys = append([]string{"HTTP_PROXY", "http_proxy"}, keys...)
	default:
		keys = append([]string{
			"HTTPS_PROXY",
			"https_proxy",
			"HTTP_PROXY",
			"http_proxy",
		}, keys...)
	}
	return firstValidProxyURL(keys...)
}

func firstValidProxyURL(keys ...string) *url.URL {
	for _, key := range keys {
		value := strings.TrimSpace(os.Getenv(key))
		if value == "" {
			continue
		}
		parsed, err := url.Parse(value)
		if err == nil && parsed != nil {
			return parsed
		}
	}
	return nil
}
