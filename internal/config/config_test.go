package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateProxyConfigRejectsInvalidURL(t *testing.T) {
	enabled := true
	for _, rawURL := range []string{"://bad", "proxy.internal:8080", "foo", "socks5://proxy.internal:1080"} {
		cfg := Config{
			Runtime:  RuntimeConfig{HTTPAddress: ":8080", RequestTimeout: 1},
			Database: DatabaseConfig{DSN: "postgres://example"},
			Connectors: ConnectorsConfig{
				GitHub: ConnectorConfig{
					Enabled: true,
					BaseURL: "https://github.example.com",
					Proxy:   &ProxyConfig{Enabled: &enabled, URL: rawURL},
				},
			},
		}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected invalid proxy url validation error for %q", rawURL)
		}
	}
}

func TestValidateProxyConfigRejectsMissingCredentialEnv(t *testing.T) {
	t.Setenv("PROXY_USER", "alice")
	enabled := true
	cfg := Config{
		Runtime:  RuntimeConfig{HTTPAddress: ":8080", RequestTimeout: 1},
		Database: DatabaseConfig{DSN: "postgres://example"},
		Network: NetworkConfig{
			Proxy: &ProxyConfig{
				Enabled:     &enabled,
				URL:         "http://proxy.example.com:8080",
				UsernameEnv: "PROXY_USER",
				PasswordEnv: "PROXY_PASS",
			},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected missing proxy credential env error")
	}
}

func TestLoadParsesGlobalAndConnectorProxy(t *testing.T) {
	t.Setenv("PROXY_USER", "alice")
	t.Setenv("PROXY_PASS", "secret")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := `
runtime:
  http_address: ":8080"
  request_timeout: 8s
database:
  dsn: postgres://postgres:postgres@localhost:5432/secure_code_retrieval?sslmode=disable
network:
  proxy:
    enabled: true
    url: http://proxy.internal:8080
    username_env: PROXY_USER
    password_env: PROXY_PASS
connectors:
  github:
    enabled: true
    base_url: https://github.example.com
  gitlab:
    enabled: true
    base_url: https://gitlab.example.com
    proxy:
      enabled: false
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCRM_CONFIG", path)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Network.Proxy == nil || cfg.Network.Proxy.URL != "http://proxy.internal:8080" {
		t.Fatalf("expected global proxy, got %#v", cfg.Network.Proxy)
	}
	if cfg.Connectors.GitLab.Proxy == nil || cfg.Connectors.GitLab.Proxy.Enabled == nil || *cfg.Connectors.GitLab.Proxy.Enabled {
		t.Fatalf("expected gitlab proxy to be explicitly disabled, got %#v", cfg.Connectors.GitLab.Proxy)
	}
}
