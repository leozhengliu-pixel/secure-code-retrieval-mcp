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
			Database: DatabaseConfig{SQLitePath: "var/test.db"},
			Auth:     AuthConfig{Issuer: "issuer", Audience: "aud", PublicKeyPEM: "pem"},
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
		Database: DatabaseConfig{SQLitePath: "var/test.db"},
		Auth:     AuthConfig{Issuer: "issuer", Audience: "aud", PublicKeyPEM: "pem"},
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
  sqlite_path: ./var/test.db
auth:
  issuer: issuer
  audience: aud
  public_key_pem: |
    pem
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

func TestLoadAppliesAuthDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := `
runtime:
  http_address: ":8080"
  request_timeout: 8s
database:
  sqlite_path: ./var/test.db
auth:
  issuer: issuer
  audience: aud
  public_key_pem: |
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtesttesttesttesttest
    -----END PUBLIC KEY-----
policies:
  - name: default
    rules:
      - name: allow-basic
        action: allow
default_policy_profile: default
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCRM_CONFIG", path)
	cfg, err := Load()
	if err == nil {
		if cfg.Auth.AdminRole != "scrm_admin" {
			t.Fatalf("expected default admin role, got %q", cfg.Auth.AdminRole)
		}
		return
	}
	t.Fatalf("expected defaults to apply before validation, got %v", err)
}

func TestApplyDefaultsUsesSQLiteWhenDSNMissing(t *testing.T) {
	cfg := Config{}
	cfg.applyDefaults()
	if cfg.Database.DSN != "" {
		t.Fatalf("expected empty dsn, got %q", cfg.Database.DSN)
	}
	if !filepath.IsAbs(cfg.Database.SQLitePath) {
		t.Fatalf("expected absolute sqlite path, got %q", cfg.Database.SQLitePath)
	}
}

func TestLoadResolvesRelativeSQLitePathAgainstConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := `
runtime:
  http_address: ":8080"
  request_timeout: 8s
database:
  sqlite_path: ./var/test.db
auth:
  issuer: issuer
  audience: aud
  public_key_pem: |
    pem
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCRM_CONFIG", path)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	expected := filepath.Join(dir, "var", "test.db")
	if cfg.Database.SQLitePath != expected {
		t.Fatalf("expected sqlite path %q, got %q", expected, cfg.Database.SQLitePath)
	}
}
