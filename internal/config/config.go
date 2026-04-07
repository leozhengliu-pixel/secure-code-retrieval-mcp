package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	LogLevel             LogLevel         `yaml:"log_level"`
	Runtime              RuntimeConfig    `yaml:"runtime"`
	Network              NetworkConfig    `yaml:"network"`
	Database             DatabaseConfig   `yaml:"database"`
	Connectors           ConnectorsConfig `yaml:"connectors"`
	DefaultPolicyProfile string           `yaml:"default_policy_profile"`
	Auth                 AuthConfig       `yaml:"auth"`
	Policies             []PolicyProfile  `yaml:"policies"`
	Models               []ModelEndpoint  `yaml:"models"`
}

type RuntimeConfig struct {
	HTTPAddress    string        `yaml:"http_address"`
	RequestTimeout time.Duration `yaml:"request_timeout"`
}

type DatabaseConfig struct {
	DSN        string `yaml:"dsn"`
	SQLitePath string `yaml:"sqlite_path"`
}

type AuthConfig struct {
	Issuer       string `yaml:"issuer"`
	Audience     string `yaml:"audience"`
	PublicKeyPEM string `yaml:"public_key_pem"`
	PublicKeyEnv string `yaml:"public_key_env"`
	AdminRole    string `yaml:"admin_role"`
}

type NetworkConfig struct {
	Proxy *ProxyConfig `yaml:"proxy"`
}

type ConnectorsConfig struct {
	GitHub ConnectorConfig `yaml:"github"`
	GitLab ConnectorConfig `yaml:"gitlab"`
}

type ConnectorConfig struct {
	Enabled       bool              `yaml:"enabled"`
	BaseURL       string            `yaml:"base_url"`
	TokenEnv      string            `yaml:"token_env"`
	Headers       map[string]string `yaml:"headers"`
	AllowInsecure bool              `yaml:"allow_insecure"`
	Proxy         *ProxyConfig      `yaml:"proxy"`
}

type ProxyConfig struct {
	Enabled     *bool  `yaml:"enabled"`
	URL         string `yaml:"url"`
	NoProxy     string `yaml:"no_proxy"`
	UsernameEnv string `yaml:"username_env"`
	PasswordEnv string `yaml:"password_env"`
}

type PolicyProfile struct {
	Name            string       `yaml:"name"`
	RepositoryAllow []string     `yaml:"repository_allow"`
	RepositoryDeny  []string     `yaml:"repository_deny"`
	PathAllow       []string     `yaml:"path_allow"`
	PathDeny        []string     `yaml:"path_deny"`
	Rules           []PolicyRule `yaml:"rules"`
}

type PolicyRule struct {
	Name          string `yaml:"name"`
	Action        string `yaml:"action"`
	Literal       string `yaml:"literal"`
	Pattern       string `yaml:"pattern"`
	Replacement   string `yaml:"replacement"`
	ModelAllowed  bool   `yaml:"model_allowed"`
	ExportAllowed bool   `yaml:"export_allowed"`
}

type ModelEndpoint struct {
	Name         string        `yaml:"name"`
	ProviderKind string        `yaml:"provider_kind"`
	BaseURL      string        `yaml:"base_url"`
	Model        string        `yaml:"model"`
	APIKeyEnv    string        `yaml:"api_key_env"`
	Timeout      time.Duration `yaml:"timeout"`
	Proxy        *ProxyConfig  `yaml:"proxy"`
}

type LogLevel string

func (l LogLevel) Level() slog.Level {
	switch strings.ToLower(string(l)) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func Load() (Config, error) {
	path := os.Getenv("SCRM_CONFIG")
	if path == "" {
		cfg := defaultConfig()
		cfg.applyDefaults()
		cfg.normalizePaths("")
		return cfg, cfg.Validate()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	cfg.applyDefaults()
	cfg.normalizePaths(path)
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func defaultConfig() Config {
	return Config{
		LogLevel: "info",
		Runtime: RuntimeConfig{
			HTTPAddress:    ":8080",
			RequestTimeout: 8 * time.Second,
		},
		Database: DatabaseConfig{
			SQLitePath: defaultSQLitePath(),
		},
	}
}

func (c Config) Validate() error {
	if c.Runtime.HTTPAddress == "" {
		return errors.New("runtime.http_address is required")
	}
	if c.Runtime.RequestTimeout <= 0 {
		return errors.New("runtime.request_timeout must be greater than zero")
	}
	if c.Database.DSN == "" && c.Database.SQLitePath == "" {
		return errors.New("database.sqlite_path is required when database.dsn is empty")
	}
	if c.Auth.Issuer == "" {
		return errors.New("auth.issuer is required")
	}
	if c.Auth.Audience == "" {
		return errors.New("auth.audience is required")
	}
	if c.Auth.PublicKeyPEM == "" && c.Auth.PublicKeyEnv == "" {
		return errors.New("auth.public_key_pem or auth.public_key_env is required")
	}
	if c.Auth.PublicKeyPEM != "" && c.Auth.PublicKeyEnv != "" {
		return errors.New("only one of auth.public_key_pem or auth.public_key_env may be set")
	}
	if err := validateProxyConfig("network.proxy", c.Network.Proxy); err != nil {
		return err
	}
	for _, connector := range []struct {
		name string
		cfg  ConnectorConfig
	}{
		{name: "github", cfg: c.Connectors.GitHub},
		{name: "gitlab", cfg: c.Connectors.GitLab},
	} {
		if !connector.cfg.Enabled {
			continue
		}
		if connector.cfg.BaseURL == "" {
			return fmt.Errorf("connectors.%s.base_url is required when enabled", connector.name)
		}
		if err := validateProxyConfig(fmt.Sprintf("connectors.%s.proxy", connector.name), connector.cfg.Proxy); err != nil {
			return err
		}
	}
	for idx, model := range c.Models {
		if err := validateProxyConfig(fmt.Sprintf("models[%d].proxy", idx), model.Proxy); err != nil {
			return err
		}
	}
	seenProfiles := make(map[string]struct{}, len(c.Policies))
	for idx, policy := range c.Policies {
		if policy.Name == "" {
			return fmt.Errorf("policies[%d].name is required", idx)
		}
		if _, exists := seenProfiles[policy.Name]; exists {
			return fmt.Errorf("duplicate policy profile %q", policy.Name)
		}
		seenProfiles[policy.Name] = struct{}{}
		for ridx, rule := range policy.Rules {
			if err := validatePolicyRule(fmt.Sprintf("policies[%d].rules[%d]", idx, ridx), rule); err != nil {
				return err
			}
		}
	}
	if c.DefaultPolicyProfile != "" {
		if _, ok := seenProfiles[c.DefaultPolicyProfile]; !ok {
			return fmt.Errorf("default_policy_profile %q not found", c.DefaultPolicyProfile)
		}
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.Database.DSN == "" && c.Database.SQLitePath == "" {
		c.Database.SQLitePath = defaultSQLitePath()
	}
	if c.Auth.AdminRole == "" {
		c.Auth.AdminRole = "scrm_admin"
	}
}

func (c *Config) normalizePaths(configPath string) {
	if c.Database.DSN != "" || c.Database.SQLitePath == "" || filepath.IsAbs(c.Database.SQLitePath) {
		return
	}
	if configPath != "" {
		c.Database.SQLitePath = filepath.Clean(filepath.Join(filepath.Dir(configPath), c.Database.SQLitePath))
		return
	}
	c.Database.SQLitePath = filepath.Clean(c.Database.SQLitePath)
}

func defaultSQLitePath() string {
	baseDir, err := os.UserConfigDir()
	if err != nil || baseDir == "" {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil || home == "" {
			return filepath.Clean("var/secure-code-retrieval.db")
		}
		baseDir = filepath.Join(home, ".config")
	}
	return filepath.Join(baseDir, "secure-code-retrieval-mcp", "secure-code-retrieval.db")
}

func validatePolicyRule(name string, rule PolicyRule) error {
	switch rule.Action {
	case string("allow"), string("mask"), string("rewrite_required"), string("suppress"):
	default:
		return fmt.Errorf("%s.action must be one of allow, mask, rewrite_required, suppress", name)
	}
	if rule.Literal == "" && rule.Pattern == "" && rule.Action != "allow" {
		return fmt.Errorf("%s must set literal or pattern", name)
	}
	if rule.Pattern != "" {
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			return fmt.Errorf("%s.pattern is invalid: %w", name, err)
		}
	}
	return nil
}

func validateProxyConfig(name string, cfg *ProxyConfig) error {
	if cfg == nil {
		return nil
	}
	if cfg.UsernameEnv != "" && cfg.PasswordEnv == "" {
		return fmt.Errorf("%s.password_env is required when username_env is set", name)
	}
	if cfg.PasswordEnv != "" && cfg.UsernameEnv == "" {
		return fmt.Errorf("%s.username_env is required when password_env is set", name)
	}
	if cfg.Enabled != nil && !*cfg.Enabled {
		return nil
	}
	if cfg.URL != "" {
		parsed, err := url.Parse(cfg.URL)
		if err != nil {
			return fmt.Errorf("%s.url is invalid: %w", name, err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return fmt.Errorf("%s.url must use http or https", name)
		}
		if parsed.Host == "" {
			return fmt.Errorf("%s.url must include a host", name)
		}
	}
	if cfg.Enabled != nil && *cfg.Enabled && cfg.URL == "" {
		return fmt.Errorf("%s.url is required when proxy is enabled", name)
	}
	if cfg.UsernameEnv != "" {
		if os.Getenv(cfg.UsernameEnv) == "" {
			return fmt.Errorf("%s.username_env %q is not set", name, cfg.UsernameEnv)
		}
		if os.Getenv(cfg.PasswordEnv) == "" {
			return fmt.Errorf("%s.password_env %q is not set", name, cfg.PasswordEnv)
		}
	}
	return nil
}
