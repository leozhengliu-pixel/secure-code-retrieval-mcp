package sanitize

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"secure-code-retrieval-mcp/internal/config"
	"secure-code-retrieval-mcp/internal/httpclient"
)

func newProvider(cfg config.ModelEndpoint, defaultProxy *config.ProxyConfig, logger *slog.Logger) Rewriter {
	if cfg.BaseURL == "" || cfg.Model == "" {
		return nil
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	transportResult, err := httpclient.BuildTransport(httpclient.BuildOptions{
		TargetName:    "model:" + cfg.Name,
		AllowInsecure: false,
		EndpointProxy: cfg.Proxy,
		DefaultProxy:  defaultProxy,
		Logger:        logger,
	})
	if err != nil {
		return nil
	}
	client := &http.Client{Timeout: timeout, Transport: transportResult.Transport}
	switch strings.ToLower(cfg.ProviderKind) {
	case "openai_compatible":
		return &openAICompatibleProvider{client: client, cfg: cfg}
	case "anthropic_compatible":
		return &anthropicCompatibleProvider{client: client, cfg: cfg}
	default:
		return nil
	}
}

type openAICompatibleProvider struct {
	client *http.Client
	cfg    config.ModelEndpoint
}

func (p *openAICompatibleProvider) Rewrite(ctx context.Context, snippet string) (string, error) {
	body := map[string]any{
		"model": p.cfg.Model,
		"messages": []map[string]string{
			{"role": "system", "content": "Rewrite code into sanitized abstract pseudocode without secrets or internal identifiers."},
			{"role": "user", "content": snippet},
		},
	}
	data, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.BaseURL, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if key := strings.TrimSpace(os.Getenv(p.cfg.APIKeyEnv)); key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("provider returned %d", resp.StatusCode)
	}
	var payload struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if len(payload.Choices) == 0 {
		return "", fmt.Errorf("empty provider response")
	}
	return payload.Choices[0].Message.Content, nil
}

type anthropicCompatibleProvider struct {
	client *http.Client
	cfg    config.ModelEndpoint
}

func (p *anthropicCompatibleProvider) Rewrite(ctx context.Context, snippet string) (string, error) {
	body := map[string]any{
		"model":      p.cfg.Model,
		"max_tokens": 512,
		"messages": []map[string]string{{
			"role":    "user",
			"content": "Rewrite this code into sanitized abstract pseudocode without secrets or internal identifiers:\n" + snippet,
		}},
	}
	data, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.BaseURL, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if key := strings.TrimSpace(os.Getenv(p.cfg.APIKeyEnv)); key != "" {
		req.Header.Set("x-api-key", key)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("provider returned %d", resp.StatusCode)
	}
	var payload struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if len(payload.Content) == 0 {
		return "", fmt.Errorf("empty provider response")
	}
	return payload.Content[0].Text, nil
}
