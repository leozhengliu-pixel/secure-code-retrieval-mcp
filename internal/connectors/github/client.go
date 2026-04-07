package github

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"secure-code-retrieval-mcp/internal/config"
	"secure-code-retrieval-mcp/internal/domain"
	"secure-code-retrieval-mcp/internal/httpclient"
)

type Client struct {
	cfg       config.ConnectorConfig
	client    *http.Client
	token     string
	usesProxy func(*http.Request) bool
}

func New(cfg config.ConnectorConfig, defaultProxy *config.ProxyConfig, logger *slog.Logger) (*Client, error) {
	transportResult, err := httpclient.BuildTransport(httpclient.BuildOptions{
		TargetName:    "github",
		AllowInsecure: cfg.AllowInsecure,
		EndpointProxy: cfg.Proxy,
		DefaultProxy:  defaultProxy,
		Logger:        logger,
	})
	if err != nil {
		return nil, err
	}
	token := ""
	if cfg.TokenEnv != "" {
		token = strings.TrimSpace(os.Getenv(cfg.TokenEnv))
	}
	return &Client{
		cfg:       cfg,
		client:    &http.Client{Timeout: 10 * time.Second, Transport: transportResult.Transport},
		token:     token,
		usesProxy: transportResult.UsesProxy,
	}, nil
}

func (c *Client) Search(ctx context.Context, req domain.SearchRequest) ([]domain.SearchResult, error) {
	if !c.cfg.Enabled {
		return nil, fmt.Errorf("%w: github connector disabled", domain.ErrConnector)
	}
	if len(req.Filters.Groups) > 0 {
		return nil, domain.ErrUnsupportedFilter
	}
	u, err := url.Parse(c.cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid github base url", domain.ErrConnector)
	}
	u.Path = path.Join(u.Path, "/search/code")
	q := u.Query()
	q.Set("q", compileQuery(req))
	perPage := req.Filters.PerPage
	if perPage <= 0 {
		perPage = req.MaxResults
	}
	if perPage > 100 {
		perPage = 100
	}
	q.Set("per_page", fmt.Sprintf("%d", perPage))
	if req.Filters.Page > 0 {
		q.Set("page", fmt.Sprintf("%d", req.Filters.Page))
	}
	u.RawQuery = q.Encode()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", domain.ErrConnector, err)
	}
	httpReq.Header.Set("Accept", "application/vnd.github.text-match+json")
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}
	for k, v := range c.cfg.Headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, classifyTransportError(err, c.usesProxy != nil && c.usesProxy(httpReq))
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		resp.Body.Close()
		time.Sleep(100 * time.Millisecond)
		resp, err = c.client.Do(httpReq.Clone(ctx))
		if err != nil {
			return nil, classifyTransportError(err, c.usesProxy != nil && c.usesProxy(httpReq))
		}
		defer resp.Body.Close()
	}
	if resp.StatusCode == http.StatusProxyAuthRequired {
		return nil, fmt.Errorf("%w: github proxy auth failed", domain.ErrProxyAuth)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%w: github auth failed", domain.ErrUnauthorized)
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.Header.Get("X-RateLimit-Remaining") == "0" {
		return nil, fmt.Errorf("%w: github rate limited", domain.ErrConnector)
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: github upstream status %d", domain.ErrConnector, resp.StatusCode)
	}

	var payload struct {
		Items []struct {
			Path       string `json:"path"`
			HTMLURL    string `json:"html_url"`
			Repository struct {
				FullName      string `json:"full_name"`
				DefaultBranch string `json:"default_branch"`
			} `json:"repository"`
			TextMatches []struct {
				Fragment string `json:"fragment"`
			} `json:"text_matches"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("%w: decode github response", domain.ErrConnector)
	}

	results := make([]domain.SearchResult, 0, len(payload.Items))
	for _, item := range payload.Items {
		snippet := ""
		if len(item.TextMatches) > 0 {
			snippet = item.TextMatches[0].Fragment
		}
		results = append(results, domain.SearchResult{
			SourceType:        domain.SourceTypeGitHub,
			SourceHost:        req.SourceHost,
			Repository:        item.Repository.FullName,
			FilePath:          item.Path,
			Ref:               item.Repository.DefaultBranch,
			Language:          languageFromPath(item.Path),
			SnippetTextRaw:    snippet,
			MatchRanges:       []domain.MatchRange{{StartLine: 1, EndLine: 1}},
			SourceURL:         item.HTMLURL,
			ConnectorMetadata: map[string]string{"backend": "github_api"},
		})
	}
	if len(results) > req.MaxResults {
		results = results[:req.MaxResults]
	}
	return results, nil
}

func (c *Client) ReadFile(ctx context.Context, req domain.FileReadRequest) (domain.FileContentResult, error) {
	if !c.cfg.Enabled {
		return domain.FileContentResult{}, fmt.Errorf("%w: github connector disabled", domain.ErrConnector)
	}
	endpoint, err := githubFileAPIURL(c.cfg.BaseURL, req.Repository, req.FilePath, req.Ref)
	if err != nil {
		return domain.FileContentResult{}, fmt.Errorf("%w: invalid github base url", domain.ErrConnector)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return domain.FileContentResult{}, fmt.Errorf("%w: %v", domain.ErrConnector, err)
	}
	httpReq.Header.Set("Accept", "application/vnd.github+json")
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}
	for k, v := range c.cfg.Headers {
		httpReq.Header.Set(k, v)
	}
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return domain.FileContentResult{}, classifyTransportError(err, c.usesProxy != nil && c.usesProxy(httpReq))
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return domain.FileContentResult{}, fmt.Errorf("%w: github auth failed", domain.ErrUnauthorized)
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.Header.Get("X-RateLimit-Remaining") == "0" {
		return domain.FileContentResult{}, fmt.Errorf("%w: github rate limited", domain.ErrConnector)
	}
	if resp.StatusCode == http.StatusNotFound {
		return domain.FileContentResult{}, fmt.Errorf("%w: github file not found", domain.ErrNotFound)
	}
	if resp.StatusCode >= 300 {
		return domain.FileContentResult{}, fmt.Errorf("%w: github upstream status %d", domain.ErrConnector, resp.StatusCode)
	}
	var payload struct {
		Type     string `json:"type"`
		Path     string `json:"path"`
		HTMLURL  string `json:"html_url"`
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return domain.FileContentResult{}, fmt.Errorf("%w: decode github response", domain.ErrConnector)
	}
	if payload.Type != "file" || payload.Encoding != "base64" {
		return domain.FileContentResult{}, fmt.Errorf("%w: github content is not a text file", domain.ErrInvalidRequest)
	}
	decoded, err := decodeGitHubContent(payload.Content)
	if err != nil {
		return domain.FileContentResult{}, err
	}
	return domain.FileContentResult{
		SourceType:        domain.SourceTypeGitHub,
		SourceHost:        req.SourceHost,
		Repository:        req.Repository,
		FilePath:          payload.Path,
		Ref:               req.Ref,
		Language:          languageFromPath(payload.Path),
		FullTextRaw:       decoded,
		SourceURL:         payload.HTMLURL,
		ConnectorMetadata: map[string]string{"backend": "github_contents_api"},
	}, nil
}

func compileQuery(req domain.SearchRequest) string {
	parts := []string{req.QueryText}
	for _, repo := range req.Filters.Repositories {
		parts = append(parts, "repo:"+repo)
	}
	for _, org := range req.Filters.Organizations {
		parts = append(parts, "org:"+org)
	}
	for _, p := range req.Filters.Paths {
		parts = append(parts, "path:"+p)
	}
	for _, ext := range req.Filters.Extensions {
		parts = append(parts, "extension:"+strings.TrimPrefix(ext, "."))
	}
	for _, lang := range req.Filters.Languages {
		parts = append(parts, "language:"+lang)
	}
	return strings.Join(parts, " ")
}
