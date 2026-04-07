package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
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
		TargetName:    "gitlab",
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
		return nil, fmt.Errorf("%w: gitlab connector disabled", domain.ErrConnector)
	}
	if len(req.Filters.Organizations) > 0 {
		return nil, domain.ErrUnsupportedFilter
	}
	u, err := url.Parse(c.cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid gitlab base url", domain.ErrConnector)
	}
	u.Path = path.Join(u.Path, "/search")
	q := u.Query()
	q.Set("scope", "blobs")
	q.Set("search", req.QueryText)
	if len(req.Filters.Groups) > 0 {
		q.Set("group_id", req.Filters.Groups[0])
	}
	if len(req.Filters.Repositories) > 0 {
		q.Set("project_id", req.Filters.Repositories[0])
	}
	perPage := req.Filters.PerPage
	if perPage <= 0 {
		perPage = req.MaxResults
	}
	if perPage > 100 {
		perPage = 100
	}
	q.Set("per_page", strconv.Itoa(perPage))
	if req.Filters.Page > 0 {
		q.Set("page", strconv.Itoa(req.Filters.Page))
	}
	u.RawQuery = q.Encode()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", domain.ErrConnector, err)
	}
	if c.token != "" {
		httpReq.Header.Set("PRIVATE-TOKEN", c.token)
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
		return nil, fmt.Errorf("%w: gitlab proxy auth failed", domain.ErrProxyAuth)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%w: gitlab auth failed", domain.ErrUnauthorized)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("%w: gitlab rate limited", domain.ErrConnector)
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: gitlab upstream status %d", domain.ErrConnector, resp.StatusCode)
	}

	var payload []struct {
		Path      string `json:"path"`
		Filename  string `json:"filename"`
		StartLine int    `json:"startline"`
		ProjectID int    `json:"project_id"`
		Data      string `json:"data"`
		Ref       string `json:"ref"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("%w: decode gitlab response", domain.ErrConnector)
	}

	results := make([]domain.SearchResult, 0, len(payload))
	for _, item := range payload {
		filePath := item.Path
		if filePath == "" {
			filePath = item.Filename
		}
		results = append(results, domain.SearchResult{
			SourceType:        domain.SourceTypeGitLab,
			SourceHost:        req.SourceHost,
			Repository:        strconv.Itoa(item.ProjectID),
			FilePath:          filePath,
			Ref:               item.Ref,
			Language:          languageFromPath(filePath),
			SnippetTextRaw:    item.Data,
			MatchRanges:       []domain.MatchRange{{StartLine: item.StartLine, EndLine: item.StartLine}},
			SourceURL:         gitlabSourceURL(c.cfg.BaseURL, item.ProjectID, item.Ref, filePath),
			ConnectorMetadata: map[string]string{"backend": "gitlab_api"},
		})
	}
	if len(results) > req.MaxResults {
		results = results[:req.MaxResults]
	}
	return results, nil
}
