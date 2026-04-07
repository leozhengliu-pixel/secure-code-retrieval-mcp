package github

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"secure-code-retrieval-mcp/internal/domain"
)

func classifyTransportError(err error, proxyEnabled bool) error {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		if proxyEnabled {
			return fmt.Errorf("%w: %v", domain.ErrProxyTimeout, err)
		}
		return fmt.Errorf("%w: timeout", domain.ErrConnector)
	}
	if proxyEnabled {
		return fmt.Errorf("%w: %v", domain.ErrProxyConnect, err)
	}
	return fmt.Errorf("%w: %v", domain.ErrConnector, err)
}

func languageFromPath(p string) string {
	ext := strings.TrimPrefix(filepath.Ext(p), ".")
	switch ext {
	case "go":
		return "Go"
	case "py":
		return "Python"
	case "js":
		return "JavaScript"
	case "ts":
		return "TypeScript"
	case "java":
		return "Java"
	default:
		return strings.ToUpper(ext)
	}
}

func githubFileAPIURL(baseURL, repository, filePath, ref string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/repos/" + repository + "/contents/" + strings.TrimPrefix(filePath, "/")
	q := u.Query()
	if ref != "" {
		q.Set("ref", ref)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func decodeGitHubContent(raw string) (string, error) {
	cleaned := strings.ReplaceAll(raw, "\n", "")
	bytes, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return "", err
	}
	if !isTextContent(bytes) {
		return "", fmt.Errorf("%w: github content is binary", domain.ErrInvalidRequest)
	}
	return string(bytes), nil
}

func isTextContent(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	for _, b := range raw {
		if b == 0 {
			return false
		}
	}
	return true
}
