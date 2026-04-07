package gitlab

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"

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

func gitlabSourceURL(baseURL string, projectID int, ref, filePath string) string {
	if baseURL == "" || filePath == "" {
		return ""
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	if ref == "" {
		ref = "HEAD"
	}
	u.RawQuery = ""
	u.Fragment = ""
	u.Path = gitlabWebBasePath(u.Path) + fmt.Sprintf("/-/project/%d/blob/%s/%s", projectID, url.PathEscape(ref), strings.TrimPrefix(filePath, "/"))
	return u.String()
}

func gitlabWebBasePath(apiPath string) string {
	trimmed := strings.TrimSuffix(strings.TrimSpace(apiPath), "/")
	switch {
	case trimmed == "/api/v4":
		return ""
	case strings.HasSuffix(trimmed, "/api/v4"):
		return strings.TrimSuffix(trimmed, "/api/v4")
	default:
		return trimmed
	}
}
