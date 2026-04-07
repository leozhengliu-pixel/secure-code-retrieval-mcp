package github

import (
	"errors"
	"fmt"
	"net"
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
