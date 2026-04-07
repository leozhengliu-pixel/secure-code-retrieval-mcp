package sanitize

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"secure-code-retrieval-mcp/internal/domain"
)

func TestMaskResult(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	service := NewService(&ProviderFactory{}, logger)
	result, modelInvoked, err := service.Sanitize(context.Background(), domain.SearchRequest{ResponseMode: domain.ResponseModeSnippet}, domain.SearchResult{Repository: "repo", FilePath: "main.go", SnippetTextRaw: `api_key = "123"`}, domain.PolicyDecision{Decision: domain.DecisionMask, ExportAllowed: true})
	if err != nil {
		t.Fatal(err)
	}
	if modelInvoked {
		t.Fatal("did not expect model invocation")
	}
	if result.SnippetText == `api_key = "123"` {
		t.Fatal("expected snippet to be masked")
	}
}
