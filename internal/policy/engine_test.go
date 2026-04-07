package policy

import (
	"context"
	"testing"

	"secure-code-retrieval-mcp/internal/config"
	"secure-code-retrieval-mcp/internal/domain"
)

func TestSuppressesDeniedContent(t *testing.T) {
	engine, err := NewEngine([]config.PolicyProfile{{Name: "default", Rules: []config.PolicyRule{{Name: "secret", Action: "suppress", Literal: "SECRET", ExportAllowed: false}}}})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := engine.Evaluate(context.Background(), domain.SearchRequest{PolicyProfile: "default"}, domain.SearchResult{Repository: "repo", FilePath: "main.go", SnippetTextRaw: `const key = "SECRET"`})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != domain.DecisionSuppress {
		t.Fatalf("expected suppress, got %s", decision.Decision)
	}
}
