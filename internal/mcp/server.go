package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"secure-code-retrieval-mcp/internal/domain"
	"secure-code-retrieval-mcp/internal/gateway"
)

type Server struct {
	service *gateway.Service
	logger  *slog.Logger
	in      io.Reader
	out     io.Writer
}

func NewServer(service *gateway.Service, logger *slog.Logger) *Server {
	return &Server{service: service, logger: logger, in: os.Stdin, out: os.Stdout}
}

func (s *Server) Serve(ctx context.Context) error {
	reader := bufio.NewReader(s.in)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		payload, err := readFrame(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		var req rpcRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return s.write(rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}})
		}
		if req.Method == "" {
			continue
		}
		resp := s.handle(ctx, req)
		if req.ID == nil {
			continue
		}
		if err := s.write(resp); err != nil {
			return err
		}
	}
}

func (s *Server) handle(ctx context.Context, req rpcRequest) rpcResponse {
	switch req.Method {
	case "initialize":
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": "2024-11-05",
				"serverInfo":      map[string]string{"name": "secure-code-retrieval-mcp", "version": "0.1.0"},
				"capabilities":    map[string]any{"tools": map[string]any{}},
			},
		}
	case "tools/list":
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"tools": []map[string]any{{
					"name":        "code_search_secure",
					"description": "Search enterprise code and return policy-sanitized snippets",
					"inputSchema": toolInputSchema(),
				}},
			},
		}
	case "tools/call":
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := decodeParams(req.Params, &params); err != nil {
			return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: "invalid params"}}
		}
		if params.Name != "code_search_secure" {
			return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: "tool not found"}}
		}
		var input gateway.SearchInput
		if err := json.Unmarshal(params.Arguments, &input); err != nil {
			return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: "invalid tool arguments"}}
		}
		resp, err := s.service.Search(ctx, input)
		if err != nil {
			return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32000, Message: err.Error()}}
		}
		data, _ := json.Marshal(resp)
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"content":           []map[string]string{{"type": "text", "text": string(data)}},
				"structuredContent": resp,
			},
		}
	case "ping":
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]string{"status": "ok"}}
	default:
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: "method not found"}}
	}
}

func decodeParams(raw json.RawMessage, out any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func (s *Server) write(resp rpcResponse) error {
	payload, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(s.out, "Content-Length: %d\r\n\r\n%s", len(payload), payload)
	return err
}

func readFrame(reader *bufio.Reader) ([]byte, error) {
	header, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(strings.ToLower(header), "content-length:") {
		return nil, fmt.Errorf("unexpected header: %s", header)
	}
	lengthValue := strings.TrimSpace(strings.TrimPrefix(header, "Content-Length:"))
	length, err := strconv.Atoi(lengthValue)
	if err != nil {
		return nil, err
	}
	if _, err := reader.ReadString('\n'); err != nil {
		return nil, err
	}
	payload := make([]byte, length)
	_, err = io.ReadFull(reader, payload)
	return payload, err
}

func toolInputSchema() map[string]any {
	return map[string]any{
		"type":     "object",
		"required": []string{"tenant_id", "caller_principal", "source_type", "source_host", "query_text", "max_results", "response_mode"},
		"properties": map[string]any{
			"request_id":       map[string]string{"type": "string"},
			"tenant_id":        map[string]string{"type": "string"},
			"caller_principal": map[string]string{"type": "string"},
			"source_type":      map[string]any{"type": "string", "enum": []string{string(domain.SourceTypeGitHub), string(domain.SourceTypeGitLab)}},
			"source_host":      map[string]string{"type": "string"},
			"query_text":       map[string]string{"type": "string"},
			"max_results":      map[string]string{"type": "integer"},
			"policy_profile":   map[string]string{"type": "string"},
			"response_mode":    map[string]any{"type": "string", "enum": []string{string(domain.ResponseModeSnippet), string(domain.ResponseModeSummary)}},
			"filters":          map[string]any{"type": "object"},
		},
	}
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id,omitempty"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
