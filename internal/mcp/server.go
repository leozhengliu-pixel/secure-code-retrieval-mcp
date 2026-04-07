package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"secure-code-retrieval-mcp/internal/domain"
	"secure-code-retrieval-mcp/internal/gateway"
)

type Server struct {
	service *gateway.Service
	logger  *slog.Logger
}

func NewServer(service *gateway.Service, logger *slog.Logger) *Server {
	return &Server{service: service, logger: logger}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	case http.MethodPost:
	default:
		writeJSON(w, http.StatusMethodNotAllowed, rpcResponse{
			JSONRPC: "2.0",
			Error:   &rpcError{Code: -32600, Message: "invalid request"},
		})
		return
	}
	if !acceptsMCPPost(r.Header.Get("Accept")) {
		writeJSON(w, http.StatusNotAcceptable, rpcResponse{
			JSONRPC: "2.0",
			Error:   &rpcError{Code: -32600, Message: "invalid accept header"},
		})
		return
	}

	var raw json.RawMessage
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&raw); err != nil {
		writeJSON(w, http.StatusBadRequest, rpcResponse{
			JSONRPC: "2.0",
			Error:   &rpcError{Code: -32700, Message: "parse error"},
		})
		return
	}
	requests, batch, hasRequest, err := decodeRPCRequests(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, rpcResponse{
			JSONRPC: "2.0",
			Error:   &rpcError{Code: -32600, Message: "invalid request"},
		})
		return
	}
	if !hasRequest {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	responses := make([]rpcResponse, 0, len(requests))
	for _, req := range requests {
		resp := s.handle(r.Context(), req)
		if req.ID != nil {
			responses = append(responses, resp)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if batch {
		writeJSON(w, http.StatusOK, responses)
		return
	}
	if len(responses) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeJSON(w, http.StatusOK, responses[0])
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
				"tools": []map[string]any{
					{
						"name":        "code_search_secure",
						"description": "Search enterprise code and return policy-sanitized snippets",
						"inputSchema": searchToolInputSchema(),
					},
					{
						"name":        "code_view_secure",
						"description": "Read a policy-sanitized file window from enterprise code",
						"inputSchema": fileViewToolInputSchema(),
					},
				},
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
		if params.Name != "code_search_secure" && params.Name != "code_view_secure" {
			return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: "tool not found"}}
		}
		return s.handleToolCall(ctx, req.ID, params.Name, params.Arguments)
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

func acceptsMCPPost(header string) bool {
	header = strings.ToLower(header)
	return strings.Contains(header, "application/json") && strings.Contains(header, "text/event-stream")
}

func decodeRPCRequests(raw json.RawMessage) ([]rpcRequest, bool, bool, error) {
	raw = json.RawMessage(bytesTrimSpace(raw))
	if len(raw) == 0 {
		return nil, false, false, errors.New("empty payload")
	}
	if raw[0] == '[' {
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, false, false, err
		}
		requests := make([]rpcRequest, 0, len(items))
		hasRequest := false
		for _, item := range items {
			req, isRequest, err := decodeSingleRPCRequest(item)
			if err != nil {
				return nil, true, false, err
			}
			if isRequest {
				hasRequest = true
			}
			requests = append(requests, req)
		}
		return requests, true, hasRequest, nil
	}
	req, isRequest, err := decodeSingleRPCRequest(raw)
	if err != nil {
		return nil, false, false, err
	}
	return []rpcRequest{req}, false, isRequest, nil
}

func decodeSingleRPCRequest(raw json.RawMessage) (rpcRequest, bool, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return rpcRequest{}, false, err
	}
	methodRaw, hasMethod := envelope["method"]
	if !hasMethod {
		return rpcRequest{}, false, nil
	}
	var req rpcRequest
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return rpcRequest{}, false, err
	}
	_, hasID := envelope["id"]
	var method string
	if err := json.Unmarshal(methodRaw, &method); err != nil || method == "" {
		return rpcRequest{}, false, errors.New("invalid method")
	}
	if !hasID {
		req.ID = nil
		return req, false, nil
	}
	return req, true, nil
}

func bytesTrimSpace(raw []byte) []byte {
	return []byte(strings.TrimSpace(string(raw)))
}

func searchToolInputSchema() map[string]any {
	return map[string]any{
		"type":     "object",
		"required": []string{"source_type", "source_host", "query_text", "max_results", "response_mode"},
		"properties": map[string]any{
			"request_id":     map[string]string{"type": "string"},
			"source_type":    map[string]any{"type": "string", "enum": []string{string(domain.SourceTypeGitHub), string(domain.SourceTypeGitLab)}},
			"source_host":    map[string]string{"type": "string"},
			"query_text":     map[string]string{"type": "string"},
			"max_results":    map[string]string{"type": "integer"},
			"policy_profile": map[string]string{"type": "string"},
			"response_mode":  map[string]any{"type": "string", "enum": []string{string(domain.ResponseModeSnippet), string(domain.ResponseModeSummary)}},
			"filters":        map[string]any{"type": "object"},
		},
	}
}

func fileViewToolInputSchema() map[string]any {
	return map[string]any{
		"type":     "object",
		"required": []string{"source_type", "source_host", "repository", "file_path", "ref", "start_line", "line_count"},
		"properties": map[string]any{
			"request_id":     map[string]string{"type": "string"},
			"source_type":    map[string]any{"type": "string", "enum": []string{string(domain.SourceTypeGitHub), string(domain.SourceTypeGitLab)}},
			"source_host":    map[string]string{"type": "string"},
			"repository":     map[string]string{"type": "string"},
			"file_path":      map[string]string{"type": "string"},
			"ref":            map[string]string{"type": "string"},
			"start_line":     map[string]string{"type": "integer"},
			"line_count":     map[string]string{"type": "integer"},
			"policy_profile": map[string]string{"type": "string"},
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

func mapMCPError(err error) (int, string) {
	switch {
	case errors.Is(err, domain.ErrInvalidRequest), errors.Is(err, domain.ErrMissingPrincipal):
		return -32602, "invalid_request"
	case errors.Is(err, domain.ErrUnauthorized):
		return -32001, "unauthorized"
	case errors.Is(err, domain.ErrForbidden):
		return -32003, "forbidden"
	case errors.Is(err, domain.ErrUnsupportedFilter):
		return -32022, "unsupported_filter"
	case errors.Is(err, domain.ErrConnector), errors.Is(err, domain.ErrProxyAuth), errors.Is(err, domain.ErrProxyTimeout), errors.Is(err, domain.ErrProxyConnect):
		return -32050, "connector_error"
	case errors.Is(err, domain.ErrPolicyEvaluation):
		return -32060, "policy_error"
	case errors.Is(err, domain.ErrSanitization):
		return -32070, "sanitize_error"
	case errors.Is(err, domain.ErrAuditPersistence):
		return -32080, "audit_error"
	default:
		return -32000, "internal_error"
	}
}

func (s *Server) handleToolCall(ctx context.Context, id any, name string, arguments json.RawMessage) rpcResponse {
	principal := domain.PrincipalFromContext(ctx)
	roles := domain.RolesFromContext(ctx)
	switch name {
	case "code_search_secure":
		var input gateway.SearchInput
		decoder := json.NewDecoder(strings.NewReader(string(arguments)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: -32602, Message: "invalid tool arguments"}}
		}
		if input.CallerPrincipal != "" {
			return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: -32602, Message: "caller_principal must not be supplied"}}
		}
		input.CallerPrincipal = principal
		input.CallerRoles = append([]string(nil), roles...)
		ctx = domain.WithRequestMetadata(ctx, input.RequestID, input.CallerPrincipal, input.CallerRoles)
		resp, err := s.service.Search(ctx, input)
		if err != nil {
			code, payload := mapMCPError(err)
			return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: payload}}
		}
		return toolSuccessResponse(id, resp)
	case "code_view_secure":
		var input gateway.FileReadInput
		decoder := json.NewDecoder(strings.NewReader(string(arguments)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: -32602, Message: "invalid tool arguments"}}
		}
		if input.CallerPrincipal != "" {
			return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: -32602, Message: "caller_principal must not be supplied"}}
		}
		input.CallerPrincipal = principal
		input.CallerRoles = append([]string(nil), roles...)
		ctx = domain.WithRequestMetadata(ctx, input.RequestID, input.CallerPrincipal, input.CallerRoles)
		resp, err := s.service.ReadFileWindow(ctx, input)
		if err != nil {
			code, payload := mapMCPError(err)
			return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: payload}}
		}
		return toolSuccessResponse(id, resp)
	default:
		return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: -32601, Message: "tool not found"}}
	}
}

func toolSuccessResponse(id any, payload any) rpcResponse {
	data, _ := json.Marshal(payload)
	return rpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: map[string]any{
			"content":           []map[string]string{{"type": "text", "text": string(data)}},
			"structuredContent": payload,
		},
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
