# Secure Code Retrieval MCP Gateway

This repository now contains a runnable Go implementation of the MVP gateway described in `docs/`.

## What it does

- Exposes a minimal MCP server over stdio with the `code_search_secure` tool
- Exposes HTTP health endpoints and a small internal API:
  - `GET /healthz`
  - `GET /readyz`
  - `POST /v1/search`
  - `GET /v1/audit/{request_id}`
- Uses GitHub and GitLab native search APIs as retrieval backends
- Applies tenant-scoped deterministic policy evaluation and bounded sanitization
- Persists audit request / decision / delivery records in PostgreSQL
- Supports enterprise outbound proxy configuration with global defaults and per-connector / per-model overrides

## Run

1. Start PostgreSQL and create a database.
2. Copy `config.example.yaml` and set `SCRM_CONFIG`.
3. Export connector, model, and optional proxy secrets referenced by `token_env`, `api_key_env`, `username_env`, and `password_env`.
4. Run `go run ./cmd/server`.

## Testing

Run `go test ./...`.

## Notes

- MCP is implemented with stdio JSON-RPC framing and the minimal `initialize`, `tools/list`, `tools/call`, and `ping` methods required for the single-tool MVP.
- The service fails closed on missing tenant context, missing principal, unsupported filters, policy errors, and sanitization errors.
