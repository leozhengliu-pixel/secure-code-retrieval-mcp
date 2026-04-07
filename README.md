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
- Applies policy-scoped deterministic policy evaluation and bounded sanitization
- Persists audit request / decision / delivery records in PostgreSQL
- Supports enterprise outbound proxy configuration with global defaults and per-connector / per-model overrides
- Requires Bearer JWT for HTTP search and audit APIs
- Exposes Prometheus metrics on `GET /metrics`

## Run

1. Start PostgreSQL and create a database.
2. Copy `config.example.yaml` and set `SCRM_CONFIG`.
3. Export connector, model, JWT, and optional proxy secrets referenced by `token_env`, `api_key_env`, `public_key_env`, `username_env`, and `password_env`.
4. Apply schema migrations with `go run ./cmd/migrate`.
5. Run `go run ./cmd/server`.

## Testing

Run `go test ./...`.

## Notes

- MCP is implemented with stdio JSON-RPC framing and the minimal `initialize`, `tools/list`, `tools/call`, and `ping` methods required for the single-tool MVP.
- The service fails closed on missing or invalid auth, unsupported filters, missing policy profile, policy errors, and sanitization errors.
- HTTP `POST /v1/search` derives `caller_principal` from JWT and does not accept caller identity in the request body.
- HTTP `GET /readyz` returns structured JSON readiness state for auth, database, migrations, and connector config.
