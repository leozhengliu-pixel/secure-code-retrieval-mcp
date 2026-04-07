# Secure Code Retrieval MCP Gateway

This repository now contains a runnable Go implementation of the MVP gateway described in `docs/`.

## What it does

- Exposes an HTTP streamable MCP server at `POST /mcp` with the `code_search_secure` and `code_view_secure` tools
- Exposes HTTP health and audit endpoints:
  - `GET /healthz`
  - `GET /readyz`
  - `GET /metrics`
  - `GET /v1/audit/{request_id}`
- Uses GitHub and GitLab native search APIs as retrieval backends
- Applies policy-scoped deterministic policy evaluation and bounded sanitization
- Persists audit request / decision / delivery records in local SQLite by default, or PostgreSQL when `database.dsn` is configured
- Supports enterprise outbound proxy configuration with global defaults and per-connector / per-model overrides
- Requires Bearer JWT for HTTP MCP and audit APIs

## Run

1. Copy `config.example.yaml` and set `SCRM_CONFIG`.
2. Export connector, model, JWT, and optional proxy secrets referenced by `token_env`, `api_key_env`, `public_key_env`, `username_env`, and `password_env`.
3. If you want PostgreSQL, set `database.dsn`. If you leave it unset, the service uses local SQLite at `database.sqlite_path`.
4. Apply schema migrations with `go run ./cmd/migrate`.
5. Run `go run ./cmd/server`.

## Testing

Run `go test ./...`.

## Notes

- MCP is implemented as an HTTP JSON-RPC endpoint at `/mcp` with the `initialize`, `tools/list`, `tools/call`, and `ping` methods.
- `code_search_secure` returns policy-sanitized search evidence and optional digest summaries.
- `code_view_secure` returns a policy-sanitized file window for an explicit `repository + file_path + ref + start_line + line_count`.
- The service fails closed on missing or invalid auth, unsupported filters, missing policy profile, policy errors, and sanitization errors.
- `/mcp` derives `caller_principal` from JWT and does not accept caller identity in tool arguments.
- HTTP `GET /readyz` returns structured JSON readiness state for auth, database, migrations, and connector config.
