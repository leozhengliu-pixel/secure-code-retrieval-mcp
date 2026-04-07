#!/usr/bin/env bash

set -euo pipefail

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "missing required environment variable: $name" >&2
    exit 1
  fi
}

require_command curl
require_command jq

require_env MCP_URL
require_env MCP_BEARER_TOKEN

if [[ -z "${MCP_ORIGIN:-}" ]]; then
  MCP_ORIGIN="$(python3 - <<'PY' "$MCP_URL"
import sys
from urllib.parse import urlparse

u = urlparse(sys.argv[1])
print(f"{u.scheme}://{u.netloc}")
PY
)"
fi

post_json() {
  local payload="$1"
  curl --silent --show-error --fail \
    -X POST "$MCP_URL" \
    -H "Authorization: Bearer $MCP_BEARER_TOKEN" \
    -H "Accept: application/json, text/event-stream" \
    -H "Content-Type: application/json" \
    -H "Origin: $MCP_ORIGIN" \
    --data "$payload"
}

echo "smoke: initialize"
initialize_response="$(post_json '{"jsonrpc":"2.0","id":"initialize-smoke","method":"initialize"}')"
echo "$initialize_response" | jq -e '
  .jsonrpc == "2.0" and
  .id == "initialize-smoke" and
  (.result.protocolVersion | type == "string") and
  .result.serverInfo.name == "secure-code-retrieval-mcp"
' >/dev/null

echo "smoke: tools/list"
tools_response="$(post_json '{"jsonrpc":"2.0","id":"tools-smoke","method":"tools/list"}')"
echo "$tools_response" | jq -e '
  .jsonrpc == "2.0" and
  .id == "tools-smoke" and
  (
    [.result.tools[].name] |
    index("code_search_secure") != null and
    index("code_view_secure") != null
  )
' >/dev/null

if [[ -n "${MCP_TOOL_NAME:-}" ]]; then
  require_env MCP_TOOL_ARGUMENTS_JSON
  echo "smoke: tools/call ($MCP_TOOL_NAME)"
  tool_payload="$(
    jq -cn \
      --arg tool_name "$MCP_TOOL_NAME" \
      --argjson tool_args "$MCP_TOOL_ARGUMENTS_JSON" \
      '{jsonrpc:"2.0", id:"tool-smoke", method:"tools/call", params:{name:$tool_name, arguments:$tool_args}}'
  )"
  tool_response="$(post_json "$tool_payload")"
  echo "$tool_response" | jq -e '
    .jsonrpc == "2.0" and
    .id == "tool-smoke" and
    (.error | not)
  ' >/dev/null
fi

echo "mcp smoke test passed"
