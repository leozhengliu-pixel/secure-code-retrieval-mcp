#!/usr/bin/env bash

set -euo pipefail

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_command openssl
require_command sqlite3
require_command go
require_command python3

workdir="$(mktemp -d)"
openssl genrsa -out "$workdir/private.pem" 2048 >/dev/null 2>&1
openssl rsa -in "$workdir/private.pem" -pubout -out "$workdir/public.pem" >/dev/null 2>&1

WORKDIR="$workdir" python3 - <<'PY'
import os
from pathlib import Path

workdir = Path(os.environ["WORKDIR"])
public_key = workdir.joinpath("public.pem").read_text()
config = f"""log_level: info
runtime:
  http_address: ":8080"
  request_timeout: 8s
database:
  sqlite_path: /work/secure-code-retrieval.db
auth:
  issuer: https://ci.local
  audience: secure-code-retrieval-mcp
  public_key_pem: |
{''.join(f'    {line}\n' for line in public_key.splitlines())}  admin_role: scrm_admin
default_policy_profile: default
connectors:
  github:
    enabled: false
  gitlab:
    enabled: false
policies:
  - name: default
    rules:
      - name: allow-basic
        action: allow
models: []
"""
workdir.joinpath("config.yaml").write_text(config)
mint = """package main

import (
  "crypto/rsa"
  "crypto/x509"
  "encoding/pem"
  "fmt"
  "os"
  "time"

  "github.com/golang-jwt/jwt/v5"
)

func main() {
  keyPEM, err := os.ReadFile(os.Args[1])
  if err != nil {
    panic(err)
  }
  block, _ := pem.Decode(keyPEM)
  if block == nil {
    panic("invalid pem")
  }
  key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
  if err != nil {
    parsed, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
    if err2 != nil {
      panic(err)
    }
    var ok bool
    key, ok = parsed.(*rsa.PrivateKey)
    if !ok {
      panic("not an RSA private key")
    }
  }
  now := time.Now().UTC()
  token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
    "iss": "https://ci.local",
    "aud": "secure-code-retrieval-mcp",
    "sub": os.Getenv("SMOKE_SUBJECT"),
    "roles": []string{"scrm_admin"},
    "iat": now.Unix(),
    "exp": now.Add(15 * time.Minute).Unix(),
    "jti": fmt.Sprintf("%d", now.UnixNano()),
  })
  signed, err := token.SignedString(key)
  if err != nil {
    panic(err)
  }
  fmt.Println(signed)
}
"""
workdir.joinpath("mint_jwt.go").write_text(mint)
PY

sqlite3 "$workdir/secure-code-retrieval.db" < internal/storage/sqlite/migrations/0001_audit.sql
sqlite3 "$workdir/secure-code-retrieval.db" "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (1, '$(date -u +%Y-%m-%dT%H:%M:%SZ)');"

subject="${SMOKE_SUBJECT:-ci-smoke}"
token="$(SMOKE_SUBJECT="$subject" go run "$workdir/mint_jwt.go" "$workdir/private.pem")"

echo "workdir=$workdir"
echo "token=$token"
