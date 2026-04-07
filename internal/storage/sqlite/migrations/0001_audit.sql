CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_requests (
  audit_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE,
  caller_principal TEXT NOT NULL,
  caller_roles_json TEXT NOT NULL,
  source_type TEXT NOT NULL,
  source_host TEXT NOT NULL,
  query_text TEXT NOT NULL,
  filters_json TEXT NOT NULL,
  policy_profile TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_decisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id TEXT NOT NULL,
  audit_id TEXT NOT NULL,
  evidence_id TEXT NOT NULL,
  repository TEXT NOT NULL,
  file_path TEXT NOT NULL,
  line_start INTEGER NOT NULL,
  line_end INTEGER NOT NULL,
  decision TEXT NOT NULL,
  matched_rules TEXT NOT NULL,
  model_invoked INTEGER NOT NULL,
  release_mode TEXT NOT NULL,
  suppression_reason TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_deliveries (
  audit_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  snippet_count INTEGER NOT NULL,
  raw_hit_count INTEGER NOT NULL,
  evidence_count INTEGER NOT NULL,
  suppressed_count INTEGER NOT NULL,
  response_bytes INTEGER NOT NULL,
  connector_stats TEXT NOT NULL,
  latency_millis INTEGER NOT NULL,
  results_truncated INTEGER NOT NULL,
  suppressed_due_to_budget INTEGER NOT NULL,
  remaining_hits_estimate INTEGER NOT NULL,
  summary_generated INTEGER NOT NULL,
  summary_citation_ids TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_requests_caller_principal ON audit_requests (caller_principal);
CREATE INDEX IF NOT EXISTS idx_audit_decisions_request_id ON audit_decisions (request_id);
CREATE INDEX IF NOT EXISTS idx_audit_decisions_audit_id ON audit_decisions (audit_id);
CREATE INDEX IF NOT EXISTS idx_audit_deliveries_request_id ON audit_deliveries (request_id);
