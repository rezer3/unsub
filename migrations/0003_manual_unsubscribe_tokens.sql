CREATE TABLE IF NOT EXISTS manual_unsubscribe_tokens (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  created_by TEXT,
  email TEXT NOT NULL,
  email_normalized TEXT NOT NULL,
  scope_type TEXT NOT NULL DEFAULT 'global',
  scope_key TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT 'manual_ui',
  method TEXT NOT NULL DEFAULT 'manual_generated',
  token_id TEXT NOT NULL,
  token_version TEXT NOT NULL,
  signed INTEGER NOT NULL DEFAULT 0,
  token_value TEXT NOT NULL,
  token_url TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_manual_unsubscribe_tokens_created_at
  ON manual_unsubscribe_tokens(created_at);

CREATE INDEX IF NOT EXISTS idx_manual_unsubscribe_tokens_email_created_at
  ON manual_unsubscribe_tokens(email_normalized, created_at);
