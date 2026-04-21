CREATE TABLE IF NOT EXISTS email_suppressions (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  channel TEXT NOT NULL DEFAULT 'email',
  email TEXT NOT NULL,
  email_normalized TEXT NOT NULL,
  scope_type TEXT NOT NULL DEFAULT 'global',
  scope_key TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT 'manual',
  method TEXT NOT NULL DEFAULT 'manual',
  reason TEXT,
  notes TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_email_suppressions_lookup
  ON email_suppressions(channel, email_normalized, scope_type, scope_key);

CREATE INDEX IF NOT EXISTS idx_email_suppressions_updated_at
  ON email_suppressions(updated_at);

CREATE TABLE IF NOT EXISTS unsubscribe_events (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  email TEXT,
  email_normalized TEXT,
  scope_type TEXT NOT NULL DEFAULT 'global',
  scope_key TEXT NOT NULL DEFAULT '',
  method TEXT NOT NULL,
  source TEXT NOT NULL,
  event_type TEXT NOT NULL,
  token_id TEXT,
  ip_address TEXT,
  user_agent TEXT,
  payload_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_unsubscribe_events_email_created_at
  ON unsubscribe_events(email_normalized, created_at);

CREATE INDEX IF NOT EXISTS idx_unsubscribe_events_scope_created_at
  ON unsubscribe_events(scope_type, scope_key, created_at);
