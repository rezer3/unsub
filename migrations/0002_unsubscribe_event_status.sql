ALTER TABLE unsubscribe_events ADD COLUMN status TEXT NOT NULL DEFAULT 'received';
ALTER TABLE unsubscribe_events ADD COLUMN reviewed_at TEXT;
ALTER TABLE unsubscribe_events ADD COLUMN reviewed_by TEXT;
ALTER TABLE unsubscribe_events ADD COLUMN notes TEXT;

CREATE INDEX IF NOT EXISTS idx_unsubscribe_events_status_created_at
  ON unsubscribe_events(status, created_at);
