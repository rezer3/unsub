CREATE TABLE IF NOT EXISTS email_notification_cooldowns (
  email_normalized TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  window_started_at TEXT NOT NULL,
  last_event_at TEXT NOT NULL,
  last_event_id TEXT NOT NULL,
  last_notified_at TEXT NOT NULL,
  last_notified_event_id TEXT NOT NULL,
  cooldown_until TEXT NOT NULL,
  repeat_count INTEGER NOT NULL DEFAULT 1,
  suppressed_alert_count INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_email_notification_cooldowns_updated_at
  ON email_notification_cooldowns(updated_at);

CREATE INDEX IF NOT EXISTS idx_email_notification_cooldowns_cooldown_until
  ON email_notification_cooldowns(cooldown_until);
