# unsub

Cloudflare Worker scaffold for shared email suppression and unsubscribe handling.

## Resources

- Worker: `unsub`
- D1: `unsub_db`
- Binding: `UNSUB_DB`

## Endpoints

- `GET /ui` serves the unsubscribe review dashboard
- `GET /admin` serves the same dashboard as an alias
- `GET /health` returns a basic health payload
- `GET /u/:token` logs a body-link unsubscribe event and shows a confirmation page
- `POST /api/unsubscribe/:token` logs an API unsubscribe event and returns JSON
- `GET /api/admin/events` returns recent unsubscribe events
- `GET /api/admin/generated-tokens` returns recently generated manual footer links
- `GET /api/admin/email-settings` returns unsubscribe email notification settings
- `POST /api/admin/generate-token` generates a full unsubscribe link for one email and stores it
- `POST /api/admin/email-settings` saves unsubscribe email notification settings
- `POST /api/admin/mark-reviewed` marks an event as reviewed
- `POST /api/admin/suppress` inserts a suppression entry and marks the event suppressed

The migrations create tables for:

- `email_suppressions`
- `unsubscribe_events`
- `manual_unsubscribe_tokens`
- `admin_settings`
- `email_notification_cooldowns`

Supported token formats:

- `u1.<base64url(json)>` for unsigned development/testing
- `v1.<base64url(json)>.<hex_hmac>` for signed tokens using `UNSUB_SIGNING_SECRET`

The `/ui` dashboard now includes:

- `Unsubscribe events` tab for review workflow
- `Generate token` tab for one-off footer links and a history table of generated tokens
- `Email` tab for SendPulse-powered unsubscribe click notifications

## Email Notifications

This Worker now supports unsubscribe-click alert emails through SendPulse.

- Preferred auth: static `SENDPULSE_API_KEY` Worker secret.
- Alternate auth: `SENDPULSE_CLIENT_ID` and `SENDPULSE_CLIENT_SECRET` Worker secrets.
- Notifications only send when the `Email` tab is enabled and both a recipient and sender address are saved.
- The first click for a recipient sends immediately, then repeat clicks for that same email are rate-limited by the configured cooldown window.
- Every click is still written to `unsubscribe_events`, and the UI shows repeat counts even when extra alert emails are suppressed.
- The sender address entered in the UI must already be approved in SendPulse.
- Your SendPulse SMTP/API profile must be approved before SendPulse will actually send.

Suggested payload shape:

```json
{
  "token_id": "abc123",
  "email": "person@example.com",
  "scope_type": "global",
  "scope_key": "",
  "source": "campaign-name",
  "method": "body_link"
}
```

This repo is intentionally small. The next build step is to add:

1. RFC 8058 one-click unsubscribe token handling
2. stronger admin authentication via Cloudflare Access
3. sender/list scoping rules
4. delivery-time suppression checks from calling services

## Admin Access

If you set a Worker secret named `ADMIN_API_TOKEN`, the admin API routes require:

- `Authorization: Bearer <token>`, or
- a valid `CF-Access-Authenticated-User-Email` header from Cloudflare Access

The built-in UI at `/ui` includes a token field and stores it in local browser storage for same-origin admin API calls.

## Local Commands

```bash
npm install
npm run dev
wrangler d1 migrations apply unsub_db --local
```
