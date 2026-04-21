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
- `POST /api/admin/mark-reviewed` marks an event as reviewed
- `POST /api/admin/suppress` inserts a suppression entry and marks the event suppressed

The migrations create tables for:

- `email_suppressions`
- `unsubscribe_events`

Supported token formats:

- `u1.<base64url(json)>` for unsigned development/testing
- `v1.<base64url(json)>.<hex_hmac>` for signed tokens using `UNSUB_SIGNING_SECRET`

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
