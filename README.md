# unsub

Cloudflare Worker scaffold for shared email suppression and unsubscribe handling.

## Resources

- Worker: `unsub`
- D1: `unsub_db`
- Binding: `UNSUB_DB`

## Endpoints

- `GET /` returns a small service description
- `GET /health` returns a basic health payload

The initial migration creates tables for:

- `email_suppressions`
- `unsubscribe_events`

This repo is intentionally small. The next build step is to add:

1. RFC 8058 one-click unsubscribe token handling
2. admin-authenticated suppression CRUD
3. sender/list scoping rules
4. delivery-time suppression checks from calling services

## Local Commands

```bash
npm install
npm run dev
wrangler d1 migrations apply unsub_db --local
```
