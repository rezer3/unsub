function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...headers,
    },
  });
}

function html(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      ...headers,
    },
  });
}

function redirect(location, status = 302) {
  return new Response(null, {
    status,
    headers: {
      location,
      "cache-control": "no-store",
    },
  });
}

function nowIso() {
  return new Date().toISOString();
}

function isTruthy(value) {
  return ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());
}

function cleanText(value, max = 500) {
  const text = String(value ?? "").trim();
  if (!text) return "";
  return text.slice(0, max);
}

function normalizeEmail(value) {
  return cleanText(value, 320).toLowerCase();
}

function getBearerToken(request) {
  const header = cleanText(request.headers.get("Authorization") || "", 2000);
  if (!header.toLowerCase().startsWith("bearer ")) return "";
  return cleanText(header.slice(7), 1000);
}

async function d1Exec(db, sql, bindings = []) {
  const stmt = db.prepare(sql);
  const bound = bindings.length ? stmt.bind(...bindings) : stmt;
  return bound.run();
}

async function d1First(db, sql, bindings = []) {
  const stmt = db.prepare(sql);
  const bound = bindings.length ? stmt.bind(...bindings) : stmt;
  return bound.first();
}

async function d1All(db, sql, bindings = []) {
  const stmt = db.prepare(sql);
  const bound = bindings.length ? stmt.bind(...bindings) : stmt;
  return bound.all();
}

function toBase64(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function fromBase64(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function base64UrlEncodeUtf8(text) {
  const encoded = new TextEncoder().encode(text);
  return toBase64(encoded).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecodeUtf8(text) {
  const base64 = String(text || "")
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(String(text || "").length / 4) * 4, "=");
  return new TextDecoder().decode(fromBase64(base64));
}

async function hmacSha256Hex(secret, text) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text));
  return Array.from(new Uint8Array(signature))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function parseTokenClaims(env, token) {
  const value = cleanText(token, 4000);
  if (!value) throw new Error("missing_token");

  // Unsigned developer token: u1.<base64url(json)>
  if (value.startsWith("u1.")) {
    const payloadSegment = value.slice(3);
    const payloadText = base64UrlDecodeUtf8(payloadSegment);
    return {
      version: "u1",
      signed: false,
      payload: JSON.parse(payloadText),
      payloadText,
    };
  }

  // Signed token: v1.<base64url(json)>.<hex-hmac>
  if (value.startsWith("v1.")) {
    const parts = value.split(".");
    if (parts.length !== 3) throw new Error("invalid_signed_token");
    const [, payloadSegment, providedSig] = parts;
    const payloadText = base64UrlDecodeUtf8(payloadSegment);
    const secret = cleanText(env.UNSUB_SIGNING_SECRET || "", 500);
    if (!secret) throw new Error("missing_signing_secret");
    const expectedSig = await hmacSha256Hex(secret, payloadSegment);
    if (expectedSig !== providedSig) throw new Error("invalid_signature");
    return {
      version: "v1",
      signed: true,
      payload: JSON.parse(payloadText),
      payloadText,
    };
  }

  throw new Error("unsupported_token_version");
}

function eventStatusLabel(status) {
  const normalized = cleanText(status, 40).toLowerCase() || "received";
  if (["received", "reviewed", "suppressed", "ignored"].includes(normalized)) return normalized;
  return "received";
}

function deriveReviewer(request, body) {
  return (
    cleanText(body?.created_by, 200) ||
    cleanText(body?.reviewed_by, 200) ||
    cleanText(request.headers.get("CF-Access-Authenticated-User-Email") || "", 200) ||
    cleanText(request.headers.get("x-auth-request-email") || "", 200) ||
    "manual"
  );
}

function adminAuthorized(request, env) {
  const accessEmail = cleanText(request.headers.get("CF-Access-Authenticated-User-Email") || "", 200);
  if (accessEmail) return { ok: true, identity: accessEmail, mode: "cf_access" };

  const expectedToken = cleanText(env.ADMIN_API_TOKEN || "", 1000);
  if (!expectedToken) return { ok: true, identity: "open", mode: "open" };

  const providedToken =
    getBearerToken(request) ||
    cleanText(request.headers.get("x-admin-token") || "", 1000);
  if (providedToken && providedToken === expectedToken) {
    return { ok: true, identity: "token", mode: "token" };
  }

  return { ok: false };
}

function buildScopeLabel(event) {
  const scopeType = cleanText(event?.scope_type, 80) || "global";
  const scopeKey = cleanText(event?.scope_key, 200);
  return scopeKey ? `${scopeType}:${scopeKey}` : scopeType;
}

async function buildTokenValue(env, payload) {
  const payloadText = JSON.stringify(payload);
  const payloadSegment = base64UrlEncodeUtf8(payloadText);
  const secret = cleanText(env.UNSUB_SIGNING_SECRET || "", 500);

  if (secret) {
    const signature = await hmacSha256Hex(secret, payloadSegment);
    return {
      token: `v1.${payloadSegment}.${signature}`,
      token_version: "v1",
      signed: true,
      payload_text: payloadText,
    };
  }

  return {
    token: `u1.${payloadSegment}`,
    token_version: "u1",
    signed: false,
    payload_text: payloadText,
  };
}

async function createManualToken(request, env, input = {}) {
  const email = cleanText(input.email, 320);
  const emailNormalized = normalizeEmail(email);
  if (!emailNormalized) throw new Error("missing_email");

  const createdAt = nowIso();
  const scopeType = cleanText(input.scope_type, 80) || "global";
  const scopeKey = cleanText(input.scope_key, 200);
  const createdBy = deriveReviewer(request, input);
  const tokenId = cleanText(input.token_id, 120) || crypto.randomUUID();
  const payload = {
    email,
    scope_type: scopeType,
    scope_key: scopeKey,
    source: cleanText(input.source, 120) || "manual_ui",
    method: cleanText(input.method, 80) || "body_link_manual",
    token_id: tokenId,
    issued_at: createdAt,
  };
  const encoded = await buildTokenValue(env, payload);
  const origin = cleanText(env.PUBLIC_BASE_URL || "", 500) || new URL(request.url).origin;
  const tokenUrl = `${origin}/u/${encoded.token}`;

  const row = {
    id: crypto.randomUUID(),
    created_at: createdAt,
    created_by: createdBy,
    email,
    email_normalized: emailNormalized,
    scope_type: scopeType,
    scope_key: scopeKey,
    source: cleanText(payload.source, 120) || "manual_ui",
    method: cleanText(payload.method, 80) || "body_link_manual",
    token_id: tokenId,
    token_version: encoded.token_version,
    signed: encoded.signed ? 1 : 0,
    token_value: encoded.token,
    token_url: tokenUrl,
    payload_json: JSON.stringify(payload),
    notes: cleanText(input.notes, 2000) || null,
  };

  await d1Exec(
    env.UNSUB_DB,
    `INSERT INTO manual_unsubscribe_tokens
     (id, created_at, created_by, email, email_normalized, scope_type, scope_key, source, method, token_id, token_version, signed, token_value, token_url, payload_json, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      row.id,
      row.created_at,
      row.created_by,
      row.email,
      row.email_normalized,
      row.scope_type,
      row.scope_key,
      row.source,
      row.method,
      row.token_id,
      row.token_version,
      row.signed,
      row.token_value,
      row.token_url,
      row.payload_json,
      row.notes,
    ]
  );

  return {
    ...row,
    signed: !!row.signed,
    scope_label: buildScopeLabel(row),
  };
}

async function listManualTokens(env, url) {
  const limitRaw = Number(url.searchParams.get("limit") || 100);
  const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 250) : 100;

  const res = await d1All(
    env.UNSUB_DB,
    `SELECT id, created_at, created_by, email, email_normalized, scope_type, scope_key, source,
            method, token_id, token_version, signed, token_url, notes
     FROM manual_unsubscribe_tokens
     ORDER BY created_at DESC
     LIMIT ?`,
    [limit]
  );

  const rows = Array.isArray(res?.results) ? res.results : [];
  return rows.map((row) => ({
    ...row,
    signed: Number(row.signed) === 1,
    scope_label: buildScopeLabel(row),
  }));
}

async function recordUnsubscribeEvent(env, request, claims, options = {}) {
  const payload = claims?.payload || {};
  const email = cleanText(payload.email, 320);
  const emailNormalized = normalizeEmail(email);
  if (!emailNormalized) throw new Error("token_missing_email");

  const ts = nowIso();
  const event = {
    id: crypto.randomUUID(),
    created_at: ts,
    email,
    email_normalized: emailNormalized,
    scope_type: cleanText(payload.scope_type, 80) || "global",
    scope_key: cleanText(payload.scope_key, 200),
    method: cleanText(options.method || payload.method, 80) || "link",
    source: cleanText(payload.source, 120) || "body_link",
    event_type: cleanText(options.event_type, 80) || "unsubscribe_requested",
    token_id: cleanText(payload.token_id, 120) || cleanText(payload.message_id, 120),
    ip_address: cleanText(request.headers.get("CF-Connecting-IP") || "", 120),
    user_agent: cleanText(request.headers.get("User-Agent") || "", 2000),
    payload_json: JSON.stringify(payload),
    status: eventStatusLabel(options.status || "received"),
    reviewed_at: options.reviewed_at || null,
    reviewed_by: cleanText(options.reviewed_by, 200) || null,
    notes: cleanText(options.notes, 2000) || null,
  };

  await d1Exec(
    env.UNSUB_DB,
    `INSERT INTO unsubscribe_events
     (id, created_at, email, email_normalized, scope_type, scope_key, method, source, event_type, token_id, ip_address, user_agent, payload_json, status, reviewed_at, reviewed_by, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      event.id,
      event.created_at,
      event.email,
      event.email_normalized,
      event.scope_type,
      event.scope_key,
      event.method,
      event.source,
      event.event_type,
      event.token_id,
      event.ip_address,
      event.user_agent,
      event.payload_json,
      event.status,
      event.reviewed_at,
      event.reviewed_by,
      event.notes,
    ]
  );

  return event;
}

async function upsertSuppression(env, input) {
  const email = cleanText(input.email, 320);
  const emailNormalized = normalizeEmail(email);
  if (!emailNormalized) throw new Error("missing_email");

  const ts = nowIso();
  const id = cleanText(input.id, 120) || crypto.randomUUID();
  const channel = cleanText(input.channel, 40) || "email";
  const scopeType = cleanText(input.scope_type, 80) || "global";
  const scopeKey = cleanText(input.scope_key, 200);
  const source = cleanText(input.source, 120) || "admin";
  const method = cleanText(input.method, 80) || "manual";
  const reason = cleanText(input.reason, 500) || null;
  const notes = cleanText(input.notes, 2000) || null;
  const metadataJson = JSON.stringify(input.metadata || {});

  await d1Exec(
    env.UNSUB_DB,
    `INSERT INTO email_suppressions
     (id, created_at, updated_at, channel, email, email_normalized, scope_type, scope_key, source, method, reason, notes, metadata_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(channel, email_normalized, scope_type, scope_key)
     DO UPDATE SET
       updated_at = excluded.updated_at,
       source = excluded.source,
       method = excluded.method,
       reason = excluded.reason,
       notes = excluded.notes,
       metadata_json = excluded.metadata_json`,
    [
      id,
      ts,
      ts,
      channel,
      email,
      emailNormalized,
      scopeType,
      scopeKey,
      source,
      method,
      reason,
      notes,
      metadataJson,
    ]
  );

  return {
    id,
    email,
    email_normalized: emailNormalized,
    scope_type: scopeType,
    scope_key: scopeKey,
    source,
    method,
    reason,
    notes,
    updated_at: ts,
  };
}

async function maybeAutoSuppress(env, request, event, claims) {
  if (!isTruthy(env.AUTO_SUPPRESS_UNSUB)) return null;

  const payload = claims?.payload || {};
  const suppression = await upsertSuppression(env, {
    email: event.email,
    scope_type: event.scope_type,
    scope_key: event.scope_key,
    source: cleanText(payload.source, 120) || "unsubscribe_endpoint",
    method: cleanText(payload.method, 80) || cleanText(event.method, 80) || "one_click",
    reason: "Auto-suppressed from unsubscribe endpoint",
    notes: cleanText(payload.notes, 2000),
    metadata: {
      event_id: event.id,
      token_id: event.token_id,
      ip_address: cleanText(request.headers.get("CF-Connecting-IP") || "", 120),
    },
  });

  await d1Exec(
    env.UNSUB_DB,
    `UPDATE unsubscribe_events
     SET status = 'suppressed', reviewed_at = ?, reviewed_by = ?, notes = COALESCE(notes, ?)
     WHERE id = ?`,
    [nowIso(), "auto", "Auto-suppressed by endpoint", event.id]
  );

  return suppression;
}

async function listAdminEvents(env, url) {
  const limitRaw = Number(url.searchParams.get("limit") || 100);
  const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 250) : 100;
  const status = cleanText(url.searchParams.get("status"), 40).toLowerCase();
  const email = normalizeEmail(url.searchParams.get("email"));

  const where = [];
  const bindings = [];

  if (status) {
    where.push("status = ?");
    bindings.push(status);
  }
  if (email) {
    where.push("email_normalized = ?");
    bindings.push(email);
  }

  const res = await d1All(
    env.UNSUB_DB,
    `SELECT id, created_at, email, email_normalized, scope_type, scope_key, method, source,
            event_type, token_id, status, reviewed_at, reviewed_by, notes
     FROM unsubscribe_events
     ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
     ORDER BY created_at DESC
     LIMIT ?`,
    [...bindings, limit]
  );

  const rows = Array.isArray(res?.results) ? res.results : [];
  return rows.map((row) => ({
    ...row,
    status: eventStatusLabel(row.status),
    scope_label: buildScopeLabel(row),
  }));
}

async function handleGenerateToken(request, env) {
  const body = await request.json().catch(() => null);

  let tokenRow;
  try {
    tokenRow = await createManualToken(request, env, {
      email: body?.email,
      created_by: body?.created_by,
      notes: body?.notes,
      scope_type: body?.scope_type,
      scope_key: body?.scope_key,
    });
  } catch (error) {
    return json({ ok: false, error: cleanText(error?.message, 200) || "token_generation_failed" }, 400);
  }

  return json({
    ok: true,
    token: tokenRow,
    signing_secret_configured: !!cleanText(env.UNSUB_SIGNING_SECRET || "", 500),
  });
}

async function handleMarkReviewed(request, env) {
  const body = await request.json().catch(() => null);
  const id = cleanText(body?.id, 120);
  if (!id) return json({ ok: false, error: "missing_id" }, 400);

  const existing = await d1First(env.UNSUB_DB, `SELECT * FROM unsubscribe_events WHERE id = ?`, [id]);
  if (!existing) return json({ ok: false, error: "event_not_found" }, 404);

  const reviewedAt = nowIso();
  const reviewedBy = deriveReviewer(request, body);
  const notes = cleanText(body?.notes, 2000) || cleanText(existing.notes, 2000) || null;

  await d1Exec(
    env.UNSUB_DB,
    `UPDATE unsubscribe_events
     SET status = 'reviewed', reviewed_at = ?, reviewed_by = ?, notes = ?
     WHERE id = ?`,
    [reviewedAt, reviewedBy, notes, id]
  );

  return json({
    ok: true,
    id,
    status: "reviewed",
    reviewed_at: reviewedAt,
    reviewed_by: reviewedBy,
    notes,
  });
}

async function handleSuppress(request, env) {
  const body = await request.json().catch(() => null);
  const eventId = cleanText(body?.id || body?.event_id, 120);
  let event = null;

  if (eventId) {
    event = await d1First(env.UNSUB_DB, `SELECT * FROM unsubscribe_events WHERE id = ?`, [eventId]);
    if (!event) return json({ ok: false, error: "event_not_found" }, 404);
  }

  const suppression = await upsertSuppression(env, {
    email: cleanText(body?.email, 320) || cleanText(event?.email, 320),
    scope_type: cleanText(body?.scope_type, 80) || cleanText(event?.scope_type, 80) || "global",
    scope_key: cleanText(body?.scope_key, 200) || cleanText(event?.scope_key, 200),
    source: cleanText(body?.source, 120) || "admin",
    method: cleanText(body?.method, 80) || cleanText(event?.method, 80) || "manual",
    reason: cleanText(body?.reason, 500) || "Manual suppression",
    notes: cleanText(body?.notes, 2000) || cleanText(event?.notes, 2000),
    metadata: {
      event_id: eventId || null,
      reviewed_by: deriveReviewer(request, body),
    },
  });

  if (eventId) {
    await d1Exec(
      env.UNSUB_DB,
      `UPDATE unsubscribe_events
       SET status = 'suppressed', reviewed_at = ?, reviewed_by = ?, notes = ?
       WHERE id = ?`,
      [nowIso(), deriveReviewer(request, body), suppression.notes, eventId]
    );
  }

  return json({ ok: true, suppression, event_id: eventId || null });
}

function successPage({ email, autoSuppressed }) {
  const actionText = autoSuppressed
    ? "Your unsubscribe request has been processed."
    : "Your unsubscribe request has been received.";
  const detailText = autoSuppressed
    ? "You have been added to the suppression list for this token scope."
    : "No automatic suppression is enabled yet. This request is now visible in the dashboard for review.";

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Unsubscribe Request</title>
    <style>
      :root {
        color-scheme: light;
        --bg: #f5f1e8;
        --panel: #fffaf0;
        --ink: #1f1d1a;
        --muted: #6a6254;
        --accent: #a23b2a;
        --border: #d8ccb4;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100vh;
        font-family: Georgia, "Times New Roman", serif;
        background:
          radial-gradient(circle at top left, rgba(162, 59, 42, 0.14), transparent 28rem),
          linear-gradient(180deg, #f2ecdf 0%, var(--bg) 100%);
        color: var(--ink);
        display: grid;
        place-items: center;
        padding: 2rem;
      }
      .card {
        width: min(42rem, 100%);
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 20px;
        padding: 2rem;
        box-shadow: 0 24px 70px rgba(74, 58, 34, 0.14);
      }
      h1 {
        margin: 0 0 1rem;
        font-size: clamp(2rem, 4vw, 3rem);
        line-height: 1.05;
      }
      p {
        margin: 0 0 1rem;
        font-size: 1.05rem;
        line-height: 1.6;
        color: var(--muted);
      }
      .email {
        display: inline-block;
        margin-top: 0.25rem;
        padding: 0.5rem 0.75rem;
        border-radius: 999px;
        background: rgba(162, 59, 42, 0.08);
        color: var(--accent);
        font-weight: 700;
      }
    </style>
  </head>
  <body>
    <main class="card">
      <h1>${actionText}</h1>
      <p>${detailText}</p>
      ${email ? `<p class="email">${email}</p>` : ""}
    </main>
  </body>
</html>`;
}

function errorPage(title, message, status = 400) {
  return html(
    `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${title}</title>
    <style>
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        padding: 2rem;
        background: #111;
        color: #f6f2ea;
        font-family: Georgia, "Times New Roman", serif;
      }
      main { width: min(36rem, 100%); }
      h1 { margin: 0 0 1rem; font-size: 2rem; }
      p { margin: 0; line-height: 1.6; color: #d5cab8; }
    </style>
  </head>
  <body>
    <main>
      <h1>${title}</h1>
      <p>${message}</p>
    </main>
  </body>
</html>`,
    status
  );
}

function adminUiPage(env) {
  const uiConfig = JSON.stringify({
    autoSuppress: isTruthy(env.AUTO_SUPPRESS_UNSUB),
    signingSecretConfigured: !!cleanText(env.UNSUB_SIGNING_SECRET || "", 500),
  });

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Unsubscribe Console</title>
    <style>
      :root {
        color-scheme: light;
        --bg: #f7f3ea;
        --panel: #fffdf8;
        --ink: #1d1a16;
        --muted: #6f6658;
        --accent: #9f412e;
        --accent-2: #2f6c64;
        --accent-3: #27465b;
        --border: #dbcdb4;
        --shadow: rgba(53, 42, 24, 0.12);
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: Georgia, "Times New Roman", serif;
        background:
          radial-gradient(circle at top left, rgba(159, 65, 46, 0.12), transparent 24rem),
          linear-gradient(180deg, #efe7d7 0%, var(--bg) 100%);
        color: var(--ink);
      }
      .wrap {
        width: min(1200px, calc(100% - 2rem));
        margin: 2rem auto 4rem;
      }
      .hero,
      .panel-shell,
      .table-shell,
      .result-card {
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 24px;
        box-shadow: 0 18px 50px var(--shadow);
      }
      .hero {
        padding: 1.5rem;
      }
      .panel-shell {
        margin-top: 1.2rem;
        padding: 1.3rem;
      }
      h1 {
        margin: 0;
        font-size: clamp(2rem, 4vw, 3.2rem);
        line-height: 1.02;
      }
      .sub {
        margin: 0.8rem 0 0;
        color: var(--muted);
        font-size: 1.02rem;
        line-height: 1.55;
      }
      .admin-grid,
      .toolbar {
        display: grid;
        gap: 0.85rem;
        margin-top: 1.2rem;
      }
      .admin-grid {
        grid-template-columns: 1fr 1fr;
      }
      .toolbar.events-toolbar {
        grid-template-columns: 1.2fr 0.9fr 0.8fr auto;
      }
      .toolbar.generator-toolbar {
        grid-template-columns: 1.35fr auto;
      }
      input, select, button, a.button-link {
        font: inherit;
      }
      input, select {
        width: 100%;
        border: 1px solid var(--border);
        background: #fff;
        border-radius: 14px;
        padding: 0.8rem 0.9rem;
        color: var(--ink);
      }
      button,
      a.button-link {
        border: 0;
        border-radius: 14px;
        padding: 0.8rem 1rem;
        cursor: pointer;
        background: var(--accent);
        color: #fff8f2;
        font-weight: 700;
        text-decoration: none;
        display: inline-flex;
        align-items: center;
        justify-content: center;
      }
      button.secondary,
      a.button-link.secondary {
        background: var(--accent-2);
      }
      button.ghost,
      a.button-link.ghost {
        background: rgba(39, 70, 91, 0.1);
        color: var(--accent-3);
      }
      .tabs {
        display: inline-flex;
        gap: 0.55rem;
        margin-top: 1.25rem;
        padding: 0.35rem;
        border-radius: 18px;
        background: rgba(29, 26, 22, 0.05);
      }
      .tab {
        background: transparent;
        color: var(--muted);
        padding: 0.75rem 1rem;
      }
      .tab.is-active {
        background: var(--panel);
        color: var(--ink);
        box-shadow: inset 0 0 0 1px rgba(219, 205, 180, 0.9);
      }
      .panel-shell[hidden] {
        display: none;
      }
      .statusbar {
        display: flex;
        justify-content: space-between;
        gap: 1rem;
        align-items: center;
        margin: 1rem 0 0;
        color: var(--muted);
        font-size: 0.98rem;
      }
      .notice {
        border-radius: 18px;
        padding: 0.95rem 1rem;
        margin-bottom: 1rem;
        line-height: 1.5;
      }
      .notice.warn {
        background: rgba(159, 65, 46, 0.08);
        color: var(--accent);
      }
      .notice.ok {
        background: rgba(47, 108, 100, 0.1);
        color: var(--accent-2);
      }
      .table-shell {
        margin-top: 1.1rem;
        overflow: hidden;
      }
      table {
        width: 100%;
        border-collapse: collapse;
      }
      th, td {
        padding: 0.95rem 1rem;
        border-bottom: 1px solid rgba(219, 205, 180, 0.7);
        vertical-align: top;
        text-align: left;
      }
      th {
        background: rgba(159, 65, 46, 0.06);
        font-size: 0.88rem;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        color: var(--muted);
      }
      tr:last-child td { border-bottom: 0; }
      .tag {
        display: inline-flex;
        align-items: center;
        gap: 0.35rem;
        padding: 0.25rem 0.55rem;
        border-radius: 999px;
        background: rgba(47, 108, 100, 0.09);
        color: var(--accent-2);
        font-size: 0.82rem;
        font-weight: 700;
      }
      .tag.received,
      .tag.unsigned {
        background: rgba(159, 65, 46, 0.1);
        color: var(--accent);
      }
      .tag.reviewed,
      .tag.signed {
        background: rgba(47, 108, 100, 0.1);
        color: var(--accent-2);
      }
      .tag.suppressed {
        background: rgba(29, 26, 22, 0.09);
        color: #1d1a16;
      }
      .tag.ignored {
        background: rgba(111, 102, 88, 0.14);
        color: #5a5044;
      }
      .actions {
        display: flex;
        gap: 0.5rem;
        flex-wrap: wrap;
      }
      .actions button,
      .actions a.button-link {
        padding: 0.55rem 0.7rem;
        font-size: 0.88rem;
      }
      .muted {
        color: var(--muted);
        font-size: 0.9rem;
      }
      .mono {
        font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
        word-break: break-all;
      }
      .result-card {
        margin-top: 1rem;
        padding: 1rem;
      }
      .result-head {
        display: flex;
        justify-content: space-between;
        gap: 1rem;
        align-items: center;
      }
      .link-box {
        margin-top: 0.85rem;
        padding: 0.9rem 1rem;
        border-radius: 18px;
        background: rgba(39, 70, 91, 0.06);
      }
      .link-cell a {
        color: var(--accent-3);
      }
      @media (max-width: 980px) {
        .admin-grid,
        .toolbar.events-toolbar,
        .toolbar.generator-toolbar {
          grid-template-columns: 1fr;
        }
        .table-shell {
          overflow-x: auto;
        }
        table {
          min-width: 980px;
        }
      }
    </style>
  </head>
  <body>
    <div class="wrap">
      <section class="hero">
        <h1>Unsubscribe Console</h1>
        <p class="sub">
          Event-only mode is active. Requests are logged here and are not automatically enforced unless the Worker is configured to auto-suppress.
          Use <code>/u/:token</code> for body-link clicks and <code>POST /api/unsubscribe/:token</code> for endpoint testing.
        </p>
        <div class="admin-grid">
          <input id="reviewer" type="text" placeholder="Operator name or email" />
          <input id="adminToken" type="password" placeholder="Admin token if ADMIN_API_TOKEN is set" />
        </div>
        <div class="tabs" role="tablist" aria-label="Unsubscribe admin tabs">
          <button id="tab-events" class="tab is-active" type="button" data-tab-target="events" role="tab" aria-controls="panel-events" aria-selected="true">Unsubscribe events</button>
          <button id="tab-generate" class="tab" type="button" data-tab-target="generate" role="tab" aria-controls="panel-generate" aria-selected="false">Generate token</button>
        </div>
      </section>

      <section id="panel-events" class="panel-shell" data-panel="events" role="tabpanel" aria-labelledby="tab-events">
        <div class="toolbar events-toolbar">
          <input id="emailFilter" type="text" placeholder="Filter by email" />
          <select id="statusFilter">
            <option value="">All statuses</option>
            <option value="received">Received</option>
            <option value="reviewed">Reviewed</option>
            <option value="suppressed">Suppressed</option>
            <option value="ignored">Ignored</option>
          </select>
          <div class="muted" style="display:flex;align-items:center;padding:0 0.2rem;">
            Auto suppress: <strong style="margin-left:0.35rem;">${isTruthy(env.AUTO_SUPPRESS_UNSUB) ? "On" : "Off"}</strong>
          </div>
          <button id="refreshBtn" type="button">Refresh</button>
        </div>
        <div class="statusbar">
          <div id="eventsSummary">Loading…</div>
          <div id="eventsLastUpdated"></div>
        </div>
        <section class="table-shell">
          <table>
            <thead>
              <tr>
                <th>Email</th>
                <th>Timestamp</th>
                <th>Scope</th>
                <th>Method</th>
                <th>Source</th>
                <th>Current Status</th>
                <th>Review</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="eventsBody">
              <tr><td colspan="8" class="muted">Loading events…</td></tr>
            </tbody>
          </table>
        </section>
      </section>

      <section id="panel-generate" class="panel-shell" data-panel="generate" role="tabpanel" aria-labelledby="tab-generate" hidden>
        <div id="generatorNotice" class="notice"></div>
        <div class="toolbar generator-toolbar">
          <input id="generateEmail" type="email" placeholder="recipient@example.com" />
          <button id="generateBtn" type="button">Generate token</button>
        </div>
        <section id="generatedResult" class="result-card" hidden></section>
        <div class="statusbar">
          <div id="tokensSummary">Loading…</div>
          <div id="tokensLastUpdated"></div>
        </div>
        <section class="table-shell">
          <table>
            <thead>
              <tr>
                <th>Email</th>
                <th>Generated</th>
                <th>Scope</th>
                <th>Type</th>
                <th>Link</th>
                <th>Generated By</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="generatedTokensBody">
              <tr><td colspan="7" class="muted">Loading generated tokens…</td></tr>
            </tbody>
          </table>
        </section>
      </section>
    </div>

    <script>
      const uiConfig = ${uiConfig};
      const state = {
        activeTab: "events",
        events: [],
        manualTokens: [],
        latestGenerated: null,
      };

      const reviewerInput = document.getElementById("reviewer");
      const adminTokenInput = document.getElementById("adminToken");
      const emailFilterInput = document.getElementById("emailFilter");
      const statusFilterSelect = document.getElementById("statusFilter");
      const refreshBtn = document.getElementById("refreshBtn");
      const eventsBody = document.getElementById("eventsBody");
      const eventsSummary = document.getElementById("eventsSummary");
      const eventsLastUpdated = document.getElementById("eventsLastUpdated");
      const generatorNotice = document.getElementById("generatorNotice");
      const generateEmailInput = document.getElementById("generateEmail");
      const generateBtn = document.getElementById("generateBtn");
      const generatedResult = document.getElementById("generatedResult");
      const generatedTokensBody = document.getElementById("generatedTokensBody");
      const tokensSummary = document.getElementById("tokensSummary");
      const tokensLastUpdated = document.getElementById("tokensLastUpdated");
      const tabButtons = Array.from(document.querySelectorAll("[data-tab-target]"));
      const panels = Array.from(document.querySelectorAll("[data-panel]"));

      reviewerInput.value = window.localStorage.getItem("unsub_operator_name") || "";
      adminTokenInput.value = window.localStorage.getItem("unsub_admin_token") || "";

      reviewerInput.addEventListener("change", () => {
        window.localStorage.setItem("unsub_operator_name", reviewerInput.value.trim());
      });
      adminTokenInput.addEventListener("change", () => {
        window.localStorage.setItem("unsub_admin_token", adminTokenInput.value.trim());
      });

      function escapeHtml(value) {
        return String(value ?? "")
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#39;");
      }

      function formatTimestamp(value) {
        if (!value) return "";
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return value;
        return new Intl.DateTimeFormat(undefined, {
          year: "numeric",
          month: "short",
          day: "numeric",
          hour: "numeric",
          minute: "2-digit",
        }).format(date);
      }

      function tabNameFromHash(hash) {
        return hash === "#generate-token" ? "generate" : "events";
      }

      function tabHashFor(name) {
        return name === "generate" ? "#generate-token" : "#unsubscribe-events";
      }

      function setActiveTab(name, options = {}) {
        state.activeTab = name === "generate" ? "generate" : "events";
        tabButtons.forEach((button) => {
          const active = button.getAttribute("data-tab-target") === state.activeTab;
          button.classList.toggle("is-active", active);
          button.setAttribute("aria-selected", active ? "true" : "false");
        });
        panels.forEach((panel) => {
          panel.hidden = panel.getAttribute("data-panel") !== state.activeTab;
        });
        if (!options.skipHash) {
          const nextHash = tabHashFor(state.activeTab);
          if (window.location.hash !== nextHash) {
            window.history.replaceState(null, "", nextHash);
          }
        }
      }

      function authHeaders(extra = {}) {
        const headers = { accept: "application/json", ...extra };
        const adminToken = adminTokenInput.value.trim();
        if (adminToken) headers.authorization = "Bearer " + adminToken;
        return headers;
      }

      async function fetchJson(url) {
        const res = await fetch(url, { headers: authHeaders() });
        const data = await res.json();
        if (!res.ok || !data.ok) {
          throw new Error(data.error || "request_failed");
        }
        return data;
      }

      async function postJson(url, body) {
        const res = await fetch(url, {
          method: "POST",
          headers: authHeaders({ "content-type": "application/json" }),
          body: JSON.stringify(body || {}),
        });
        const data = await res.json();
        if (!res.ok || !data.ok) {
          throw new Error(data.error || "request_failed");
        }
        return data;
      }

      async function copyText(value) {
        if (!value) return;
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(value);
          return;
        }
        window.prompt("Copy this link:", value);
      }

      function renderGeneratorNotice() {
        if (uiConfig.signingSecretConfigured) {
          generatorNotice.className = "notice ok";
          generatorNotice.innerHTML = "Signed token mode is active. Generated links are ready to use in the Gmail footer.";
          return;
        }

        generatorNotice.className = "notice warn";
        generatorNotice.innerHTML = "No <code>UNSUB_SIGNING_SECRET</code> is set yet. Generated links will use unsigned developer tokens for now.";
      }

      function renderEvents() {
        if (!state.events.length) {
          eventsBody.innerHTML = '<tr><td colspan="8" class="muted">No unsubscribe events yet.</td></tr>';
          eventsSummary.textContent = "0 events";
          return;
        }

        eventsBody.innerHTML = state.events.map((event) => {
          const reviewBits = [];
          if (event.reviewed_by) reviewBits.push("by " + escapeHtml(event.reviewed_by));
          if (event.reviewed_at) reviewBits.push(formatTimestamp(event.reviewed_at));
          if (event.notes) reviewBits.push(escapeHtml(event.notes));

          return \`
            <tr>
              <td><strong>\${escapeHtml(event.email || "")}</strong><div class="muted">\${escapeHtml(event.token_id || "")}</div></td>
              <td>\${escapeHtml(formatTimestamp(event.created_at))}</td>
              <td>\${escapeHtml(event.scope_label || event.scope_type || "global")}</td>
              <td>\${escapeHtml(event.method || "")}</td>
              <td>\${escapeHtml(event.source || "")}</td>
              <td><span class="tag \${escapeHtml(event.status || "received")}">\${escapeHtml(event.status || "received")}</span></td>
              <td><div class="muted">\${reviewBits.join("<br />") || "Unreviewed"}</div></td>
              <td>
                <div class="actions">
                  <button type="button" data-event-action="review" data-id="\${escapeHtml(event.id)}" class="secondary">Mark Reviewed</button>
                  <button type="button" data-event-action="suppress" data-id="\${escapeHtml(event.id)}">Suppress</button>
                </div>
              </td>
            </tr>
          \`;
        }).join("");

        eventsSummary.textContent = state.events.length + " event" + (state.events.length === 1 ? "" : "s");
      }

      function renderLatestGenerated() {
        if (!state.latestGenerated) {
          generatedResult.hidden = true;
          generatedResult.innerHTML = "";
          return;
        }

        const token = state.latestGenerated;
        const typeClass = token.signed ? "signed" : "unsigned";
        const typeLabel = token.signed ? "Signed link" : "Unsigned link";

        generatedResult.hidden = false;
        generatedResult.innerHTML = \`
          <div class="result-head">
            <span class="tag \${typeClass}">\${typeLabel}</span>
            <span class="muted">\${escapeHtml(formatTimestamp(token.created_at))}</span>
          </div>
          <p class="muted" style="margin:0.9rem 0 0;">Use this full link in the email footer for <strong>\${escapeHtml(token.email || "")}</strong>.</p>
          <div class="link-box mono"><a href="\${escapeHtml(token.token_url || "")}" target="_blank" rel="noreferrer">\${escapeHtml(token.token_url || "")}</a></div>
          <div class="actions" style="margin-top:0.85rem;">
            <button type="button" class="secondary" data-copy-url="\${escapeHtml(token.token_url || "")}">Copy link</button>
            <a class="button-link ghost" href="\${escapeHtml(token.token_url || "")}" target="_blank" rel="noreferrer">Open</a>
          </div>
        \`;
      }

      function renderManualTokens() {
        if (!state.manualTokens.length) {
          generatedTokensBody.innerHTML = '<tr><td colspan="7" class="muted">No manual tokens generated yet.</td></tr>';
          tokensSummary.textContent = "0 tokens";
          return;
        }

        generatedTokensBody.innerHTML = state.manualTokens.map((token) => {
          const typeClass = token.signed ? "signed" : "unsigned";
          const typeLabel = token.signed ? "Signed" : "Unsigned";
          return \`
            <tr>
              <td><strong>\${escapeHtml(token.email || "")}</strong><div class="muted">\${escapeHtml(token.token_id || "")}</div></td>
              <td>\${escapeHtml(formatTimestamp(token.created_at))}</td>
              <td>\${escapeHtml(token.scope_label || token.scope_type || "global")}</td>
              <td><span class="tag \${typeClass}">\${typeLabel}</span><div class="muted">\${escapeHtml(token.token_version || "")}</div></td>
              <td class="link-cell"><a class="mono" href="\${escapeHtml(token.token_url || "")}" target="_blank" rel="noreferrer">\${escapeHtml(token.token_url || "")}</a></td>
              <td>\${escapeHtml(token.created_by || "manual")}</td>
              <td>
                <div class="actions">
                  <button type="button" class="secondary" data-copy-url="\${escapeHtml(token.token_url || "")}">Copy link</button>
                </div>
              </td>
            </tr>
          \`;
        }).join("");

        tokensSummary.textContent = state.manualTokens.length + " token" + (state.manualTokens.length === 1 ? "" : "s");
      }

      async function loadEvents() {
        const params = new URLSearchParams();
        params.set("limit", "150");
        if (statusFilterSelect.value) params.set("status", statusFilterSelect.value);
        if (emailFilterInput.value.trim()) params.set("email", emailFilterInput.value.trim());

        const data = await fetchJson("/api/admin/events?" + params.toString());
        state.events = Array.isArray(data.events) ? data.events : [];
        renderEvents();
        eventsLastUpdated.textContent = "Updated " + formatTimestamp(new Date().toISOString());
      }

      async function loadManualTokens() {
        const data = await fetchJson("/api/admin/generated-tokens?limit=150");
        state.manualTokens = Array.isArray(data.tokens) ? data.tokens : [];
        renderManualTokens();
        tokensLastUpdated.textContent = "Updated " + formatTimestamp(new Date().toISOString());
      }

      async function generateToken() {
        const email = generateEmailInput.value.trim();
        if (!email) {
          window.alert("Enter an email address first.");
          return;
        }

        const data = await postJson("/api/admin/generate-token", {
          email,
          created_by: reviewerInput.value.trim(),
        });

        state.latestGenerated = data.token || null;
        if (typeof data.signing_secret_configured === "boolean") {
          uiConfig.signingSecretConfigured = data.signing_secret_configured;
        }
        renderGeneratorNotice();
        renderLatestGenerated();
        generateEmailInput.value = "";
        await loadManualTokens();
        setActiveTab("generate");
      }

      tabButtons.forEach((button) => {
        button.addEventListener("click", () => {
          setActiveTab(button.getAttribute("data-tab-target"));
        });
      });

      document.addEventListener("click", async (event) => {
        const copyButton = event.target.closest("button[data-copy-url]");
        if (copyButton) {
          try {
            await copyText(copyButton.getAttribute("data-copy-url"));
          } catch (error) {
            window.alert(String(error && error.message ? error.message : error));
          }
          return;
        }

        const actionButton = event.target.closest("button[data-event-action]");
        if (!actionButton) return;

        const action = actionButton.getAttribute("data-event-action");
        const id = actionButton.getAttribute("data-id");
        const reviewer = reviewerInput.value.trim();

        try {
          if (action === "review") {
            const notes = window.prompt("Optional review note:", "");
            await postJson("/api/admin/mark-reviewed", {
              id,
              reviewed_by: reviewer,
              notes: notes || "",
            });
          }

          if (action === "suppress") {
            const confirmed = window.confirm("Add this email to suppressions for the event scope?");
            if (!confirmed) return;
            const notes = window.prompt("Optional suppression note:", "");
            await postJson("/api/admin/suppress", {
              id,
              reviewed_by: reviewer,
              notes: notes || "",
            });
          }

          await loadEvents();
        } catch (error) {
          window.alert(String(error && error.message ? error.message : error));
        }
      });

      refreshBtn.addEventListener("click", () => {
        loadEvents().catch((error) => {
          window.alert(String(error && error.message ? error.message : error));
        });
      });

      generateBtn.addEventListener("click", () => {
        generateToken().catch((error) => {
          window.alert(String(error && error.message ? error.message : error));
        });
      });

      generateEmailInput.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          generateToken().catch(() => {});
        }
      });
      emailFilterInput.addEventListener("keydown", (event) => {
        if (event.key === "Enter") loadEvents().catch(() => {});
      });
      statusFilterSelect.addEventListener("change", () => loadEvents().catch(() => {}));
      window.addEventListener("hashchange", () => {
        setActiveTab(tabNameFromHash(window.location.hash), { skipHash: true });
      });

      renderGeneratorNotice();
      renderLatestGenerated();
      setActiveTab(tabNameFromHash(window.location.hash), { skipHash: true });

      loadEvents().catch((error) => {
        eventsBody.innerHTML = '<tr><td colspan="8" class="muted">' + escapeHtml(String(error && error.message ? error.message : error)) + '</td></tr>';
      });
      loadManualTokens().catch((error) => {
        generatedTokensBody.innerHTML = '<tr><td colspan="7" class="muted">' + escapeHtml(String(error && error.message ? error.message : error)) + '</td></tr>';
      });
      setInterval(() => {
        loadEvents().catch(() => {});
        loadManualTokens().catch(() => {});
      }, 30000);
    </script>
  </body>
</html>`;
}

async function handleUnsubscribeApi(request, env, token) {
  let claims;
  try {
    claims = await parseTokenClaims(env, token);
  } catch (error) {
    return json({ ok: false, error: cleanText(error?.message, 200) || "invalid_token" }, 400);
  }

  const bodyText = await request.text().catch(() => "");
  const event = await recordUnsubscribeEvent(env, request, claims, {
    method: "one_click_post",
    event_type: "unsubscribe_requested",
    notes: bodyText ? `body:${bodyText.slice(0, 500)}` : "",
  });
  const suppression = await maybeAutoSuppress(env, request, event, claims);

  return json({
    ok: true,
    event_id: event.id,
    status: suppression ? "suppressed" : "received",
    auto_suppressed: !!suppression,
  });
}

async function handleUnsubscribePage(request, env, token) {
  let claims;
  try {
    claims = await parseTokenClaims(env, token);
  } catch {
    return errorPage("Invalid unsubscribe link", "This link could not be verified. Generate a valid token before using this route.", 400);
  }

  const event = await recordUnsubscribeEvent(env, request, claims, {
    method: "body_link_get",
    event_type: "unsubscribe_requested",
  });
  const suppression = await maybeAutoSuppress(env, request, event, claims);

  return html(
    successPage({
      email: event.email,
      autoSuppressed: !!suppression,
    })
  );
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/") {
      return redirect("/ui");
    }

    if (request.method === "GET" && url.pathname === "/health") {
      let database = "unavailable";
      try {
        if (env.UNSUB_DB) {
          await env.UNSUB_DB.prepare("SELECT 1 AS ok").first();
          database = "ok";
        }
      } catch (error) {
        database = `error:${String(error?.message || error)}`;
      }

      return json({
        ok: database === "ok",
        service: "unsub",
        database,
        auto_suppress_unsub: isTruthy(env.AUTO_SUPPRESS_UNSUB),
        signing_secret_configured: !!cleanText(env.UNSUB_SIGNING_SECRET || "", 500),
      });
    }

    if (request.method === "GET" && (url.pathname === "/ui" || url.pathname === "/admin")) {
      return html(adminUiPage(env));
    }

    const unsubscribeApiMatch = url.pathname.match(/^\/api\/unsubscribe\/([^/]+)$/);
    if (unsubscribeApiMatch && request.method === "POST") {
      return handleUnsubscribeApi(request, env, unsubscribeApiMatch[1]);
    }

    const unsubscribePageMatch = url.pathname.match(/^\/u\/([^/]+)$/);
    if (unsubscribePageMatch && request.method === "GET") {
      return handleUnsubscribePage(request, env, unsubscribePageMatch[1]);
    }

    if (request.method === "GET" && url.pathname === "/api/admin/events") {
      const auth = adminAuthorized(request, env);
      if (!auth.ok) return json({ ok: false, error: "unauthorized" }, 401);
      const events = await listAdminEvents(env, url);
      return json({ ok: true, events });
    }

    if (request.method === "GET" && url.pathname === "/api/admin/generated-tokens") {
      const auth = adminAuthorized(request, env);
      if (!auth.ok) return json({ ok: false, error: "unauthorized" }, 401);
      const tokens = await listManualTokens(env, url);
      return json({ ok: true, tokens });
    }

    if (request.method === "POST" && url.pathname === "/api/admin/mark-reviewed") {
      const auth = adminAuthorized(request, env);
      if (!auth.ok) return json({ ok: false, error: "unauthorized" }, 401);
      return handleMarkReviewed(request, env);
    }

    if (request.method === "POST" && url.pathname === "/api/admin/generate-token") {
      const auth = adminAuthorized(request, env);
      if (!auth.ok) return json({ ok: false, error: "unauthorized" }, 401);
      return handleGenerateToken(request, env);
    }

    if (request.method === "POST" && url.pathname === "/api/admin/suppress") {
      const auth = adminAuthorized(request, env);
      if (!auth.ok) return json({ ok: false, error: "unauthorized" }, 401);
      return handleSuppress(request, env);
    }

    return json({ ok: false, error: "not_found" }, 404);
  },
};
