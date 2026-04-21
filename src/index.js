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

function adminUiPage() {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Unsubscribe Events</title>
    <style>
      :root {
        color-scheme: light;
        --bg: #f7f3ea;
        --panel: #fffdf8;
        --ink: #1d1a16;
        --muted: #6f6658;
        --accent: #9f412e;
        --accent-2: #2f6c64;
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
      .hero {
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 24px;
        padding: 1.5rem 1.5rem 1.2rem;
        box-shadow: 0 18px 50px var(--shadow);
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
      .toolbar {
        display: grid;
        gap: 0.85rem;
        grid-template-columns: 1.2fr 0.9fr 0.8fr auto;
        margin-top: 1.35rem;
      }
      input, select, button {
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
      button {
        border: 0;
        border-radius: 14px;
        padding: 0.8rem 1rem;
        cursor: pointer;
        background: var(--accent);
        color: #fff8f2;
        font-weight: 700;
      }
      button.secondary {
        background: var(--accent-2);
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
      .table-shell {
        margin-top: 1.2rem;
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 24px;
        overflow: hidden;
        box-shadow: 0 18px 50px var(--shadow);
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
      .tag.received { background: rgba(159, 65, 46, 0.1); color: var(--accent); }
      .tag.reviewed { background: rgba(47, 108, 100, 0.1); color: var(--accent-2); }
      .tag.suppressed { background: rgba(29, 26, 22, 0.09); color: #1d1a16; }
      .tag.ignored { background: rgba(111, 102, 88, 0.14); color: #5a5044; }
      .actions {
        display: flex;
        gap: 0.5rem;
        flex-wrap: wrap;
      }
      .actions button {
        padding: 0.55rem 0.7rem;
        font-size: 0.88rem;
      }
      .muted {
        color: var(--muted);
        font-size: 0.9rem;
      }
      @media (max-width: 980px) {
        .toolbar {
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
        <h1>Unsubscribe Event Review</h1>
        <p class="sub">
          Event-only mode is active. Requests are logged here and are not automatically enforced unless the Worker is configured to auto-suppress.
          Use <code>/u/:token</code> for link clicks and <code>POST /api/unsubscribe/:token</code> for endpoint testing.
        </p>
        <div class="toolbar">
          <input id="reviewer" type="text" placeholder="Reviewer name or email" />
          <input id="emailFilter" type="text" placeholder="Filter by email" />
          <select id="statusFilter">
            <option value="">All statuses</option>
            <option value="received">Received</option>
            <option value="reviewed">Reviewed</option>
            <option value="suppressed">Suppressed</option>
            <option value="ignored">Ignored</option>
          </select>
          <button id="refreshBtn">Refresh</button>
        </div>
        <div class="toolbar" style="grid-template-columns: 1fr;">
          <input id="adminToken" type="password" placeholder="Admin token if ADMIN_API_TOKEN is set" />
        </div>
        <div class="statusbar">
          <div id="summary">Loading…</div>
          <div id="lastUpdated"></div>
        </div>
      </section>

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
    </div>

    <script>
      const state = {
        events: [],
      };

      const reviewerInput = document.getElementById("reviewer");
      const emailFilterInput = document.getElementById("emailFilter");
      const statusFilterSelect = document.getElementById("statusFilter");
      const adminTokenInput = document.getElementById("adminToken");
      const refreshBtn = document.getElementById("refreshBtn");
      const eventsBody = document.getElementById("eventsBody");
      const summary = document.getElementById("summary");
      const lastUpdated = document.getElementById("lastUpdated");
      adminTokenInput.value = window.localStorage.getItem("unsub_admin_token") || "";
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

      function renderEvents() {
        if (!state.events.length) {
          eventsBody.innerHTML = '<tr><td colspan="8" class="muted">No unsubscribe events yet.</td></tr>';
          summary.textContent = "0 events";
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
                  <button data-action="review" data-id="\${escapeHtml(event.id)}" class="secondary">Mark Reviewed</button>
                  <button data-action="suppress" data-id="\${escapeHtml(event.id)}">Suppress</button>
                </div>
              </td>
            </tr>
          \`;
        }).join("");

        summary.textContent = state.events.length + " event" + (state.events.length === 1 ? "" : "s");
      }

      async function loadEvents() {
        const params = new URLSearchParams();
        params.set("limit", "150");
        if (statusFilterSelect.value) params.set("status", statusFilterSelect.value);
        if (emailFilterInput.value.trim()) params.set("email", emailFilterInput.value.trim());
        const headers = { "accept": "application/json" };
        const adminToken = adminTokenInput.value.trim();
        if (adminToken) headers.authorization = "Bearer " + adminToken;

        const res = await fetch("/api/admin/events?" + params.toString(), {
          headers,
        });
        const data = await res.json();
        if (!res.ok || !data.ok) {
          throw new Error(data.error || "failed_to_load_events");
        }
        state.events = Array.isArray(data.events) ? data.events : [];
        renderEvents();
        lastUpdated.textContent = "Updated " + formatTimestamp(new Date().toISOString());
      }

      async function postJson(url, body) {
        const headers = {
          "content-type": "application/json",
          "accept": "application/json",
        };
        const adminToken = adminTokenInput.value.trim();
        if (adminToken) headers.authorization = "Bearer " + adminToken;
        const res = await fetch(url, {
          method: "POST",
          headers,
          body: JSON.stringify(body || {}),
        });
        const data = await res.json();
        if (!res.ok || !data.ok) {
          throw new Error(data.error || "request_failed");
        }
        return data;
      }

      document.addEventListener("click", async (event) => {
        const button = event.target.closest("button[data-action]");
        if (!button) return;
        const action = button.getAttribute("data-action");
        const id = button.getAttribute("data-id");
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

      refreshBtn.addEventListener("click", () => loadEvents().catch((error) => {
        window.alert(String(error && error.message ? error.message : error));
      }));

      emailFilterInput.addEventListener("keydown", (event) => {
        if (event.key === "Enter") loadEvents().catch(() => {});
      });
      statusFilterSelect.addEventListener("change", () => loadEvents().catch(() => {}));

      loadEvents().catch((error) => {
        eventsBody.innerHTML = '<tr><td colspan="8" class="muted">' + escapeHtml(String(error && error.message ? error.message : error)) + '</td></tr>';
      });
      setInterval(() => loadEvents().catch(() => {}), 30000);
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
      });
    }

    if (request.method === "GET" && (url.pathname === "/ui" || url.pathname === "/admin")) {
      return html(adminUiPage());
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

    if (request.method === "POST" && url.pathname === "/api/admin/mark-reviewed") {
      const auth = adminAuthorized(request, env);
      if (!auth.ok) return json({ ok: false, error: "unauthorized" }, 401);
      return handleMarkReviewed(request, env);
    }

    if (request.method === "POST" && url.pathname === "/api/admin/suppress") {
      const auth = adminAuthorized(request, env);
      if (!auth.ok) return json({ ok: false, error: "unauthorized" }, 401);
      return handleSuppress(request, env);
    }

    return json({ ok: false, error: "not_found" }, 404);
  },
};
