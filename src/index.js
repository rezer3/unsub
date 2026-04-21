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

const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96" role="img" aria-label="unsub favicon">
  <title>unsub favicon</title>
  <rect width="96" height="96" rx="22" fill="#0d9256"/>
  <rect x="16" y="53" width="64" height="24" rx="4" fill="none" stroke="#fff" stroke-width="2.8"/>
  <line x1="48" y1="18" x2="48" y2="50" stroke="#fff" stroke-width="2.8" stroke-linecap="round"/>
  <polyline points="36,40 48,53 60,40" fill="none" stroke="#fff" stroke-width="2.8" stroke-linejoin="round" stroke-linecap="round"/>
  <line x1="20" y1="20" x2="76" y2="76" stroke="#fbbf24" stroke-width="4" stroke-linecap="round"/>
  <line x1="76" y1="20" x2="20" y2="76" stroke="#fbbf24" stroke-width="4" stroke-linecap="round"/>
</svg>`;

function svg(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "image/svg+xml; charset=utf-8",
      "cache-control": "public, max-age=3600",
      ...headers,
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

function isValidEmail(value) {
  const email = normalizeEmail(value);
  return !!email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
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

async function putJsonSetting(env, key, value) {
  const settingKey = cleanText(key, 120);
  if (!settingKey) throw new Error("missing_setting_key");
  const updatedAt = nowIso();

  await d1Exec(
    env.UNSUB_DB,
    `INSERT INTO admin_settings (key, value_json, updated_at)
     VALUES (?, ?, ?)
     ON CONFLICT(key)
     DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at`,
    [settingKey, JSON.stringify(value || {}), updatedAt]
  );

  return updatedAt;
}

async function getJsonSetting(env, key) {
  const settingKey = cleanText(key, 120);
  if (!settingKey) return null;

  const row = await d1First(
    env.UNSUB_DB,
    `SELECT key, value_json, updated_at FROM admin_settings WHERE key = ?`,
    [settingKey]
  );
  if (!row?.value_json) return null;

  try {
    return JSON.parse(row.value_json);
  } catch {
    return null;
  }
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

const EMAIL_NOTIFICATION_SETTINGS_KEY = "email_notifications";
const SENDPULSE_API_ROOT = "https://api.sendpulse.com";

function defaultEmailNotificationSettings() {
  return {
    enabled: false,
    recipient_email: "",
    sender_email: "",
    subject_prefix: "[unsub]",
    updated_at: "",
    updated_by: "",
    last_status: "never",
    last_sent_at: "",
    last_event_id: "",
    last_message_id: "",
    last_error: "",
  };
}

function normalizeEmailNotificationSettings(value = {}) {
  const defaults = defaultEmailNotificationSettings();
  const normalized = {
    ...defaults,
    ...(value && typeof value === "object" ? value : {}),
  };

  normalized.enabled = !!normalized.enabled;
  normalized.recipient_email = normalizeEmail(normalized.recipient_email);
  normalized.sender_email = normalizeEmail(normalized.sender_email);
  normalized.subject_prefix =
    cleanText(normalized.subject_prefix, 80) || defaults.subject_prefix;
  normalized.updated_at = cleanText(normalized.updated_at, 40);
  normalized.updated_by = cleanText(normalized.updated_by, 200);
  normalized.last_status = cleanText(normalized.last_status, 40) || defaults.last_status;
  normalized.last_sent_at = cleanText(normalized.last_sent_at, 40);
  normalized.last_event_id = cleanText(normalized.last_event_id, 120);
  normalized.last_message_id = cleanText(normalized.last_message_id, 200);
  normalized.last_error = cleanText(normalized.last_error, 500);
  return normalized;
}

async function getEmailNotificationSettings(env) {
  const raw = await getJsonSetting(env, EMAIL_NOTIFICATION_SETTINGS_KEY);
  return normalizeEmailNotificationSettings(raw || {});
}

async function saveEmailNotificationSettings(env, input = {}) {
  const settings = normalizeEmailNotificationSettings(input);
  settings.updated_at = nowIso();
  await putJsonSetting(env, EMAIL_NOTIFICATION_SETTINGS_KEY, settings);
  return settings;
}

async function updateEmailNotificationRuntime(env, patch = {}) {
  const current = await getEmailNotificationSettings(env);
  const next = normalizeEmailNotificationSettings({
    ...current,
    ...patch,
  });
  await putJsonSetting(env, EMAIL_NOTIFICATION_SETTINGS_KEY, next);
  return next;
}

function getSendPulseMode(env) {
  const apiKey = cleanText(env.SENDPULSE_API_KEY || "", 4000);
  if (apiKey) return "api_key";

  const clientId = cleanText(env.SENDPULSE_CLIENT_ID || "", 500);
  const clientSecret = cleanText(env.SENDPULSE_CLIENT_SECRET || "", 500);
  if (clientId && clientSecret) return "oauth";

  return "missing";
}

function isSendPulseConfigured(env) {
  return getSendPulseMode(env) !== "missing";
}

async function parseJsonResponse(response) {
  const text = await response.text();
  if (!text) return null;

  try {
    return JSON.parse(text);
  } catch {
    return { raw: cleanText(text, 2000) };
  }
}

function sendPulseResponseMessage(data, fallback = "sendpulse_request_failed") {
  if (!data) return fallback;

  const candidates = [
    data?.message,
    data?.error,
    data?.errors?.[0]?.message,
    data?.detail,
    typeof data?.raw === "string" ? data.raw : "",
  ];

  for (const candidate of candidates) {
    const text = cleanText(candidate, 500);
    if (text) return text;
  }

  return fallback;
}

function extractSendPulseMessageId(data) {
  const candidates = [
    data?.message_id,
    data?.messageId,
    data?.result?.message_id,
    data?.result?.messageId,
    data?.result?.id,
    data?.id,
  ];

  for (const candidate of candidates) {
    const value = cleanText(candidate, 200);
    if (value) return value;
  }

  return "";
}

async function getSendPulseBearerToken(env) {
  const apiKey = cleanText(env.SENDPULSE_API_KEY || "", 4000);
  if (apiKey) return { token: apiKey, mode: "api_key" };

  const clientId = cleanText(env.SENDPULSE_CLIENT_ID || "", 500);
  const clientSecret = cleanText(env.SENDPULSE_CLIENT_SECRET || "", 500);
  if (!clientId || !clientSecret) {
    throw new Error("sendpulse_credentials_missing");
  }

  const response = await fetch(`${SENDPULSE_API_ROOT}/oauth/access_token`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json",
    },
    body: JSON.stringify({
      grant_type: "client_credentials",
      client_id: clientId,
      client_secret: clientSecret,
    }),
  });

  const data = await parseJsonResponse(response);
  if (!response.ok) {
    throw new Error(sendPulseResponseMessage(data, "sendpulse_auth_failed"));
  }

  const token = cleanText(data?.access_token, 4000);
  if (!token) throw new Error("sendpulse_access_token_missing");
  return { token, mode: "oauth" };
}

async function sendSendPulseEmail(env, payload) {
  const auth = await getSendPulseBearerToken(env);
  const response = await fetch(`${SENDPULSE_API_ROOT}/smtp/emails`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${auth.token}`,
      "content-type": "application/json",
      accept: "application/json",
    },
    body: JSON.stringify({
      email: payload,
    }),
  });

  const data = await parseJsonResponse(response);
  if (!response.ok) {
    throw new Error(sendPulseResponseMessage(data, "sendpulse_send_failed"));
  }

  return {
    mode: auth.mode,
    data,
    messageId: extractSendPulseMessageId(data),
  };
}

async function maybeSendUnsubscribeNotification(env, request, event, claims, suppression) {
  const settings = await getEmailNotificationSettings(env);
  if (!settings.enabled) return { ok: false, skipped: "disabled" };

  if (!isSendPulseConfigured(env)) {
    await updateEmailNotificationRuntime(env, {
      last_status: "error",
      last_error: "sendpulse_not_configured",
      last_event_id: event.id,
      last_message_id: "",
    });
    return { ok: false, skipped: "sendpulse_not_configured" };
  }

  if (!isValidEmail(settings.recipient_email) || !isValidEmail(settings.sender_email)) {
    await updateEmailNotificationRuntime(env, {
      last_status: "error",
      last_error: "email_settings_incomplete",
      last_event_id: event.id,
      last_message_id: "",
    });
    return { ok: false, skipped: "email_settings_incomplete" };
  }

  const origin = cleanText(env.PUBLIC_BASE_URL || "", 500) || new URL(request.url).origin;
  const payload = claims?.payload || {};
  const scopeLabel = buildScopeLabel(event);
  const finalStatus = suppression ? "suppressed" : event.status;
  const subject = `${settings.subject_prefix} Unsubscribe clicked: ${event.email || "unknown"}`;
  const lines = [
    "An unsubscribe link was clicked.",
    "",
    `Email: ${event.email || ""}`,
    `Timestamp: ${event.created_at || ""}`,
    `Scope: ${scopeLabel}`,
    `Method: ${event.method || ""}`,
    `Source: ${event.source || ""}`,
    `Status: ${finalStatus || ""}`,
    `Token ID: ${event.token_id || ""}`,
    `Campaign Source: ${cleanText(payload.source, 120) || ""}`,
    `Admin UI: ${origin}/ui#unsubscribe-events`,
  ];

  const htmlBody = `
    <h1>Unsubscribe clicked</h1>
    <p>An unsubscribe link was clicked.</p>
    <ul>
      <li><strong>Email:</strong> ${escapeHtml(event.email || "")}</li>
      <li><strong>Timestamp:</strong> ${escapeHtml(event.created_at || "")}</li>
      <li><strong>Scope:</strong> ${escapeHtml(scopeLabel)}</li>
      <li><strong>Method:</strong> ${escapeHtml(event.method || "")}</li>
      <li><strong>Source:</strong> ${escapeHtml(event.source || "")}</li>
      <li><strong>Status:</strong> ${escapeHtml(finalStatus || "")}</li>
      <li><strong>Token ID:</strong> ${escapeHtml(event.token_id || "")}</li>
    </ul>
    <p><a href="${escapeHtml(origin)}/ui#unsubscribe-events">Open the unsubscribe console</a></p>
  `;

  try {
    const response = await sendSendPulseEmail(env, {
      html: htmlBody,
      text: lines.filter(Boolean).join("\n"),
      subject,
      from: {
        name: "Unsubscribe Alerts",
        email: settings.sender_email,
      },
      to: [
        {
          email: settings.recipient_email,
        },
      ],
    });

    await updateEmailNotificationRuntime(env, {
      last_status: "sent",
      last_sent_at: nowIso(),
      last_event_id: event.id,
      last_message_id: cleanText(response?.messageId, 200),
      last_error: "",
    });

    return {
      ok: true,
      message_id: cleanText(response?.messageId, 200) || null,
    };
  } catch (error) {
    const message = cleanText(error?.message || error, 500) || "email_send_failed";
    await updateEmailNotificationRuntime(env, {
      last_status: "error",
      last_event_id: event.id,
      last_message_id: "",
      last_error: message,
    });
    console.error("unsubscribe_email_notification_failed", message);
    return { ok: false, error: message };
  }
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

async function handleGetEmailSettings(env) {
  const settings = await getEmailNotificationSettings(env);
  return json({
    ok: true,
    settings,
    provider: "sendpulse",
    sendpulse_configured: isSendPulseConfigured(env),
    sendpulse_mode: getSendPulseMode(env),
  });
}

async function handleUpdateEmailSettings(request, env) {
  const body = await request.json().catch(() => null);
  const current = await getEmailNotificationSettings(env);
  const next = normalizeEmailNotificationSettings({
    ...current,
    enabled: !!body?.enabled,
    recipient_email: body?.recipient_email,
    sender_email: body?.sender_email,
    subject_prefix: body?.subject_prefix,
    updated_by: deriveReviewer(request, body),
    updated_at: nowIso(),
  });

  if (next.recipient_email && !isValidEmail(next.recipient_email)) {
    return json({ ok: false, error: "invalid_recipient_email" }, 400);
  }
  if (next.sender_email && !isValidEmail(next.sender_email)) {
    return json({ ok: false, error: "invalid_sender_email" }, 400);
  }
  if (next.enabled && !next.recipient_email) {
    return json({ ok: false, error: "missing_recipient_email" }, 400);
  }
  if (next.enabled && !next.sender_email) {
    return json({ ok: false, error: "missing_sender_email" }, 400);
  }

  const saved = await saveEmailNotificationSettings(env, next);
  return json({
    ok: true,
    settings: saved,
    provider: "sendpulse",
    sendpulse_configured: isSendPulseConfigured(env),
    sendpulse_mode: getSendPulseMode(env),
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
    : "";

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Unsubscribe Request</title>
    <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
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
      <h1>${escapeHtml(actionText)}</h1>
      ${detailText ? `<p>${escapeHtml(detailText)}</p>` : ""}
      ${email ? `<p class="email">${escapeHtml(email)}</p>` : ""}
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
    <title>${escapeHtml(title)}</title>
    <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
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
      <h1>${escapeHtml(title)}</h1>
      <p>${escapeHtml(message)}</p>
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
    sendpulseConfigured: isSendPulseConfigured(env),
    sendpulseMode: getSendPulseMode(env),
  });

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Unsubscribe Console</title>
    <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600&family=Source+Sans+3:wght@400;500;600&display=swap" rel="stylesheet" />
    <style>
      :root {
        color-scheme: light;
        --bg: #f0f2f5;
        --surface: #ffffff;
        --surface-2: #f6f7f9;
        --surface-3: #eff4ff;
        --border: #e2e5eb;
        --border-2: #d0d4dc;
        --ink: #111827;
        --muted: #6b7280;
        --dim: #9ca3af;
        --green: #0d9256;
        --green-bg: #edfbf4;
        --green-border: #a7e9c9;
        --red: #c9273e;
        --red-bg: #fef2f4;
        --red-border: #f5b8c1;
        --amber: #b45309;
        --amber-bg: #fffbeb;
        --amber-border: #fcd88a;
        --blue: #1d4ed8;
        --blue-light: #eff4ff;
        --slate: #475569;
        --slate-bg: #f1f5f9;
        --mono: "Source Sans 3", sans-serif;
        --sans: "Manrope", sans-serif;
        --radius: 7px;
        --radius-lg: 12px;
        --shadow: 0 1px 3px rgba(0, 0, 0, 0.07), 0 1px 2px rgba(0, 0, 0, 0.05);
      }
      * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
      }
      body {
        font-family: var(--sans);
        background: var(--bg);
        color: var(--ink);
        min-height: 100vh;
        font-size: 14px;
        line-height: 1.5;
      }
      .topbar {
        position: sticky;
        top: 0;
        z-index: 100;
        height: 52px;
        padding: 0 24px;
        background: var(--surface);
        border-bottom: 1px solid var(--border);
        box-shadow: var(--shadow);
        display: flex;
        align-items: center;
        gap: 16px;
      }
      .wrap {
        max-width: 1340px;
        margin: 0 auto;
        padding: 24px 24px 60px;
        display: flex;
        flex-direction: column;
        gap: 16px;
      }
      .topbar-logo {
        font-family: var(--mono);
        font-size: 13px;
        font-weight: 600;
        color: var(--ink);
        letter-spacing: -0.01em;
        white-space: nowrap;
      }
      .topbar-logo span {
        color: var(--muted);
        font-weight: 400;
      }
      .topbar-sep {
        flex: 1;
      }
      .topbar-meta {
        font-family: var(--mono);
        font-size: 11px;
        color: var(--muted);
        display: flex;
        align-items: center;
        gap: 14px;
      }
      .pulse {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: var(--green);
        box-shadow: 0 0 0 0 rgba(13, 146, 86, 0.5);
        animation: pulse 2.6s ease infinite;
        display: inline-block;
      }
      @keyframes pulse {
        0% { box-shadow: 0 0 0 0 rgba(13, 146, 86, 0.45); }
        70% { box-shadow: 0 0 0 6px rgba(13, 146, 86, 0); }
        100% { box-shadow: 0 0 0 0 rgba(13, 146, 86, 0); }
      }
      .header-card,
      .section-card,
      .table-shell,
      .result-card {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: var(--radius-lg);
        box-shadow: 0 18px 50px var(--shadow);
      }
      .header-card {
        padding: 22px 24px 20px;
      }
      .section-card {
        padding: 18px 20px 20px;
      }
      .panel-shell[hidden] {
        display: none;
      }
      h1 {
        font-size: 18px;
        font-weight: 600;
        color: var(--ink);
        letter-spacing: -0.02em;
      }
      h2 {
        font-size: 14px;
        font-weight: 600;
        color: var(--ink);
        letter-spacing: -0.01em;
      }
      .sub {
        margin-top: 5px;
        font-size: 12.5px;
        color: var(--muted);
        line-height: 1.55;
        max-width: 760px;
      }
      .sub code,
      .notice code {
        font-family: var(--mono);
        font-size: 11px;
        background: var(--blue-light);
        border: 1px solid #c7d8fc;
        border-radius: 4px;
        padding: 1px 5px;
        color: var(--blue);
      }
      .meta-strip {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin-top: 12px;
      }
      .meta-chip {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 5px 9px;
        border-radius: 999px;
        border: 1px solid var(--border-2);
        background: var(--slate-bg);
        font-family: var(--mono);
        font-size: 10px;
        font-weight: 600;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        color: var(--slate);
      }
      .meta-chip::before {
        content: "";
        width: 5px;
        height: 5px;
        border-radius: 50%;
        background: currentColor;
        flex-shrink: 0;
      }
      .meta-chip.ok {
        color: var(--green);
        background: var(--green-bg);
        border-color: var(--green-border);
      }
      .meta-chip.warn {
        color: var(--amber);
        background: var(--amber-bg);
        border-color: var(--amber-border);
      }
      .meta-chip.neutral {
        color: var(--slate);
        background: var(--slate-bg);
        border-color: var(--border-2);
      }
      .toolbar,
      .tab-strip,
      .controls-grid {
        margin-top: 16px;
      }
      .controls-grid,
      .toolbar {
        display: grid;
        gap: 10px;
      }
      .controls-grid {
        grid-template-columns: 1fr 1fr;
      }
      .toolbar.events-toolbar {
        grid-template-columns: 1.25fr 180px auto auto;
      }
      .toolbar.generator-toolbar {
        grid-template-columns: 1.35fr auto;
      }
      .toolbar.email-toolbar {
        grid-template-columns: 1fr 1fr;
      }
      .toolbar.email-actions-toolbar {
        grid-template-columns: 1fr auto;
      }
      .field {
        display: flex;
        flex-direction: column;
        gap: 4px;
      }
      .field-inline {
        display: flex;
        align-items: flex-end;
      }
      .toggle-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 14px;
        padding: 12px 14px;
        border: 1px solid var(--border);
        border-radius: var(--radius);
        background: var(--surface-2);
      }
      .toggle-copy {
        display: flex;
        flex-direction: column;
        gap: 3px;
      }
      .toggle-label {
        font-size: 13px;
        font-weight: 600;
        color: var(--ink);
      }
      .toggle-help {
        font-size: 12px;
        color: var(--muted);
      }
      .toggle-input {
        width: 18px;
        height: 18px;
        accent-color: var(--blue);
        flex-shrink: 0;
      }
      .field-label {
        font-family: var(--mono);
        font-size: 10px;
        font-weight: 600;
        color: var(--muted);
        letter-spacing: 0.07em;
        text-transform: uppercase;
      }
      input,
      select,
      button,
      a.button-link {
        font: inherit;
      }
      input, select {
        width: 100%;
        background: var(--surface);
        border: 1px solid var(--border-2);
        border-radius: var(--radius);
        padding: 8px 11px;
        color: var(--ink);
        font-size: 13px;
        outline: none;
        transition: border-color 0.15s, box-shadow 0.15s;
      }
      input::placeholder {
        color: var(--dim);
      }
      input:focus,
      select:focus {
        border-color: #93b4f8;
        box-shadow: 0 0 0 3px rgba(29, 78, 216, 0.08);
      }
      select {
        cursor: pointer;
        appearance: none;
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' fill='none'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%236b7280' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
        background-repeat: no-repeat;
        background-position: right 11px center;
        padding-right: 30px;
      }
      button,
      a.button-link {
        border: none;
        border-radius: var(--radius);
        padding: 8.5px 18px;
        cursor: pointer;
        font-size: 13px;
        font-weight: 600;
        text-decoration: none;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        white-space: nowrap;
        transition: background 0.15s;
      }
      .btn-primary {
        background: var(--ink);
        color: #fff;
        box-shadow: var(--shadow);
      }
      .btn-primary:hover {
        background: #1f2937;
      }
      .btn-ghost,
      a.button-link.ghost {
        background: var(--surface);
        color: var(--ink);
        border: 1px solid var(--border-2);
      }
      .btn-ghost:hover,
      a.button-link.ghost:hover {
        background: var(--surface-2);
      }
      .tab-strip {
        display: inline-flex;
        gap: 8px;
        border-bottom: 1px solid var(--border);
        padding-bottom: 12px;
      }
      .tab {
        padding: 8px 2px;
        border-radius: 0;
        background: transparent;
        color: var(--muted);
        font-family: var(--mono);
        font-size: 11px;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        position: relative;
      }
      .tab.is-active {
        background: transparent;
        color: var(--ink);
      }
      .tab.is-active::after {
        content: "";
        position: absolute;
        left: 0;
        right: 0;
        bottom: -13px;
        height: 2px;
        background: var(--ink);
      }
      .panel-head {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 16px;
        flex-wrap: wrap;
      }
      .statusbar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 12px;
        align-items: center;
        margin-top: 16px;
        padding-top: 14px;
        border-top: 1px solid var(--border);
        color: var(--muted);
        font-size: 12px;
        flex-wrap: wrap;
      }
      .status-summary {
        font-family: var(--mono);
        font-size: 12px;
        font-weight: 600;
        color: var(--green);
      }
      .status-note {
        font-family: var(--mono);
        font-size: 11px;
        color: var(--muted);
      }
      .notice {
        border-radius: var(--radius);
        padding: 12px 14px;
        line-height: 1.5;
        font-size: 12px;
        border: 1px solid transparent;
      }
      .notice.warn {
        background: var(--amber-bg);
        color: var(--amber);
        border-color: var(--amber-border);
      }
      .notice.ok {
        background: var(--green-bg);
        color: var(--green);
        border-color: var(--green-border);
      }
      .table-shell {
        margin-top: 16px;
        overflow: hidden;
      }
      table {
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
      }
      thead {
        background: var(--surface-2);
        border-bottom: 1px solid var(--border);
      }
      th {
        font-family: var(--mono);
        font-size: 10px;
        font-weight: 600;
        letter-spacing: 0.07em;
        text-transform: uppercase;
        color: var(--muted);
        padding: 10px 14px;
        text-align: left;
        white-space: nowrap;
      }
      td {
        padding: 12px 14px;
        border-bottom: 1px solid var(--border);
        vertical-align: top;
        text-align: left;
      }
      tbody tr {
        transition: background 0.1s;
      }
      tbody tr:hover {
        background: var(--surface-2);
      }
      tr:last-child td {
        border-bottom: none;
      }
      .cell-email strong {
        font-family: var(--mono);
        font-size: 12px;
        font-weight: 500;
        color: var(--ink);
        display: block;
      }
      .cell-email .token-id {
        font-family: var(--mono);
        font-size: 10px;
        color: var(--dim);
        margin-top: 2px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        max-width: 220px;
      }
      .ts {
        font-family: var(--mono);
        font-size: 11px;
        color: var(--muted);
        white-space: nowrap;
      }
      .scope-badge {
        font-family: var(--mono);
        font-size: 11px;
        background: var(--slate-bg);
        border: 1px solid var(--border-2);
        border-radius: 4px;
        padding: 2px 7px;
        color: var(--slate);
        white-space: nowrap;
        display: inline-block;
      }
      .method-text {
        font-family: var(--mono);
        font-size: 11px;
        color: var(--muted);
      }
      .tag {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 3px 9px;
        border-radius: 20px;
        font-family: var(--mono);
        font-size: 10px;
        font-weight: 600;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        white-space: nowrap;
        border: 1px solid transparent;
      }
      .tag::before {
        content: "";
        width: 5px;
        height: 5px;
        border-radius: 50%;
        flex-shrink: 0;
      }
      .tag.received,
      .tag.unsigned {
        background: var(--amber-bg);
        color: var(--amber);
        border-color: var(--amber-border);
      }
      .tag.received::before,
      .tag.unsigned::before {
        background: var(--amber);
      }
      .tag.reviewed,
      .tag.signed {
        background: var(--green-bg);
        color: var(--green);
        border-color: var(--green-border);
      }
      .tag.reviewed::before,
      .tag.signed::before {
        background: var(--green);
      }
      .tag.suppressed {
        background: var(--red-bg);
        color: var(--red);
        border-color: var(--red-border);
      }
      .tag.suppressed::before {
        background: var(--red);
      }
      .tag.ignored {
        background: var(--slate-bg);
        color: var(--slate);
        border-color: var(--border-2);
      }
      .tag.ignored::before {
        background: var(--slate);
      }
      .review-cell {
        font-size: 11px;
        font-family: var(--mono);
        color: var(--muted);
        line-height: 1.7;
      }
      .review-cell .unreviewed {
        color: var(--dim);
        font-style: italic;
      }
      .actions {
        display: flex;
        gap: 6px;
        flex-wrap: nowrap;
      }
      .actions button,
      .actions a.button-link {
        padding: 5px 11px;
        font-size: 11px;
        border-radius: 5px;
      }
      .btn-action {
        font-weight: 600;
        border: 1px solid transparent;
      }
      .btn-review {
        background: var(--green-bg);
        color: var(--green);
        border-color: var(--green-border);
      }
      .btn-review:hover {
        background: #d4f5e6;
      }
      .btn-suppress {
        background: var(--red-bg);
        color: var(--red);
        border-color: var(--red-border);
      }
      .btn-suppress:hover {
        background: #fce2e6;
      }
      .muted {
        color: var(--muted);
        font-size: 12px;
      }
      .mono {
        font-family: var(--mono);
        word-break: break-all;
      }
      .result-card {
        margin-top: 16px;
        padding: 16px;
      }
      .result-head {
        display: flex;
        justify-content: space-between;
        gap: 14px;
        align-items: center;
        flex-wrap: wrap;
      }
      .link-box {
        margin-top: 12px;
        padding: 12px 14px;
        border-radius: var(--radius);
        background: var(--surface-2);
        border: 1px solid var(--border);
      }
      .link-cell a {
        color: var(--blue);
      }
      .table-msg {
        padding: 28px 16px;
        text-align: center;
        font-family: var(--mono);
        font-size: 12px;
        color: var(--muted);
      }
      .table-msg.error {
        color: var(--red);
      }
      @media (max-width: 980px) {
        .controls-grid,
        .toolbar.events-toolbar,
        .toolbar.generator-toolbar,
        .toolbar.email-toolbar,
        .toolbar.email-actions-toolbar {
          grid-template-columns: 1fr;
        }
        .table-shell {
          overflow-x: auto;
        }
        table {
          min-width: 980px;
        }
      }
      @media (max-width: 560px) {
        .topbar {
          padding: 0 14px;
        }
        .wrap {
          padding: 16px 14px 40px;
        }
        .topbar-meta .label {
          display: none;
        }
      }
    </style>
  </head>
  <body>
    <header class="topbar">
      <div class="topbar-logo">unsub<span>/admin</span></div>
      <div class="topbar-sep"></div>
      <div class="topbar-meta">
        <span class="pulse"></span>
        <span class="label">auto-refresh 30s</span>
        <span id="lastUpdated"></span>
      </div>
    </header>

    <div class="wrap">
      <section class="header-card">
        <h1>Unsubscribe Console</h1>
        <p class="sub">
          Event-only mode is active. Requests are logged here and are not automatically enforced unless the Worker is configured to auto-suppress.
          Use <code>/u/:token</code> for body-link clicks and <code>POST /api/unsubscribe/:token</code> for endpoint testing.
        </p>
        <div class="meta-strip">
          <span id="autoSuppressChip" class="meta-chip"></span>
          <span id="signingChip" class="meta-chip"></span>
        </div>
        <div class="controls-grid">
          <div class="field">
            <label class="field-label" for="reviewer">Operator</label>
            <input id="reviewer" type="text" placeholder="name or email" />
          </div>
          <div class="field">
            <label class="field-label" for="adminToken">Admin token</label>
            <input id="adminToken" type="password" placeholder="Bearer token if ADMIN_API_TOKEN is set" />
          </div>
        </div>
        <div class="tab-strip" role="tablist" aria-label="Unsubscribe admin tabs">
          <button id="tab-events" class="tab is-active" type="button" data-tab-target="events" role="tab" aria-controls="panel-events" aria-selected="true">Unsubscribe events</button>
          <button id="tab-generate" class="tab" type="button" data-tab-target="generate" role="tab" aria-controls="panel-generate" aria-selected="false">Generate token</button>
          <button id="tab-email" class="tab" type="button" data-tab-target="email" role="tab" aria-controls="panel-email" aria-selected="false">Email</button>
        </div>
      </section>

      <section id="panel-events" class="section-card panel-shell" data-panel="events" role="tabpanel" aria-labelledby="tab-events">
        <div class="panel-head">
          <div>
            <h2>Unsubscribe event queue</h2>
            <p class="sub">Review inbound unsubscribe requests, track status, and optionally suppress later when you are ready to enforce.</p>
          </div>
        </div>
        <div class="toolbar events-toolbar">
          <div class="field">
            <label class="field-label" for="emailFilter">Filter by email</label>
            <input id="emailFilter" type="text" placeholder="user@domain.com" />
          </div>
          <div class="field">
            <label class="field-label" for="statusFilter">Status</label>
            <select id="statusFilter">
              <option value="">All statuses</option>
              <option value="received">Received</option>
              <option value="reviewed">Reviewed</option>
              <option value="suppressed">Suppressed</option>
              <option value="ignored">Ignored</option>
            </select>
          </div>
          <div class="field-inline">
            <span class="meta-chip ${isTruthy(env.AUTO_SUPPRESS_UNSUB) ? "ok" : "warn"}">${isTruthy(env.AUTO_SUPPRESS_UNSUB) ? "Auto suppress on" : "Auto suppress off"}</span>
          </div>
          <div class="field-inline">
            <button id="refreshBtn" class="btn-primary" type="button">Refresh</button>
          </div>
        </div>
        <div class="statusbar">
          <div id="eventsSummary" class="status-summary">Loading…</div>
          <div class="status-note">Latest 150 events</div>
        </div>
        <section class="table-shell">
          <table>
            <thead>
              <tr>
                <th>Email / Token ID</th>
                <th>Timestamp</th>
                <th>Scope</th>
                <th>Method</th>
                <th>Source</th>
                <th>Status</th>
                <th>Review</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="eventsBody">
              <tr><td colspan="8" class="table-msg">Loading events…</td></tr>
            </tbody>
          </table>
        </section>
      </section>

      <section id="panel-generate" class="section-card panel-shell" data-panel="generate" role="tabpanel" aria-labelledby="tab-generate" hidden>
        <div class="panel-head">
          <div>
            <h2>Manual footer-link generation</h2>
            <p class="sub">Generate one-off unsubscribe links for direct Gmail sends and keep a history of every link created from this console.</p>
          </div>
        </div>
        <div id="generatorNotice" class="notice"></div>
        <div class="toolbar generator-toolbar">
          <div class="field">
            <label class="field-label" for="generateEmail">Recipient email</label>
            <input id="generateEmail" type="email" placeholder="recipient@example.com" />
          </div>
          <div class="field-inline">
            <button id="generateBtn" class="btn-primary" type="button">Generate token</button>
          </div>
        </div>
        <section id="generatedResult" class="result-card" hidden></section>
        <div class="statusbar">
          <div id="tokensSummary" class="status-summary">Loading…</div>
          <div class="status-note">Most recent manual links</div>
        </div>
        <section class="table-shell">
          <table>
            <thead>
              <tr>
                <th>Email / Token ID</th>
                <th>Generated</th>
                <th>Scope</th>
                <th>Type</th>
                <th>Link</th>
                <th>Generated By</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="generatedTokensBody">
              <tr><td colspan="7" class="table-msg">Loading generated tokens…</td></tr>
            </tbody>
          </table>
        </section>
      </section>

      <section id="panel-email" class="section-card panel-shell" data-panel="email" role="tabpanel" aria-labelledby="tab-email" hidden>
        <div class="panel-head">
          <div>
            <h2>Email notifications</h2>
            <p class="sub">Get an alert email when someone clicks an unsubscribe link. This sends through SendPulse, so add SendPulse credentials as Worker secrets and use a sender address that SendPulse has approved.</p>
          </div>
        </div>
        <div id="emailNotice" class="notice"></div>
        <div class="toolbar email-toolbar">
          <div class="field">
            <label class="field-label" for="emailRecipient">Notify recipient</label>
            <input id="emailRecipient" type="email" placeholder="you@example.com" />
          </div>
          <div class="field">
            <label class="field-label" for="emailSender">Sender address</label>
            <input id="emailSender" type="email" placeholder="alerts@yourdomain.com" />
          </div>
        </div>
        <div class="toolbar email-actions-toolbar">
          <div class="field">
            <label class="field-label" for="emailSubjectPrefix">Subject prefix</label>
            <input id="emailSubjectPrefix" type="text" placeholder="[unsub]" />
          </div>
          <div class="field-inline">
            <button id="saveEmailSettingsBtn" class="btn-primary" type="button">Save email settings</button>
          </div>
        </div>
        <div class="toggle-row" style="margin-top: 12px;">
          <div class="toggle-copy">
            <span class="toggle-label">Email me when someone clicks unsubscribe</span>
            <span class="toggle-help">Turn this off anytime without deleting your saved addresses.</span>
          </div>
          <input id="emailEnabled" class="toggle-input" type="checkbox" />
        </div>
        <div class="statusbar">
          <div id="emailSummary" class="status-summary">Loading…</div>
          <div id="emailLastStatus" class="status-note"></div>
        </div>
      </section>
    </div>

    <script>
      const uiConfig = ${uiConfig};
      const state = {
        activeTab: "events",
        events: [],
        manualTokens: [],
        latestGenerated: null,
        emailSettings: null,
      };

      const reviewerInput = document.getElementById("reviewer");
      const adminTokenInput = document.getElementById("adminToken");
      const emailFilterInput = document.getElementById("emailFilter");
      const statusFilterSelect = document.getElementById("statusFilter");
      const refreshBtn = document.getElementById("refreshBtn");
      const eventsBody = document.getElementById("eventsBody");
      const eventsSummary = document.getElementById("eventsSummary");
      const lastUpdated = document.getElementById("lastUpdated");
      const generatorNotice = document.getElementById("generatorNotice");
      const generateEmailInput = document.getElementById("generateEmail");
      const generateBtn = document.getElementById("generateBtn");
      const generatedResult = document.getElementById("generatedResult");
      const generatedTokensBody = document.getElementById("generatedTokensBody");
      const tokensSummary = document.getElementById("tokensSummary");
      const emailNotice = document.getElementById("emailNotice");
      const emailRecipientInput = document.getElementById("emailRecipient");
      const emailSenderInput = document.getElementById("emailSender");
      const emailSubjectPrefixInput = document.getElementById("emailSubjectPrefix");
      const emailEnabledInput = document.getElementById("emailEnabled");
      const saveEmailSettingsBtn = document.getElementById("saveEmailSettingsBtn");
      const emailSummary = document.getElementById("emailSummary");
      const emailLastStatus = document.getElementById("emailLastStatus");
      const autoSuppressChip = document.getElementById("autoSuppressChip");
      const signingChip = document.getElementById("signingChip");
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

      function setUpdatedLabel() {
        lastUpdated.textContent = "updated " + formatTimestamp(new Date().toISOString());
      }

      function renderMetaChips() {
        autoSuppressChip.className = "meta-chip " + (uiConfig.autoSuppress ? "ok" : "warn");
        autoSuppressChip.textContent = uiConfig.autoSuppress ? "Auto suppress on" : "Auto suppress off";

        signingChip.className = "meta-chip " + (uiConfig.signingSecretConfigured ? "ok" : "neutral");
        signingChip.textContent = uiConfig.signingSecretConfigured ? "Signed tokens ready" : "Unsigned token fallback";
      }

      function tabNameFromHash(hash) {
        if (hash === "#generate-token") return "generate";
        if (hash === "#email") return "email";
        return "events";
      }

      function tabHashFor(name) {
        if (name === "generate") return "#generate-token";
        if (name === "email") return "#email";
        return "#unsubscribe-events";
      }

      function setActiveTab(name, options = {}) {
        state.activeTab = ["events", "generate", "email"].includes(name) ? name : "events";
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

      function renderEmailNotice() {
        if (uiConfig.sendpulseConfigured) {
          emailNotice.className = "notice ok";
          const authLabel = uiConfig.sendpulseMode === "oauth"
            ? "SendPulse OAuth credentials"
            : "SendPulse API key";
          emailNotice.innerHTML = authLabel + " configured. Set a recipient inbox and a SendPulse-approved sender address to receive unsubscribe-click alerts.";
          return;
        }

        emailNotice.className = "notice warn";
        emailNotice.innerHTML = "Notifications are not wired yet. Add <code>SENDPULSE_API_KEY</code> (recommended) or both <code>SENDPULSE_CLIENT_ID</code> and <code>SENDPULSE_CLIENT_SECRET</code> as Worker secrets.";
      }

      function renderEmailSettings() {
        const settings = state.emailSettings;
        if (!settings) {
          emailSummary.textContent = "Loading…";
          emailLastStatus.textContent = "";
          return;
        }

        emailRecipientInput.value = settings.recipient_email || "";
        emailSenderInput.value = settings.sender_email || "";
        emailSubjectPrefixInput.value = settings.subject_prefix || "[unsub]";
        emailEnabledInput.checked = !!settings.enabled;

        emailSummary.textContent = settings.enabled
          ? "Notifications enabled"
          : "Notifications disabled";

        if (settings.last_status === "sent" && settings.last_sent_at) {
          emailLastStatus.textContent = "Last email sent " + formatTimestamp(settings.last_sent_at);
          return;
        }
        if (settings.last_status === "error" && settings.last_error) {
          emailLastStatus.textContent = "Last error: " + settings.last_error;
          return;
        }
        if (settings.updated_at) {
          emailLastStatus.textContent = "Settings updated " + formatTimestamp(settings.updated_at);
          return;
        }
        emailLastStatus.textContent = "No email notifications sent yet.";
      }

      function renderEvents() {
        if (!state.events.length) {
          eventsBody.innerHTML = '<tr><td colspan="8" class="table-msg">No unsubscribe events yet.</td></tr>';
          eventsSummary.textContent = "0 events";
          return;
        }

        eventsBody.innerHTML = state.events.map((event) => {
          const reviewBits = [];
          if (event.reviewed_by) reviewBits.push(escapeHtml(event.reviewed_by));
          if (event.reviewed_at) reviewBits.push(escapeHtml(formatTimestamp(event.reviewed_at)));
          if (event.notes) reviewBits.push(escapeHtml(event.notes));

          return \`
            <tr>
              <td class="cell-email">
                <strong>\${escapeHtml(event.email || "")}</strong>
                \${event.token_id ? \`<div class="token-id">\${escapeHtml(event.token_id)}</div>\` : ""}
              </td>
              <td><span class="ts">\${escapeHtml(formatTimestamp(event.created_at))}</span></td>
              <td><span class="scope-badge">\${escapeHtml(event.scope_label || event.scope_type || "global")}</span></td>
              <td><span class="method-text">\${escapeHtml(event.method || "")}</span></td>
              <td><span class="method-text">\${escapeHtml(event.source || "")}</span></td>
              <td><span class="tag \${escapeHtml(event.status || "received")}">\${escapeHtml(event.status || "received")}</span></td>
              <td>
                <div class="review-cell">
                  \${reviewBits.join("<br />") || '<span class="unreviewed">Unreviewed</span>'}
                </div>
              </td>
              <td>
                <div class="actions">
                  <button type="button" data-event-action="review" data-id="\${escapeHtml(event.id)}" class="btn-action btn-review">Mark Reviewed</button>
                  <button type="button" data-event-action="suppress" data-id="\${escapeHtml(event.id)}" class="btn-action btn-suppress">Suppress</button>
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
            <span class="ts">\${escapeHtml(formatTimestamp(token.created_at))}</span>
          </div>
          <p class="muted" style="margin-top:12px;">Use this full link in the email footer for <strong>\${escapeHtml(token.email || "")}</strong>.</p>
          <div class="link-box mono"><a href="\${escapeHtml(token.token_url || "")}" target="_blank" rel="noreferrer">\${escapeHtml(token.token_url || "")}</a></div>
          <div class="actions" style="margin-top:12px;">
            <button type="button" class="btn-action btn-review" data-copy-url="\${escapeHtml(token.token_url || "")}">Copy link</button>
            <a class="button-link ghost" href="\${escapeHtml(token.token_url || "")}" target="_blank" rel="noreferrer">Open</a>
          </div>
        \`;
      }

      function renderManualTokens() {
        if (!state.manualTokens.length) {
          generatedTokensBody.innerHTML = '<tr><td colspan="7" class="table-msg">No manual tokens generated yet.</td></tr>';
          tokensSummary.textContent = "0 tokens";
          return;
        }

        generatedTokensBody.innerHTML = state.manualTokens.map((token) => {
          const typeClass = token.signed ? "signed" : "unsigned";
          const typeLabel = token.signed ? "Signed" : "Unsigned";
          return \`
            <tr>
              <td class="cell-email">
                <strong>\${escapeHtml(token.email || "")}</strong>
                \${token.token_id ? \`<div class="token-id">\${escapeHtml(token.token_id)}</div>\` : ""}
              </td>
              <td><span class="ts">\${escapeHtml(formatTimestamp(token.created_at))}</span></td>
              <td><span class="scope-badge">\${escapeHtml(token.scope_label || token.scope_type || "global")}</span></td>
              <td><span class="tag \${typeClass}">\${typeLabel}</span><div class="method-text" style="margin-top:4px;">\${escapeHtml(token.token_version || "")}</div></td>
              <td class="link-cell"><a class="mono" href="\${escapeHtml(token.token_url || "")}" target="_blank" rel="noreferrer">\${escapeHtml(token.token_url || "")}</a></td>
              <td><span class="method-text">\${escapeHtml(token.created_by || "manual")}</span></td>
              <td>
                <div class="actions">
                  <button type="button" class="btn-action btn-review" data-copy-url="\${escapeHtml(token.token_url || "")}">Copy link</button>
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
        setUpdatedLabel();
      }

      async function loadManualTokens() {
        const data = await fetchJson("/api/admin/generated-tokens?limit=150");
        state.manualTokens = Array.isArray(data.tokens) ? data.tokens : [];
        renderManualTokens();
        setUpdatedLabel();
      }

      async function loadEmailSettings() {
        const data = await fetchJson("/api/admin/email-settings");
        state.emailSettings = data.settings || null;
        if (typeof data.sendpulse_configured === "boolean") {
          uiConfig.sendpulseConfigured = data.sendpulse_configured;
        }
        if (typeof data.sendpulse_mode === "string") {
          uiConfig.sendpulseMode = data.sendpulse_mode;
        }
        renderEmailNotice();
        renderEmailSettings();
        setUpdatedLabel();
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
        renderMetaChips();
        renderGeneratorNotice();
        renderLatestGenerated();
        generateEmailInput.value = "";
        await loadManualTokens();
        setActiveTab("generate");
      }

      async function saveEmailSettings() {
        const data = await postJson("/api/admin/email-settings", {
          enabled: emailEnabledInput.checked,
          recipient_email: emailRecipientInput.value.trim(),
          sender_email: emailSenderInput.value.trim(),
          subject_prefix: emailSubjectPrefixInput.value.trim(),
          reviewed_by: reviewerInput.value.trim(),
        });

        state.emailSettings = data.settings || null;
        if (typeof data.sendpulse_configured === "boolean") {
          uiConfig.sendpulseConfigured = data.sendpulse_configured;
        }
        if (typeof data.sendpulse_mode === "string") {
          uiConfig.sendpulseMode = data.sendpulse_mode;
        }
        renderEmailNotice();
        renderEmailSettings();
        setActiveTab("email");
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
      saveEmailSettingsBtn.addEventListener("click", () => {
        saveEmailSettings().catch((error) => {
          window.alert(String(error && error.message ? error.message : error));
        });
      });

      generateEmailInput.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          generateToken().catch(() => {});
        }
      });
      emailSubjectPrefixInput.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          saveEmailSettings().catch(() => {});
        }
      });
      emailFilterInput.addEventListener("keydown", (event) => {
        if (event.key === "Enter") loadEvents().catch(() => {});
      });
      statusFilterSelect.addEventListener("change", () => loadEvents().catch(() => {}));
      window.addEventListener("hashchange", () => {
        setActiveTab(tabNameFromHash(window.location.hash), { skipHash: true });
      });

      renderMetaChips();
      renderGeneratorNotice();
      renderEmailNotice();
      renderEmailSettings();
      renderLatestGenerated();
      setActiveTab(tabNameFromHash(window.location.hash), { skipHash: true });
      setUpdatedLabel();

      loadEvents().catch((error) => {
        eventsBody.innerHTML = '<tr><td colspan="8" class="table-msg error">' + escapeHtml(String(error && error.message ? error.message : error)) + '</td></tr>';
      });
      loadManualTokens().catch((error) => {
        generatedTokensBody.innerHTML = '<tr><td colspan="7" class="table-msg error">' + escapeHtml(String(error && error.message ? error.message : error)) + '</td></tr>';
      });
      loadEmailSettings().catch((error) => {
        emailSummary.textContent = "Email settings unavailable";
        emailLastStatus.textContent = String(error && error.message ? error.message : error);
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
  const emailNotification = await maybeSendUnsubscribeNotification(env, request, event, claims, suppression);

  return json({
    ok: true,
    event_id: event.id,
    status: suppression ? "suppressed" : "received",
    auto_suppressed: !!suppression,
    email_notified: !!emailNotification?.ok,
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
  await maybeSendUnsubscribeNotification(env, request, event, claims, suppression);

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

    if (request.method === "GET" && url.pathname === "/favicon.ico") {
      return redirect("/favicon.svg", 301);
    }

    if (request.method === "GET" && url.pathname === "/favicon.svg") {
      return svg(FAVICON_SVG);
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
        email_notification_provider: "sendpulse",
        sendpulse_configured: isSendPulseConfigured(env),
        sendpulse_mode: getSendPulseMode(env),
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

    if (request.method === "GET" && url.pathname === "/api/admin/email-settings") {
      const auth = adminAuthorized(request, env);
      if (!auth.ok) return json({ ok: false, error: "unauthorized" }, 401);
      return handleGetEmailSettings(env);
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

    if (request.method === "POST" && url.pathname === "/api/admin/email-settings") {
      const auth = adminAuthorized(request, env);
      if (!auth.ok) return json({ ok: false, error: "unauthorized" }, 401);
      return handleUpdateEmailSettings(request, env);
    }

    if (request.method === "POST" && url.pathname === "/api/admin/suppress") {
      const auth = adminAuthorized(request, env);
      if (!auth.ok) return json({ ok: false, error: "unauthorized" }, 401);
      return handleSuppress(request, env);
    }

    return json({ ok: false, error: "not_found" }, 404);
  },
};
