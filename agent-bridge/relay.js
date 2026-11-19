#!/usr/bin/env node
// agent-bridge relay: a self-hosted HTTP(S) server for networks that allow neither Supabase nor Slack.
//
// It speaks the same protocol as the Supabase backend (PostgREST-style RPC), so stores/supabase.js
// works against it unchanged:
//   POST /rest/v1/rpc/<function>   JSON object of named args, `apikey` header, JSON reply, 204 for void,
//                                  errors as {code, message, details, hint}, 404 PGRST202 for unknown
//                                  functions or arguments.
// Agent functions (bridge_whoami ... bridge_recent) are authenticated by the p_token argument.
// Admin functions (bridge_admin_*) need the admin key in the `apikey` header.
// Message semantics (thread rules, hop caps, abuse limits, exactly-once claims) come from
// stores/sqlite.js; this file adds the HTTP layer, agent registry (hashed tokens), limits and audit log.
//
// Config: env vars or flags, see relay/README.md.

import http from "node:http";
import https from "node:https";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { SqliteStore } from "./stores/sqlite.js";
import { AGENT_NAME_RE, BridgeError, DEFAULT_ABUSE_LIMITS, charLength, isUuid } from "./stores/common.js";
import { expandHome } from "./store.js";
import { AuditError, AuditLog } from "./relay-audit.js";

export const MAX_BODY_BYTES = 256 * 1024;
export const MIN_ADMIN_KEY_LENGTH = 32;

export class RelayConfigError extends Error {}

// Error carrying a PostgREST-style SQLSTATE and HTTP status.
class RpcError extends Error {
  constructor(status, code, message, { details = null, hint = null, refused = false } = {}) {
    super(message);
    this.refused = refused; // refused by policy (retention, legal hold), as opposed to a bad request
    this.status = status;
    this.code = code;
    this.details = details;
    this.hint = hint;
  }
}
const userError = (message) => new RpcError(400, "P0001", message); // raise exception ... errcode P0001
const policyError = (message) => new RpcError(400, "P0001", message, { refused: true });
const authError = () => new RpcError(403, "28000", "invalid agent token");

const sha256 = (s) => createHash("sha256").update(s, "utf8").digest();
const sha256hex = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const DAY = 24 * 60 * 60_000;
const MINUTE = 60_000;

// ------------------------------------------------------------------ config

const FLAGS = {
  "--host": "RELAY_HOST",
  "--port": "RELAY_PORT",
  "--db": "RELAY_DB",
  "--admin-key-file": "RELAY_ADMIN_KEY_FILE",
  "--tls-cert": "RELAY_TLS_CERT",
  "--tls-key": "RELAY_TLS_KEY",
  "--audit-log": "RELAY_AUDIT_LOG",
  "--tls-ca": "RELAY_TLS_CA",
  "--auditor-key-file": "RELAY_AUDITOR_KEY_FILE",
  "--min-retention-days": "RELAY_MIN_RETENTION_DAYS",
};

// Strict switches: security settings must never fail open on a near-miss value.
const BOOL_ON = new Set(["1", "true", "yes", "on"]);
const BOOL_OFF = new Set(["0", "false", "no", "off", ""]);
export function parseSwitch(name, raw) {
  if (raw === undefined || raw === null) return false;
  const v = String(raw).trim().toLowerCase();
  if (BOOL_ON.has(v)) return true;
  if (BOOL_OFF.has(v)) return false;
  throw new RelayConfigError(`${name} must be one of 1/true/yes/on or 0/false/no/off (or empty), got "${String(raw).slice(0, 40)}"`);
}

const PEM_MARKERS = {
  certificate: /-----BEGIN CERTIFICATE-----/,
  key: /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
};
// Reads a PEM file named by `name`; an empty, unreadable or non-PEM file is a config error.
function readPem(name, path, kind) {
  let buf;
  try {
    buf = readFileSync(expandHome(path));
  } catch (err) {
    throw new RelayConfigError(`can't read ${name} ${path}: ${err.code || err.message}`);
  }
  const text = buf.toString("utf8");
  if (!text.trim()) throw new RelayConfigError(`${name} ${path} is empty`);
  if (!PEM_MARKERS[kind].test(text)) throw new RelayConfigError(`${name} ${path} does not contain a PEM ${kind}`);
  return buf;
}

// A positive whole number from the environment, or the default when unset. Set but empty or nonsense is an error.
function intSetting(e, name, def, { min = 1, max = 2 ** 31 - 1 } = {}) {
  if (e[name] === undefined) return def;
  const raw = String(e[name]).trim();
  const n = Number(raw);
  if (raw === "" || !Number.isInteger(n) || n < min || n > max) {
    throw new RelayConfigError(`${name} must be a whole number between ${min} and ${max}, got "${raw.slice(0, 40)}"`);
  }
  return n;
}

export const DEFAULT_LIMITS = {
  headersTimeoutMs: 10_000, // time to receive the complete request headers
  requestTimeoutMs: 30_000, // time to receive the complete request
  idleTimeoutMs: 30_000, // a socket that sends nothing for this long is closed (also before the TLS handshake)
  keepAliveTimeoutMs: 5_000,
  maxConnections: 512,
  authFailAuditMax: 10, // audit lines per source IP and scope per window; the rest are counted in a summary line
  authFailAuditWindowMs: 60_000,
};

// Flags override env. The admin key is deliberately not a flag (it would show up in `ps`).
export function loadConfig(env = process.env, argv = []) {
  const e = { ...env };
  for (const k of Object.keys(e)) if (e[k] === undefined) delete e[k];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--audit-bodies") {
      e.RELAY_AUDIT_BODIES = "1";
      continue;
    }
    if (argv[i] === "--legal-hold") {
      e.RELAY_LEGAL_HOLD = "1";
      continue;
    }
    if (argv[i] === "--audit-required") {
      e.RELAY_AUDIT_REQUIRED = "1";
      continue;
    }
    const name = FLAGS[argv[i]];
    if (!name) throw new RelayConfigError(`unknown option ${argv[i]} (see relay/README.md)`);
    if (argv[i + 1] == null || (argv[i + 1].startsWith("--") && argv[i + 1] !== "")) throw new RelayConfigError(`${argv[i]} needs a value`);
    e[name] = argv[++i];
  }

  // A path or key setting that is present but empty is an error: an unset compose/systemd variable must
  // not quietly turn a protection (client certificates, a key file, the audit log) off.
  for (const name of ["RELAY_TLS_CERT", "RELAY_TLS_KEY", "RELAY_TLS_CA", "RELAY_ADMIN_KEY_FILE", "RELAY_AUDITOR_KEY_FILE", "RELAY_AUDIT_LOG"]) {
    if (name in e && !String(e[name]).trim()) {
      throw new RelayConfigError(`${name} is set but empty. Give it a value, or remove it to leave the feature off.`);
    }
  }

  const readKey = (name, what) => {
    const fromEnv = (e[name] || "").trim();
    const fileVar = `${name}_FILE`;
    // two sources for one key: never guess which one wins (a stale variable must not outrank a rotated file)
    if (fromEnv && fileVar in e) throw new RelayConfigError(`both ${name} and ${fileVar} are set; set only one so it is clear which ${what} key is in use`);
    let k = fromEnv;
    if (!k && fileVar in e) {
      const p = expandHome(e[fileVar].trim());
      try {
        k = readFileSync(p, "utf8").trim();
      } catch (err) {
        throw new RelayConfigError(`can't read ${fileVar} ${p}: ${err.code || err.message}`);
      }
      if (!k) throw new RelayConfigError(`${fileVar} ${p} is empty`);
    }
    if (k && k.length < MIN_ADMIN_KEY_LENGTH) {
      throw new RelayConfigError(
        `the ${what} key is too weak (${k.length} characters, need at least ${MIN_ADMIN_KEY_LENGTH}). Generate one with: openssl rand -hex 32`
      );
    }
    return k || null;
  };
  const adminKey = readKey("RELAY_ADMIN_KEY", "admin");
  if (!adminKey) {
    throw new RelayConfigError("RELAY_ADMIN_KEY (or RELAY_ADMIN_KEY_FILE) is required. Generate one with: openssl rand -hex 32");
  }
  const auditorKey = readKey("RELAY_AUDITOR_KEY", "auditor");
  if (auditorKey && auditorKey === adminKey) throw new RelayConfigError("RELAY_AUDITOR_KEY must be different from RELAY_ADMIN_KEY");

  const retentionRaw = (e.RELAY_MIN_RETENTION_DAYS ?? "").trim();
  const minRetentionDays = retentionRaw === "" ? 0 : Number(retentionRaw);
  if (!Number.isFinite(minRetentionDays) || minRetentionDays < 0) {
    throw new RelayConfigError(`RELAY_MIN_RETENTION_DAYS must be a number of days >= 0, got "${retentionRaw}"`);
  }

  const port = e.RELAY_PORT == null || e.RELAY_PORT === "" ? 8787 : Number(e.RELAY_PORT);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new RelayConfigError(`invalid RELAY_PORT ${e.RELAY_PORT}`);

  const cert = e.RELAY_TLS_CERT?.trim();
  const key = e.RELAY_TLS_KEY?.trim();
  if (!!cert !== !!key) throw new RelayConfigError("RELAY_TLS_CERT and RELAY_TLS_KEY must be set together");
  const caPath = e.RELAY_TLS_CA?.trim();
  if (caPath && !cert) throw new RelayConfigError("RELAY_TLS_CA (client certificates) needs RELAY_TLS_CERT and RELAY_TLS_KEY");
  let tls = null;
  if (cert) {
    tls = { cert: readPem("RELAY_TLS_CERT", cert, "certificate"), key: readPem("RELAY_TLS_KEY", key, "key") };
    // mutual TLS: only clients holding a certificate signed by this CA complete the handshake
    if (caPath) Object.assign(tls, { ca: readPem("RELAY_TLS_CA", caPath, "certificate"), requestCert: true, rejectUnauthorized: true });
  }

  const auditLog = e.RELAY_AUDIT_LOG?.trim() ? expandHome(e.RELAY_AUDIT_LOG.trim()) : null;
  const auditRequired = parseSwitch("RELAY_AUDIT_REQUIRED", e.RELAY_AUDIT_REQUIRED);
  if (auditRequired && !auditLog) throw new RelayConfigError("RELAY_AUDIT_REQUIRED needs RELAY_AUDIT_LOG (there is nothing to require otherwise)");

  const D = DEFAULT_LIMITS;
  const limits = {
    headersTimeoutMs: intSetting(e, "RELAY_HEADERS_TIMEOUT_MS", D.headersTimeoutMs),
    requestTimeoutMs: intSetting(e, "RELAY_REQUEST_TIMEOUT_MS", D.requestTimeoutMs),
    idleTimeoutMs: intSetting(e, "RELAY_IDLE_TIMEOUT_MS", D.idleTimeoutMs),
    keepAliveTimeoutMs: intSetting(e, "RELAY_KEEPALIVE_TIMEOUT_MS", D.keepAliveTimeoutMs),
    maxConnections: intSetting(e, "RELAY_MAX_CONNECTIONS", D.maxConnections),
    authFailAuditMax: intSetting(e, "RELAY_AUTH_FAIL_AUDIT_MAX", D.authFailAuditMax),
    authFailAuditWindowMs: intSetting(e, "RELAY_AUTH_FAIL_AUDIT_WINDOW_MS", D.authFailAuditWindowMs),
  };
  if (limits.headersTimeoutMs > limits.requestTimeoutMs) {
    throw new RelayConfigError("RELAY_HEADERS_TIMEOUT_MS can't be longer than RELAY_REQUEST_TIMEOUT_MS");
  }

  return {
    adminKey,
    auditorKey,
    minRetentionDays,
    legalHold: parseSwitch("RELAY_LEGAL_HOLD", e.RELAY_LEGAL_HOLD),
    host: (e.RELAY_HOST || "127.0.0.1").trim(),
    port,
    dbPath: expandHome((e.RELAY_DB || "").trim() || "~/.agent-bridge/relay.db"),
    tls,
    auditLog,
    auditBodies: parseSwitch("RELAY_AUDIT_BODIES", e.RELAY_AUDIT_BODIES),
    auditRequired,
    limits,
  };
}

// The effective security settings on one line, printed at startup.
export function describePosture(config) {
  const audit = config.auditLog ? `on (${[config.auditBodies ? "with bodies" : "no bodies", config.auditRequired ? "required" : "best effort"].join(", ")})` : "off";
  return [
    `TLS: ${config.tls ? "on" : "off"}`,
    `mTLS: ${config.tls?.requestCert ? "required" : "off"}`,
    `legal hold: ${config.legalHold ? "ON" : "off"}`,
    `minimum retention: ${config.minRetentionDays} day(s)`,
    `audit: ${audit}`,
    `auditor key: ${config.auditorKey ? "set" : "off"}`,
  ].join(", ");
}

// ------------------------------------------------------------------ argument coercion (what Postgres would do)

const INT_MAX = 2147483647;
const MAX_INTERVAL_MS = 36500 * 24 * 60 * MINUTE; // 100 years
// A short, bounded rendering of an offending value for an error message. Never recurses without a limit:
// a 100,000-level nested array must not be able to overflow the stack (or cost anything) here.
function preview(v, depth = 0) {
  if (v === null || typeof v !== "object") return v;
  if (depth >= 3) return "...";
  if (Array.isArray(v)) return v.slice(0, 5).map((x) => preview(x, depth + 1));
  const out = {};
  for (const k of Object.keys(v).slice(0, 5)) out[k] = preview(v[k], depth + 1);
  return out;
}
const show = (v) => {
  try {
    return (JSON.stringify(preview(v)) ?? String(v)).slice(0, 100);
  } catch {
    return "<unprintable>";
  }
};
const typeError = (type, v) => new RpcError(400, "22P02", `invalid input syntax for type ${type}: ${show(v)}`);

const COERCE = {
  text(v) {
    if (v == null) return null;
    if (typeof v === "string") {
      if (v.includes("\u0000")) throw new RpcError(400, "22021", 'invalid byte sequence for encoding "UTF8": 0x00');
      return v;
    }
    if (typeof v === "number" || typeof v === "boolean") return String(v);
    throw typeError("text", v);
  },
  int(v) {
    if (v == null) return null;
    const n = typeof v === "string" && /^\s*-?\d+\s*$/.test(v) ? Number(v) : v;
    if (typeof n !== "number" || !Number.isInteger(n)) throw typeError("integer", v);
    if (Math.abs(n) > INT_MAX) throw new RpcError(400, "22003", "value is out of range for type integer");
    return n;
  },
  bigint(v) {
    if (v == null) return null;
    const n = typeof v === "string" && /^\s*-?\d+\s*$/.test(v) ? Number(v) : v;
    if (typeof n !== "number" || !Number.isInteger(n)) throw typeError("bigint", v);
    if (!Number.isSafeInteger(n)) throw new RpcError(400, "22003", "value is out of range for type bigint");
    return n;
  },
  boolean(v) {
    if (v == null) return null;
    if (typeof v === "boolean") return v;
    if (v === "true" || v === "false") return v === "true";
    throw typeError("boolean", v);
  },
  uuid(v) {
    if (v == null) return null;
    if (typeof v !== "string" || !isUuid(v)) throw typeError("uuid", v);
    return v.toLowerCase();
  },
  // A date alone is a UTC date. A date-time needs an explicit zone (Z or +HH:MM): without one the answer would
  // depend on the relay host's TZ and an export range would silently move (R2-09).
  timestamp(v) {
    if (v == null) return null;
    const bad = (why) =>
      new RpcError(400, "22007", `invalid input syntax for type timestamp with time zone: ${show(v)}${why ? ` (${why})` : ""}`, {
        hint: "Use ISO 8601 with a zone, for example 2026-11-19T18:00:00Z or 2026-11-19T18:00:00+01:00, or a UTC date like 2026-11-19.",
      });
    if (typeof v !== "string") throw bad();
    const m = v.trim().match(/^(\d{4})-(\d{2})-(\d{2})(?:[Tt ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?(?:(Z|z)|([+-])(\d{2})(?::?(\d{2}))?)?)?$/);
    if (!m) throw bad();
    const [, y, mo, d, hh, mi, ss, frac, zulu, sign, oh, om] = m;
    const hasTime = hh !== undefined;
    const hasZone = zulu !== undefined || sign !== undefined;
    if (hasTime && !hasZone) throw bad("time zone missing");
    const nums = [y, mo, d, hh ?? 0, mi ?? 0, ss ?? 0].map(Number);
    const offsetMin = sign ? (sign === "-" ? -1 : 1) * (Number(oh) * 60 + Number(om ?? 0)) : 0;
    if (nums[1] < 1 || nums[1] > 12 || nums[3] > 23 || nums[4] > 59 || nums[5] > 59 || Number(oh ?? 0) > 23 || Number(om ?? 0) > 59) throw bad();
    const t = new Date(0);
    t.setUTCFullYear(nums[0], nums[1] - 1, nums[2]);
    t.setUTCHours(nums[3], nums[4], nums[5], frac ? Number(frac.padEnd(3, "0").slice(0, 3)) : 0);
    if (t.getUTCDate() !== nums[2] || t.getUTCMonth() !== nums[1] - 1) throw bad(); // 31 February
    return new Date(t.getTime() - offsetMin * MINUTE).toISOString();
  },
  bigintArray(v) {
    if (v == null) return null;
    if (!Array.isArray(v)) throw typeError("bigint[]", v);
    return v.map((x) => (x == null ? null : COERCE.bigint(x)));
  },
  // returns milliseconds
  interval(v) {
    if (v == null) return null;
    const m =
      typeof v === "string" && v.match(/^\s*(\d+(?:\.\d+)?)\s*(seconds?|secs?|minutes?|mins?|hours?|days?|weeks?)\s*$/i);
    if (!m) throw new RpcError(400, "22007", `invalid input syntax for type interval: ${show(v)}`);
    const u = m[2].toLowerCase();
    const unit = u.startsWith("s") ? 1000 : u.startsWith("mi") ? MINUTE : u.startsWith("h") ? 60 * MINUTE : u.startsWith("d") ? 24 * 60 * MINUTE : 7 * 24 * 60 * MINUTE;
    const ms = Number(m[1]) * unit;
    // Postgres refuses intervals it can't represent; here anything beyond 100 years can't be a real age
    if (!Number.isFinite(ms) || ms > MAX_INTERVAL_MS) {
      throw new RpcError(400, "22008", `interval out of range: ${show(v)}`, { hint: "The longest accepted interval is 36500 days." });
    }
    return ms;
  },
};

// ------------------------------------------------------------------ the relay

const NAME_CHECK = (name) => {
  if (name == null) {
    throw new RpcError(400, "23502", 'null value in column "name" of relation "bridge_agents" violates not-null constraint');
  }
  if (!AGENT_NAME_RE.test(name)) {
    throw new RpcError(400, "23514", 'new row for relation "bridge_agents" violates check constraint "bridge_agents_name_check"');
  }
};
const lenCheck = (v, max, constraint) => {
  if (v != null && charLength(v) > max) {
    throw new RpcError(400, "23514", `new row for relation "bridge_agents" violates check constraint "${constraint}"`);
  }
};
const clamp = (v, lo, hi) => Math.min(Math.max(v, lo), hi);

// Failed authentications are the one audit event an unauthenticated client can produce at will. Per source IP
// and scope, the first `max` in a window are logged one by one; the rest are only counted, and the count is
// written as an `auth_failed.summary` line when the window ends. So there is always at least one line per
// source per window, and the log grows by a bounded amount however hard it is hammered.
class AuthFailAudit {
  constructor(audit, { authFailAuditMax, authFailAuditWindowMs }) {
    this.audit = audit;
    this.max = authFailAuditMax;
    this.windowMs = authFailAuditWindowMs;
    this.entries = new Map();
    this.timer = setInterval(() => this.flush(), Math.min(this.windowMs, 5000));
    this.timer.unref();
  }
  record(scope, fn, ip) {
    const now = Date.now();
    let k = `${ip}|${scope}`;
    let e = this.entries.get(k);
    if (e && now - e.start >= this.windowMs) {
      this.#summarize(e);
      this.entries.delete(k);
      e = undefined;
    }
    if (!e) {
      // bound the memory an address-spraying client can use: past 10,000 sources they share one counter per scope
      if (this.entries.size >= 10_000) {
        k = `*|${scope}`;
        e = this.entries.get(k);
      }
      if (!e) {
        e = { start: now, kept: 0, suppressed: 0, scope, ip: k.startsWith("*|") ? "(many)" : ip };
        this.entries.set(k, e);
      }
    }
    if (e.kept < this.max) {
      e.kept++;
      this.audit.write({ action: "auth_failed", scope, fn, ip }, { strict: false });
    } else {
      e.suppressed++;
    }
  }
  #summarize(e) {
    if (!e.suppressed) return;
    this.audit.write(
      { action: "auth_failed.summary", scope: e.scope, ip: e.ip, since: new Date(e.start).toISOString(), window_ms: this.windowMs, logged: e.kept, suppressed: e.suppressed },
      { strict: false }
    );
  }
  flush(all = false) {
    const now = Date.now();
    for (const [k, e] of this.entries) {
      if (all || now - e.start >= this.windowMs) {
        this.#summarize(e);
        this.entries.delete(k);
      }
    }
  }
  close() {
    clearInterval(this.timer);
    this.flush(true);
  }
}

export async function startRelay(config) {
  const audit = new AuditLog(config.auditLog, config.auditBodies, { required: !!config.auditRequired });
  const lim = { ...DEFAULT_LIMITS, ...config.limits };
  const authFails = new AuthFailAudit(audit, lim);
  // One SQLite connection owns the database. Messages go through SqliteStore (the same code the local
  // backend runs); the relay adds its own agents and settings tables next to the messages table.
  const core = new SqliteStore({ agentName: "relay", dbPath: config.dbPath, busyTimeoutMs: 10000 });
  const db = core.db;
  db.exec(`
    CREATE TABLE IF NOT EXISTS relay_agents (
      name        TEXT PRIMARY KEY CHECK (length(name) BETWEEN 1 AND 40),
      description TEXT,
      project_dir TEXT,
      token_hash  TEXT NOT NULL UNIQUE,
      created_at  TEXT NOT NULL,
      last_seen   TEXT,
      revoked_at  TEXT
    );
    CREATE TABLE IF NOT EXISTS relay_settings (
      id                    INTEGER PRIMARY KEY CHECK (id = 1),
      rate_per_minute       INTEGER NOT NULL,
      max_unread_per_sender INTEGER NOT NULL,
      max_bytes_per_day     INTEGER NOT NULL
    );
  `);
  db.prepare(
    `INSERT OR IGNORE INTO relay_settings (id, rate_per_minute, max_unread_per_sender, max_bytes_per_day) VALUES (1, ?, ?, ?)`
  ).run(DEFAULT_ABUSE_LIMITS.ratePerMinute, DEFAULT_ABUSE_LIMITS.maxUnreadPerSender, DEFAULT_ABUSE_LIMITS.maxBytesPerDay);
  const adminDigest = sha256(config.adminKey);
  const auditorDigest = config.auditorKey ? sha256(config.auditorKey) : null;
  const minRetentionMs = config.minRetentionDays * DAY;
  const nowIso = () => new Date().toISOString();

  const settings = () => db.prepare(`SELECT * FROM relay_settings WHERE id = 1`).get();
  const limitsObj = () => {
    const s = settings();
    return { ratePerMinute: s.rate_per_minute, maxUnreadPerSender: s.max_unread_per_sender, maxBytesPerDay: s.max_bytes_per_day };
  };

  // Resolves a token to an agent name or throws "invalid agent token". Touches last_seen at most every 30s.
  function authenticate(token) {
    if (typeof token !== "string" || token.length < 20 || token.length > 200) throw authError();
    const row = db.prepare(`SELECT name, last_seen FROM relay_agents WHERE token_hash = ? AND revoked_at IS NULL`).get(sha256hex(token));
    if (!row) throw authError();
    if (!row.last_seen || Date.parse(row.last_seen) < Date.now() - 30_000) {
      db.prepare(`UPDATE relay_agents SET last_seen = ? WHERE name = ?`).run(nowIso(), row.name);
    }
    return row.name;
  }

  // The store for one caller: the shared SqliteStore with this agent's identity and the current limits.
  const storeFor = (me) => Object.create(core, { agent: { value: me }, limits: { value: limitsObj() } });
  const unreadCount = (me) => db.prepare(`SELECT COUNT(*) AS n FROM messages WHERE to_agent = ? AND read_at IS NULL`).get(me).n;
  const newToken = () => "abt_" + randomBytes(32).toString("hex");

  // name -> { args: { p_name: [type, required] }, admin?: true, void?: true, run(me, args) }
  const FUNCTIONS = {
    bridge_whoami: {
      args: { p_token: ["text", true] },
      run: (me) => {
        const a = db.prepare(`SELECT name, description, project_dir FROM relay_agents WHERE name = ?`).get(me);
        return { agent: a.name, description: a.description, project_dir: a.project_dir, unread: unreadCount(me) };
      },
    },
    bridge_heartbeat: {
      args: { p_token: ["text", true], p_description: ["text"], p_project_dir: ["text"] },
      void: true,
      run: (me, a) => {
        lenCheck(a.p_description, 500, "bridge_agents_description_check");
        lenCheck(a.p_project_dir, 1000, "bridge_agents_project_dir_check");
        db.prepare(
          `UPDATE relay_agents SET description = COALESCE(?, description), project_dir = COALESCE(?, project_dir), last_seen = ? WHERE name = ?`
        ).run(a.p_description, a.p_project_dir, nowIso(), me);
      },
    },
    bridge_list_agents: {
      args: { p_token: ["text", true] },
      run: () =>
        db
          .prepare(`SELECT name, description, project_dir, last_seen FROM relay_agents WHERE revoked_at IS NULL ORDER BY name`)
          .all()
          .map((r) => ({ ...r })),
    },
    bridge_send: {
      args: {
        p_token: ["text", true],
        p_to: ["text", true],
        p_body: ["text", true],
        p_type: ["text"],
        p_subject: ["text"],
        p_thread_id: ["uuid"],
        p_max_hops: ["int"],
      },
      run: async (me, a) => {
        if (a.p_to === me) throw userError("An agent cannot message itself.");
        const known = a.p_to != null && db.prepare(`SELECT 1 FROM relay_agents WHERE name = ? AND revoked_at IS NULL`).get(a.p_to);
        if (!known) throw userError(`Unknown agent "${a.p_to}". Use list_agents to see who is registered.`);
        if (a.p_body == null) {
          throw new RpcError(400, "23502", 'null value in column "body" of relation "bridge_messages" violates not-null constraint');
        }
        const row = await storeFor(me).send({
          to: a.p_to,
          body: a.p_body,
          type: a.p_type ?? "request",
          subject: a.p_subject,
          threadId: a.p_thread_id,
          maxHops: clamp(a.p_max_hops ?? 20, 1, 100),
        });
        try {
          audit.message("send", me, row);
        } catch (e) {
          // no audit line, no message: take back what was just stored (the thread numbering uses max(hop), so this is safe)
          if (e instanceof AuditError) db.prepare(`DELETE FROM messages WHERE id = ?`).run(row.id);
          throw e;
        }
        return row;
      },
    },
    bridge_inbox: {
      args: {
        p_token: ["text", true],
        p_limit: ["int"],
        p_mark_read: ["boolean"],
        p_thread_id: ["uuid"],
        p_from: ["text"],
      },
      run: async (me, a) => {
        const markRead = a.p_mark_read ?? true;
        // a sender name that can't exist has no mail (what the SQL function answers too)
        if (a.p_from != null && !AGENT_NAME_RE.test(a.p_from)) return [];
        const rows = await storeFor(me).inbox({
          limit: clamp(a.p_limit ?? 20, 1, 100),
          markRead,
          threadId: a.p_thread_id,
          fromAgent: a.p_from,
        });
        try {
          if (markRead) for (const m of rows) audit.message("deliver", me, m);
          else audit.write({ action: "peek", agent: me, count: rows.length, ids: rows.map((m) => m.id) });
        } catch (e) {
          // not recorded, so not delivered: hand the claimed messages back
          if (e instanceof AuditError && markRead && rows.length) await storeFor(me).unmark(rows.map((m) => m.id));
          throw e;
        }
        return rows;
      },
    },
    bridge_unmark: {
      args: { p_token: ["text", true], p_ids: ["bigintArray", true] },
      run: async (me, a) => {
        const ids = (a.p_ids || []).filter((x) => x != null);
        const n = await storeFor(me).unmark(ids);
        if (n) audit.write({ action: "unmark", agent: me, ids });
        return n;
      },
    },
    bridge_unread_summary: {
      args: { p_token: ["text", true] },
      run: (me) => storeFor(me).unreadSummary(),
    },
    bridge_thread: {
      args: { p_token: ["text", true], p_thread_id: ["uuid", true] },
      run: async (me, a) => {
        const rows = await storeFor(me).thread(a.p_thread_id);
        audit.write({ action: "thread", agent: me, thread_id: a.p_thread_id, count: rows.length, ids: rows.map((m) => m.id) });
        return rows;
      },
    },
    bridge_recent: {
      args: { p_token: ["text", true], p_limit: ["int"], p_after_id: ["bigint"] },
      run: async (me, a) => {
        const rows = await storeFor(me).recent({ limit: clamp(a.p_limit ?? 20, 1, 200), afterId: Math.max(a.p_after_id ?? 0, 0) });
        // `recent` returns full bodies of read and unread messages alike: it must leave a record of which ones
        audit.write({ action: "recent", agent: me, count: rows.length, ids: rows.map((m) => m.id) });
        return rows;
      },
    },

    // ---- admin (the apikey header must be the admin key)
    bridge_admin_create_agent: {
      admin: true,
      args: { p_name: ["text", true], p_description: ["text"] },
      run: (_, a) => {
        NAME_CHECK(a.p_name);
        lenCheck(a.p_description, 500, "bridge_agents_description_check");
        const token = newToken();
        core.tx(() => {
          if (db.prepare(`SELECT 1 FROM relay_agents WHERE name = ?`).get(a.p_name)) {
            throw userError(`Agent "${a.p_name}" already exists. Use bridge_admin_rotate_token to issue a new token.`);
          }
          db.prepare(`INSERT INTO relay_agents (name, description, token_hash, created_at) VALUES (?, ?, ?, ?)`).run(
            a.p_name,
            a.p_description,
            sha256hex(token),
            nowIso()
          );
        });
        audit.write({ outcome: "ok", action: "admin.create_agent", agent: a.p_name });
        return token;
      },
    },
    // Issues a new token (the old one stops working) and un-revokes the agent.
    bridge_admin_rotate_token: {
      admin: true,
      args: { p_name: ["text", true] },
      run: (_, a) => {
        const token = newToken();
        const r = db.prepare(`UPDATE relay_agents SET token_hash = ?, revoked_at = NULL WHERE name = ?`).run(sha256hex(token), a.p_name);
        if (!r.changes) throw userError(`Unknown agent "${a.p_name}".`);
        audit.write({ outcome: "ok", action: "admin.rotate_token", agent: a.p_name });
        return token;
      },
    },
    bridge_admin_revoke_agent: {
      admin: true,
      void: true,
      args: { p_name: ["text", true] },
      run: (_, a) => {
        const r = db.prepare(`UPDATE relay_agents SET revoked_at = ? WHERE name = ?`).run(nowIso(), a.p_name);
        if (!r.changes) throw userError(`Unknown agent "${a.p_name}".`);
        audit.write({ outcome: "ok", action: "admin.revoke_agent", agent: a.p_name });
      },
    },
    // Removes an agent and every message it sent or received.
    bridge_admin_delete_agent: {
      admin: true,
      args: { p_name: ["text", true] },
      run: (_, a) => {
        if (config.legalHold) throw policyError("Legal hold is active: agents and messages can't be deleted.");
        if (minRetentionMs > 0) {
          const cutoff = new Date(Date.now() - minRetentionMs).toISOString();
          const young = db.prepare(`SELECT COUNT(*) AS n FROM messages WHERE (from_agent = ? OR to_agent = ?) AND created_at > ?`).get(a.p_name, a.p_name, cutoff).n;
          if (young) {
            throw policyError(
              `Retention policy: ${young} message(s) of "${a.p_name}" are younger than the minimum retention of ${config.minRetentionDays} day(s) and can't be deleted yet.`
            );
          }
        }
        const n = core.tx(() => {
          const del = db.prepare(`DELETE FROM messages WHERE from_agent = ? OR to_agent = ?`).run(a.p_name, a.p_name);
          const r = db.prepare(`DELETE FROM relay_agents WHERE name = ?`).run(a.p_name);
          if (!r.changes) throw userError(`Unknown agent "${a.p_name}".`);
          return Number(del.changes);
        });
        audit.write({ outcome: "ok", action: "admin.delete_agent", agent: a.p_name, messages: n });
        return n;
      },
    },
    bridge_admin_set_limits: {
      admin: true,
      args: { p_rate_per_minute: ["int"], p_max_unread_per_sender: ["int"], p_max_bytes_per_day: ["bigint"] },
      run: (_, a) => {
        const cur = settings();
        const next = {
          rate_per_minute: a.p_rate_per_minute ?? cur.rate_per_minute,
          max_unread_per_sender: a.p_max_unread_per_sender ?? cur.max_unread_per_sender,
          max_bytes_per_day: a.p_max_bytes_per_day ?? cur.max_bytes_per_day,
        };
        const ranges = { rate_per_minute: [1, 10000], max_unread_per_sender: [1, 100000], max_bytes_per_day: [1000, 100_000_000_000] };
        for (const [k, [lo, hi]] of Object.entries(ranges)) {
          if (next[k] < lo || next[k] > hi) {
            throw new RpcError(400, "23514", `new row for relation "bridge_settings" violates check constraint "bridge_settings_${k}_check"`);
          }
        }
        db.prepare(`UPDATE relay_settings SET rate_per_minute = ?, max_unread_per_sender = ?, max_bytes_per_day = ? WHERE id = 1`).run(
          next.rate_per_minute,
          next.max_unread_per_sender,
          next.max_bytes_per_day
        );
        audit.write({ outcome: "ok", action: "admin.set_limits", ...next });
        return next;
      },
    },
    bridge_admin_purge: {
      admin: true,
      args: { p_older_than: ["interval"] },
      run: (_, a) => {
        const ms = a.p_older_than ?? 30 * DAY;
        if (config.legalHold) throw policyError("Legal hold is active: messages can't be purged.");
        if (ms < minRetentionMs) {
          throw policyError(
            `Retention policy: messages must be kept for at least ${config.minRetentionDays} day(s); purge only messages older than that.`
          );
        }
        const cutoff = new Date(Date.now() - ms).toISOString();
        const n = Number(db.prepare(`DELETE FROM messages WHERE created_at < ?`).run(cutoff).changes);
        audit.write({ outcome: "ok", action: "admin.purge", older_than_ms: ms, messages: n });
        return n;
      },
    },
    // ---- auditor (the apikey header must be the auditor key; nothing else works for it)
    // Messages in a time range, oldest first. Page with p_after_id. Does not mark anything read.
    bridge_admin_export: {
      auditor: true,
      args: { p_from: ["timestamp"], p_to: ["timestamp"], p_after_id: ["bigint"], p_limit: ["int"] },
      run: (_, a, raw) => {
        const rows = db
          .prepare(
            `SELECT * FROM messages
              WHERE id > ? AND (? IS NULL OR created_at >= ?) AND (? IS NULL OR created_at < ?)
              ORDER BY id LIMIT ?`
          )
          .all(Math.max(a.p_after_id ?? 0, 0), a.p_from, a.p_from, a.p_to, a.p_to, clamp(a.p_limit ?? 1000, 1, 10000))
          .map((r) => ({ ...r }));
        // `from_raw` / `to_raw` keep the text the auditor typed next to the instant it was understood as
        audit.write({
          action: "auditor.export",
          outcome: "ok",
          from: a.p_from,
          to: a.p_to,
          ...(raw?.p_from != null ? { from_raw: String(raw.p_from).slice(0, 100) } : {}),
          ...(raw?.p_to != null ? { to_raw: String(raw.p_to).slice(0, 100) } : {}),
          after_id: a.p_after_id ?? 0,
          count: rows.length,
        });
        return rows;
      },
    },
  };

  // ---------------------------------------------------------------- HTTP

  const send = (res, status, body) => {
    const headers = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };
    if (status === 204) {
      res.writeHead(204, headers).end();
      return;
    }
    const text = JSON.stringify(body);
    res.writeHead(status, { ...headers, "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text) }).end(text);
  };
  const sendError = (res, status, code, message, extra = {}) =>
    send(res, status, { code, message, details: extra.details ?? null, hint: extra.hint ?? null });

  // Reads the body up to the limit. Resolves null (after answering 413) when it is too large.
  const readBody = (req, res) =>
    new Promise((resolve) => {
      let done = false;
      const tooLarge = () => {
        done = true;
        sendError(res, 413, "PGRST413", `Request body too large (limit ${MAX_BODY_BYTES} bytes)`);
        // keep discarding input so the client can finish its upload and read the answer, but not forever
        req.on("data", () => {});
        const t = setTimeout(() => req.destroy(), 5000);
        t.unref();
        req.on("close", () => clearTimeout(t));
        resolve(null);
      };
      if (Number(req.headers["content-length"]) > MAX_BODY_BYTES) return tooLarge();
      const chunks = [];
      let size = 0;
      req.on("data", (c) => {
        if (done) return;
        size += c.length;
        if (size > MAX_BODY_BYTES) {
          chunks.length = 0;
          return tooLarge();
        }
        chunks.push(c);
      });
      req.on("end", () => {
        if (!done) resolve(Buffer.concat(chunks).toString("utf8"));
      });
      req.on("error", () => {
        if (!done) resolve(null);
      });
    });

  const keyMatches = (apikey, digest) => !!digest && typeof apikey === "string" && timingSafeEqual(sha256(apikey), digest);

  async function handle(req, res) {
    const path = (req.url || "").split("?")[0];
    if (path === "/healthz") {
      if (req.method !== "GET" && req.method !== "HEAD") return sendError(res, 405, "PGRST117", "Unsupported HTTP method");
      // a failing audit log is a failing service: say so (and try to recover, so a freed disk shows up here)
      if (audit.failed) {
        try {
          audit.ensureWritable();
        } catch {
          return send(res, 503, { status: "audit log failing" });
        }
      }
      return send(res, 200, { status: "ok" });
    }
    const m = path.match(/^\/rest\/v1\/rpc\/([A-Za-z0-9_]{1,100})$/);
    if (!m) return sendError(res, 404, "PGRST125", "Invalid path specified in request URL");
    if (req.method !== "POST") return sendError(res, 405, "PGRST117", `Unsupported HTTP method: ${String(req.method).slice(0, 20)}`);

    const raw = await readBody(req, res);
    if (raw === null) return;
    let body = {};
    if (raw.trim()) {
      try {
        body = JSON.parse(raw);
      } catch {
        return sendError(res, 400, "PGRST102", "Empty or invalid json");
      }
      if (body === null || typeof body !== "object" || Array.isArray(body)) {
        return sendError(res, 400, "PGRST102", "Request body must be a JSON object of named arguments");
      }
    }

    // Resolve like PostgREST's schema cache: known function, every given arg is a parameter,
    // every parameter without a default is given.
    const fnName = m[1];
    const fn = Object.hasOwn(FUNCTIONS, fnName) ? FUNCTIONS[fnName] : null;
    const keys = Object.keys(body);
    const resolved =
      fn &&
      keys.every((k) => Object.hasOwn(fn.args, k)) &&
      Object.entries(fn.args).every(([k, [, required]]) => !required || keys.includes(k));
    if (!resolved) {
      return sendError(res, 404, "PGRST202", `Could not find the function public.${fnName}(${keys.join(", ").slice(0, 300)}) in the schema cache`, {
        hint: "No function matches the given name and argument names.",
      });
    }
    const ip = req.socket.remoteAddress;

    // Each privileged function accepts exactly one key: admin functions the admin key, export the auditor key.
    const privileged = fn.auditor || fn.admin;
    if (privileged && !keyMatches(req.headers.apikey, fn.auditor ? auditorDigest : adminDigest)) {
      authFails.record(fn.auditor ? "auditor" : "admin", fnName, ip);
      return sendError(res, 401, "42501", `permission denied for function ${fnName}`);
    }
    const args = {};
    try {
      for (const [k, [type]] of Object.entries(fn.args)) args[k] = COERCE[type](Object.hasOwn(body, k) ? body[k] : null);
      let me = null;
      if (!privileged) {
        try {
          me = authenticate(args.p_token);
        } catch (e) {
          authFails.record("agent", fnName, ip);
          throw e;
        }
      }
      if (audit.required) {
        audit.ensureWritable(); // no audit, no service
        // a change that can't be taken back is written down first
        if (fn.admin) audit.write({ action: `admin.${fnName.slice("bridge_admin_".length)}`, outcome: "attempt", ...(args.p_name != null ? { agent: args.p_name } : {}) });
      }
      const out = await fn.run(me, args, body);
      if (fn.void) return send(res, 204);
      return send(res, 200, out === undefined ? null : out);
    } catch (e) {
      // admin attempts are audited whether they worked or not (refused ones say why), whatever went wrong
      if (fn.admin && !fn.auditor && !(e instanceof AuditError)) {
        audit.write(
          {
            action: `admin.${fnName.slice("bridge_admin_".length)}`,
            outcome: e instanceof RpcError && e.refused ? "refused" : "failed",
            ...(args.p_name != null ? { agent: args.p_name } : {}),
            reason: e instanceof RpcError || e instanceof BridgeError ? e.message : "internal error",
          },
          { strict: false }
        );
      }
      if (e instanceof AuditError) {
        console.error(`relay: ${fnName} refused: ${e.message}`);
        return sendError(res, 503, "55000", "audit log unavailable: the request was refused (RELAY_AUDIT_REQUIRED)", { hint: "Retry once the relay's audit log is writable again." });
      }
      if (e instanceof RpcError) return sendError(res, e.status, e.code, e.message, { details: e.details, hint: e.hint });
      if (e instanceof BridgeError) return sendError(res, 400, "P0001", e.message); // rules from SqliteStore
      if (/database is locked|SQLITE_BUSY/i.test(String(e?.message))) return sendError(res, 503, "55P03", "database busy, retry");
      // never a stack trace or SQL text on the wire; the log gets a short message only
      console.error(`relay: internal error in ${fnName}: ${String(e?.message).slice(0, 300)}`);
      return sendError(res, 500, "XX000", "internal error");
    }
  }

  const wrap = (req, res) => {
    handle(req, res).catch((e) => {
      console.error(`relay: unhandled error: ${String(e?.message).slice(0, 300)}`);
      if (!res.headersSent) sendError(res, 500, "XX000", "internal error");
      else res.end();
    });
  };
  // Timeouts and a connection cap, so a client that connects and says nothing (or drips a header byte at a time)
  // can't hold the relay's file descriptors for ever (R2-15). `timeout` closes any socket that is silent for
  // that long, including one that never finished the TLS handshake; the header/request timeouts cover a
  // client that keeps sending slowly; connectionsCheckingInterval is how often Node enforces those two.
  const httpOptions = {
    headersTimeout: lim.headersTimeoutMs,
    requestTimeout: lim.requestTimeoutMs,
    keepAliveTimeout: lim.keepAliveTimeoutMs,
    connectionsCheckingInterval: Math.max(250, Math.min(2000, Math.floor(lim.headersTimeoutMs / 2))),
  };
  const server = config.tls
    ? https.createServer({ ...config.tls, minVersion: "TLSv1.2", handshakeTimeout: lim.idleTimeoutMs, ...httpOptions }, wrap)
    : http.createServer(httpOptions, wrap);
  server.on("tlsClientError", () => {}); // failed handshakes (no/untrusted client certificate) are just dropped
  server.timeout = lim.idleTimeoutMs; // no 'timeout' listener: Node destroys the socket
  server.maxConnections = lim.maxConnections;
  server.maxHeadersCount = 50;

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.port, config.host, resolve);
  });
  const { port } = server.address();
  return {
    server,
    audit,
    core,
    port,
    url: `${config.tls ? "https" : "http"}://${config.host}:${port}`,
    close: async () => {
      await new Promise((r) => {
        server.close(r);
        server.closeAllConnections?.();
      });
      authFails.close();
      audit.close();
      try {
        core.db.close();
      } catch {
        // already closed
      }
    },
  };
}

// ------------------------------------------------------------------ entry point

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  let relay;
  try {
    const config = loadConfig(process.env, process.argv.slice(2));
    relay = await startRelay(config);
    if (!["127.0.0.1", "::1", "localhost"].includes(config.host) && !config.tls) {
      console.error("relay: WARNING: listening on a non-loopback address without TLS; tokens cross the network in clear text.");
    }
    console.log(`relay: security posture: ${describePosture(config)}`);
    console.log(
      `agent-bridge relay listening on ${relay.url} (db ${config.dbPath}${config.auditLog ? ", audit log " + config.auditLog : ""})`
    );
  } catch (e) {
    console.error(`relay: ${e.message}`);
    process.exit(1);
  }
  const stop = () => relay.close().finally(() => process.exit(0));
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}
