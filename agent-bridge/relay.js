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
import { AuditLog } from "./relay-audit.js";

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

// Flags override env. The admin key is deliberately not a flag (it would show up in `ps`).
export function loadConfig(env = process.env, argv = []) {
  const e = { ...env };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--audit-bodies") {
      e.RELAY_AUDIT_BODIES = "1";
      continue;
    }
    if (argv[i] === "--legal-hold") {
      e.RELAY_LEGAL_HOLD = "1";
      continue;
    }
    const name = FLAGS[argv[i]];
    if (!name) throw new RelayConfigError(`unknown option ${argv[i]} (see relay/README.md)`);
    if (argv[i + 1] == null || argv[i + 1].startsWith("--")) throw new RelayConfigError(`${argv[i]} needs a value`);
    e[name] = argv[++i];
  }
  // a flag naming the key file wins over a key in the environment
  if (argv.includes("--admin-key-file")) delete e.RELAY_ADMIN_KEY;

  const readKey = (name, what) => {
    let k = (e[name] || "").trim();
    if (!k && e[`${name}_FILE`]) {
      const p = expandHome(e[`${name}_FILE`].trim());
      try {
        k = readFileSync(p, "utf8").trim();
      } catch (err) {
        throw new RelayConfigError(`can't read ${name}_FILE ${p}: ${err.code || err.message}`);
      }
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
    try {
      tls = { cert: readFileSync(expandHome(cert)), key: readFileSync(expandHome(key)) };
      // mutual TLS: only clients holding a certificate signed by this CA complete the handshake
      if (caPath) Object.assign(tls, { ca: readFileSync(expandHome(caPath)), requestCert: true, rejectUnauthorized: true });
    } catch (err) {
      throw new RelayConfigError(`can't read the TLS certificate, key or CA: ${err.code || err.message}`);
    }
  }

  return {
    adminKey,
    auditorKey,
    minRetentionDays,
    legalHold: e.RELAY_LEGAL_HOLD === "1",
    host: (e.RELAY_HOST || "127.0.0.1").trim(),
    port,
    dbPath: expandHome((e.RELAY_DB || "").trim() || "~/.agent-bridge/relay.db"),
    tls,
    auditLog: e.RELAY_AUDIT_LOG?.trim() ? expandHome(e.RELAY_AUDIT_LOG.trim()) : null,
    auditBodies: e.RELAY_AUDIT_BODIES === "1",
  };
}

// ------------------------------------------------------------------ argument coercion (what Postgres would do)

const INT_MAX = 2147483647;
const typeError = (type, v) => new RpcError(400, "22P02", `invalid input syntax for type ${type}: ${JSON.stringify(v).slice(0, 100)}`);

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
  timestamp(v) {
    if (v == null) return null;
    const t = typeof v === "string" && /^\d{4}-\d{2}-\d{2}/.test(v) ? Date.parse(v) : NaN;
    if (Number.isNaN(t)) throw new RpcError(400, "22007", `invalid input syntax for type timestamp with time zone: ${JSON.stringify(v).slice(0, 100)}`);
    return new Date(t).toISOString();
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
    if (!m) throw new RpcError(400, "22007", `invalid input syntax for type interval: ${JSON.stringify(v).slice(0, 100)}`);
    const u = m[2].toLowerCase();
    const unit = u.startsWith("s") ? 1000 : u.startsWith("mi") ? MINUTE : u.startsWith("h") ? 60 * MINUTE : u.startsWith("d") ? 24 * 60 * MINUTE : 7 * 24 * 60 * MINUTE;
    return Number(m[1]) * unit;
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

export async function startRelay(config) {
  const audit = new AuditLog(config.auditLog, config.auditBodies);
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
        audit.message("send", me, row);
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
        if (markRead) for (const m of rows) audit.message("deliver", me, m);
        else audit.write({ action: "peek", agent: me, count: rows.length });
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
        audit.write({ action: "thread", agent: me, thread_id: a.p_thread_id, count: rows.length });
        return rows;
      },
    },
    bridge_recent: {
      args: { p_token: ["text", true], p_limit: ["int"], p_after_id: ["bigint"] },
      run: (me, a) => storeFor(me).recent({ limit: clamp(a.p_limit ?? 20, 1, 200), afterId: Math.max(a.p_after_id ?? 0, 0) }),
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
      run: (_, a) => {
        const rows = db
          .prepare(
            `SELECT * FROM messages
              WHERE id > ? AND (? IS NULL OR created_at >= ?) AND (? IS NULL OR created_at < ?)
              ORDER BY id LIMIT ?`
          )
          .all(Math.max(a.p_after_id ?? 0, 0), a.p_from, a.p_from, a.p_to, a.p_to, clamp(a.p_limit ?? 1000, 1, 10000))
          .map((r) => ({ ...r }));
        audit.write({ action: "auditor.export", outcome: "ok", from: a.p_from, to: a.p_to, after_id: a.p_after_id ?? 0, count: rows.length });
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
      audit.write({ action: "auth_failed", scope: fn.auditor ? "auditor" : "admin", fn: fnName, ip });
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
          audit.write({ action: "auth_failed", scope: "agent", fn: fnName, ip });
          throw e;
        }
      }
      const out = await fn.run(me, args);
      if (fn.void) return send(res, 204);
      return send(res, 200, out === undefined ? null : out);
    } catch (e) {
      // admin attempts are audited whether they worked or not (refused ones say why)
      if (fn.admin && !fn.auditor && e instanceof RpcError) {
        audit.write({
          action: `admin.${fnName.slice("bridge_admin_".length)}`,
          outcome: e.refused ? "refused" : "failed",
          ...(args.p_name != null ? { agent: args.p_name } : {}),
          reason: e.message,
        });
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
  const server = config.tls ? https.createServer({ ...config.tls, minVersion: "TLSv1.2" }, wrap) : http.createServer(wrap);
  server.on("tlsClientError", () => {}); // failed handshakes (no/untrusted client certificate) are just dropped
  server.requestTimeout = 30_000;
  server.headersTimeout = 15_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 50;

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.port, config.host, resolve);
  });
  const { port } = server.address();
  return {
    server,
    port,
    url: `${config.tls ? "https" : "http"}://${config.host}:${port}`,
    close: async () => {
      await new Promise((r) => {
        server.close(r);
        server.closeAllConnections?.();
      });
      audit.close();
      core.db.close();
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
