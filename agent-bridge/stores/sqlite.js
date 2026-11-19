// Local backend: a SQLite file shared by every agent on the same machine.
// Uses Node's built-in node:sqlite (Node >= 22.13), so there is nothing native to compile.
// Behaves like the Supabase backend: same limits, same thread rules (see supabase/migration.sql).

import { chmodSync, closeSync, existsSync, mkdirSync, openSync, statSync } from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import {
  BridgeError,
  DEFAULT_ABUSE_LIMITS,
  LIMITS,
  MESSAGE_TYPES,
  isUuid,
  validateAgentName,
  validateOutgoing,
} from "./common.js";

// node:sqlite prints an "experimental" warning on load; keep stdout/stderr clean.
const originalEmitWarning = process.emitWarning;
process.emitWarning = (warning, ...args) => {
  if (String(warning).includes("SQLite")) return;
  return originalEmitWarning.call(process, warning, ...args);
};
const { DatabaseSync } = await import("node:sqlite");

const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;

export class SqliteStore {
  constructor({ agentName, dbPath, busyTimeoutMs = 10000, limits = {} }) {
    try {
      validateAgentName(agentName, "AGENT_NAME"); // R1-09
    } catch (e) {
      throw new BridgeError(e.message);
    }
    this.agent = agentName;
    this.dbPath = dbPath;
    this.pollIntervalMs = 1000;
    this.limits = { ...DEFAULT_ABUSE_LIMITS, ...limits };

    // The mailbox holds other projects' messages: keep it private to this user (R1-07).
    // Only a directory we create is chmod'ed; a directory the user chose is left alone.
    const madeDir = mkdirSync(dirname(dbPath), { recursive: true, mode: 0o700 });
    if (madeDir) chmodSync(dirname(dbPath), 0o700);
    if (!existsSync(dbPath)) closeSync(openSync(dbPath, "a", 0o600));
    const st = statSync(dbPath);
    if ((st.mode & 0o077) !== 0 && st.uid === process.getuid?.()) chmodSync(dbPath, 0o600);

    // The busy timeout must be in place before ANY statement (including the WAL switch),
    // otherwise agents that start at the same moment fail with "database is locked".
    // SQLite creates -wal/-shm with the main file's permissions.
    this.db = new DatabaseSync(dbPath, { timeout: busyTimeoutMs });
    this.db.exec(`PRAGMA busy_timeout = ${Math.max(0, Math.floor(busyTimeoutMs))}`);
    this.db.exec("PRAGMA journal_mode = WAL");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS agents (
        name        TEXT PRIMARY KEY,
        description TEXT,
        project_dir TEXT,
        last_seen   TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS messages (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        thread_id   TEXT NOT NULL,
        from_agent  TEXT NOT NULL,
        to_agent    TEXT NOT NULL,
        type        TEXT NOT NULL,
        subject     TEXT,
        body        TEXT NOT NULL,
        hop         INTEGER NOT NULL,
        created_at  TEXT NOT NULL,
        read_at     TEXT,
        max_hops    INTEGER NOT NULL DEFAULT 20,
        UNIQUE (thread_id, hop)
      );
      CREATE INDEX IF NOT EXISTS idx_inbox  ON messages (to_agent, read_at);
      CREATE INDEX IF NOT EXISTS idx_thread ON messages (thread_id, id);
      CREATE INDEX IF NOT EXISTS idx_from_time ON messages (from_agent, created_at);
    `);
    // Upgrade a mailbox created by an earlier version.
    const cols = this.db.prepare(`PRAGMA table_info(messages)`).all().map((c) => c.name);
    if (!cols.includes("max_hops")) {
      this.tx(() => {
        const again = this.db.prepare(`PRAGMA table_info(messages)`).all().map((c) => c.name);
        if (!again.includes("max_hops")) this.db.exec(`ALTER TABLE messages ADD COLUMN max_hops INTEGER NOT NULL DEFAULT 20`);
      });
    }
    for (const f of [dbPath + "-wal", dbPath + "-shm"]) {
      try {
        if ((statSync(f).mode & 0o077) !== 0) chmodSync(f, 0o600);
      } catch {}
    }
  }

  describe() {
    return `sqlite:${this.dbPath}`;
  }

  now() {
    return new Date().toISOString();
  }

  // Runs fn inside BEGIN IMMEDIATE so concurrent processes serialize their writes.
  tx(fn) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const out = fn();
      this.db.exec("COMMIT");
      return out;
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }

  async identify() {
    return this.agent;
  }

  async heartbeat({ description = null, projectDir = null } = {}) {
    this.db
      .prepare(
        `INSERT INTO agents (name, description, project_dir, last_seen)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(name) DO UPDATE SET
           description = COALESCE(excluded.description, agents.description),
           project_dir = COALESCE(excluded.project_dir, agents.project_dir),
           last_seen   = excluded.last_seen`
      )
      .run(this.agent, description, projectDir, this.now());
  }

  async whoami() {
    await this.heartbeat();
    const a = this.db.prepare(`SELECT * FROM agents WHERE name = ?`).get(this.agent);
    return {
      agent: this.agent,
      description: a?.description ?? null,
      project_dir: a?.project_dir ?? null,
      unread: this.db
        .prepare(`SELECT COUNT(*) AS n FROM messages WHERE to_agent = ? AND read_at IS NULL`)
        .get(this.agent).n,
    };
  }

  async listAgents() {
    return this.db
      .prepare(`SELECT name, description, project_dir, last_seen FROM agents ORDER BY name`)
      .all()
      .map((r) => ({ ...r }));
  }

  checkAbuseLimits(to, body) {
    const L = this.limits;
    const since = (ms) => new Date(Date.now() - ms).toISOString();
    const recent = this.db
      .prepare(`SELECT COUNT(*) AS n FROM messages WHERE from_agent = ? AND created_at > ?`)
      .get(this.agent, since(MINUTE)).n;
    if (recent >= L.ratePerMinute) {
      throw new BridgeError(
        `Rate limit: at most ${L.ratePerMinute} messages per minute per agent. Wait a moment and send fewer, longer messages.`
      );
    }
    const backlog = this.db
      .prepare(`SELECT COUNT(*) AS n FROM messages WHERE from_agent = ? AND to_agent = ? AND read_at IS NULL`)
      .get(this.agent, to).n;
    if (backlog >= L.maxUnreadPerSender) {
      throw new BridgeError(`"${to}" already has ${backlog} unread messages from you. Wait until they read them.`);
    }
    const bytes = this.db
      .prepare(`SELECT COALESCE(SUM(LENGTH(CAST(body AS BLOB))), 0) AS n FROM messages WHERE from_agent = ? AND created_at > ?`)
      .get(this.agent, since(DAY)).n;
    if (bytes + Buffer.byteLength(body) > L.maxBytesPerDay) {
      throw new BridgeError(`Daily limit: at most ${L.maxBytesPerDay} bytes of messages per agent per day.`);
    }
  }

  async send({ to, body, type = "request", subject = null, threadId = null, maxHops = 20 }) {
    validateOutgoing({ from: this.agent, to, body, type, subject, threadId });
    const row = this.tx(() => {
      this.checkAbuseLimits(to, body);
      let thread = threadId;
      let hop = 1;
      let max = Math.min(Math.max(Number(maxHops) || 20, 1), LIMITS.maxHopsCap);
      if (!thread) {
        thread = randomUUID();
      } else {
        const inThread = (who) =>
          this.db
            .prepare(`SELECT 1 FROM messages WHERE thread_id = ? AND (from_agent = ? OR to_agent = ?) LIMIT 1`)
            .get(thread, who, who);
        if (!inThread(this.agent)) throw new BridgeError(`Unknown thread_id ${thread}. Omit it to start a new thread.`);
        // replies stay between the thread's participants (R1-02)
        if (!inThread(to)) throw new BridgeError(`"${to}" is not part of this thread. Start a new thread to include them.`);
        // max(hop) and the thread's own cap (R1-01, R1-10)
        const last = this.db
          .prepare(`SELECT hop, max_hops FROM messages WHERE thread_id = ? ORDER BY hop DESC LIMIT 1`)
          .get(thread);
        hop = last.hop + 1;
        max = last.max_hops;
      }
      if (hop > max) {
        throw new BridgeError(
          `Thread ${thread} hit the ${max}-message limit (loop protection). ` +
            `Ask a human before continuing, or start a new thread with a summary.`
        );
      }
      const info = this.db
        .prepare(
          `INSERT INTO messages (thread_id, from_agent, to_agent, type, subject, body, hop, created_at, max_hops)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(thread, this.agent, to, type, subject, body, hop, this.now(), max);
      return this.db.prepare(`SELECT * FROM messages WHERE id = ?`).get(Number(info.lastInsertRowid));
    });
    return { ...row };
  }

  async inbox({ limit = 20, markRead = true, threadId = null, fromAgent = null } = {}) {
    if (threadId != null && !isUuid(threadId)) throw new BridgeError(`Unknown thread_id ${threadId}.`);
    if (fromAgent != null) validateAgentName(fromAgent);
    const lim = Math.min(Math.max(Number(limit) || 20, 1), 100);
    const select = () =>
      this.db
        .prepare(
          `SELECT * FROM messages
            WHERE to_agent = ? AND read_at IS NULL
              AND (? IS NULL OR thread_id = ?)
              AND (? IS NULL OR from_agent = ?)
            ORDER BY id LIMIT ?`
        )
        .all(this.agent, threadId, threadId, fromAgent, fromAgent, lim)
        .map((r) => ({ ...r }));
    if (!markRead) return select();
    // Claim inside a write transaction so two readers never get the same message.
    return this.tx(() => {
      const rows = select();
      const ts = this.now();
      const mark = this.db.prepare(`UPDATE messages SET read_at = ? WHERE id = ?`);
      for (const r of rows) {
        mark.run(ts, r.id);
        r.read_at = ts;
      }
      return rows;
    });
  }

  // Puts claimed messages back as unread when they couldn't be delivered (R1-05).
  async unmark(ids) {
    if (!ids?.length) return 0;
    const stmt = this.db.prepare(`UPDATE messages SET read_at = NULL WHERE id = ? AND to_agent = ? AND read_at IS NOT NULL`);
    return this.tx(() => ids.reduce((n, id) => n + Number(stmt.run(id, this.agent).changes), 0));
  }

  async unreadSummary() {
    return this.db
      .prepare(
        `SELECT from_agent, COUNT(*) AS n FROM messages
         WHERE to_agent = ? AND read_at IS NULL GROUP BY from_agent ORDER BY from_agent`
      )
      .all(this.agent)
      .map((r) => ({ ...r }));
  }

  async thread(threadId) {
    if (!isUuid(threadId)) throw new BridgeError(`Unknown thread_id ${threadId}.`);
    const rows = this.db.prepare(`SELECT * FROM messages WHERE thread_id = ? ORDER BY id`).all(threadId);
    if (!rows.some((r) => r.from_agent === this.agent || r.to_agent === this.agent)) {
      throw new BridgeError(`Unknown thread_id ${threadId}.`);
    }
    return rows.map((r) => ({ ...r }));
  }

  // Messages this agent sent or received. afterId > 0: newer than that id, ascending.
  async recent({ limit = 20, afterId = 0 } = {}) {
    const lim = Math.min(Math.max(Number(limit) || 20, 1), 200);
    const rows =
      afterId > 0
        ? this.db
            .prepare(
              `SELECT * FROM messages WHERE id > ? AND (from_agent = ? OR to_agent = ?) ORDER BY id LIMIT ?`
            )
            .all(afterId, this.agent, this.agent, lim)
        : this.db
            .prepare(
              `SELECT * FROM messages WHERE from_agent = ? OR to_agent = ? ORDER BY id DESC LIMIT ?`
            )
            .all(this.agent, this.agent, lim)
            .reverse();
    return rows.map((r) => ({ ...r }));
  }

  // Local-only: every message on the bridge, for humans watching from the CLI.
  allRecent({ limit = 20, afterId = 0 } = {}) {
    const rows =
      afterId > 0
        ? this.db.prepare(`SELECT * FROM messages WHERE id > ? ORDER BY id LIMIT ?`).all(afterId, limit)
        : this.db.prepare(`SELECT * FROM messages ORDER BY id DESC LIMIT ?`).all(limit).reverse();
    return rows.map((r) => ({ ...r }));
  }

  async close() {
    this.db.close();
  }
}

export { MESSAGE_TYPES };
