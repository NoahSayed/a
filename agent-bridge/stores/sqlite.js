// Local backend: a SQLite file shared by every agent on the same machine.
// Uses Node's built-in node:sqlite (Node >= 22.13), so there is nothing native to compile.

import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import { BridgeError, LIMITS, MESSAGE_TYPES, isUuid, validateOutgoing } from "./common.js";

// node:sqlite prints an "experimental" warning on load; keep stdout/stderr clean.
const originalEmitWarning = process.emitWarning;
process.emitWarning = (warning, ...args) => {
  if (String(warning).includes("SQLite")) return;
  return originalEmitWarning.call(process, warning, ...args);
};
const { DatabaseSync } = await import("node:sqlite");

export class SqliteStore {
  constructor({ agentName, dbPath }) {
    this.agent = agentName;
    this.dbPath = dbPath;
    this.pollIntervalMs = 1000;
    mkdirSync(dirname(dbPath), { recursive: true });
    // The busy timeout must be in place before ANY statement (including the WAL switch),
    // otherwise agents that start at the same moment fail with "database is locked".
    this.db = new DatabaseSync(dbPath, { timeout: 10000 });
    this.db.exec("PRAGMA busy_timeout = 10000");
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
        UNIQUE (thread_id, hop)
      );
      CREATE INDEX IF NOT EXISTS idx_inbox  ON messages (to_agent, read_at);
      CREATE INDEX IF NOT EXISTS idx_thread ON messages (thread_id, id);
    `);
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

  async send({ to, body, type = "request", subject = null, threadId = null, maxHops = 20 }) {
    validateOutgoing({ from: this.agent, to, body, type, subject, threadId });
    const max = Math.min(Math.max(Number(maxHops) || 20, 1), LIMITS.maxHopsCap);
    const row = this.tx(() => {
      let thread = threadId;
      let n = 0;
      if (!thread) {
        thread = randomUUID();
      } else {
        const mine = this.db
          .prepare(`SELECT 1 FROM messages WHERE thread_id = ? AND (from_agent = ? OR to_agent = ?) LIMIT 1`)
          .get(thread, this.agent, this.agent);
        if (!mine) throw new BridgeError(`Unknown thread_id ${thread}. Omit it to start a new thread.`);
        n = this.db.prepare(`SELECT COUNT(*) AS n FROM messages WHERE thread_id = ?`).get(thread).n;
      }
      if (n + 1 > max) {
        throw new BridgeError(
          `Thread ${thread} hit the ${max}-message limit (loop protection). ` +
            `Ask a human before continuing, or start a new thread with a summary.`
        );
      }
      const info = this.db
        .prepare(
          `INSERT INTO messages (thread_id, from_agent, to_agent, type, subject, body, hop, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(thread, this.agent, to, type, subject, body, n + 1, this.now());
      return this.db.prepare(`SELECT * FROM messages WHERE id = ?`).get(Number(info.lastInsertRowid));
    });
    return { ...row };
  }

  async inbox({ limit = 20, markRead = true, threadId = null } = {}) {
    if (threadId != null && !isUuid(threadId)) throw new BridgeError(`Unknown thread_id ${threadId}.`);
    const lim = Math.min(Math.max(Number(limit) || 20, 1), 100);
    const select = () =>
      (threadId
        ? this.db
            .prepare(
              `SELECT * FROM messages WHERE to_agent = ? AND read_at IS NULL AND thread_id = ? ORDER BY id LIMIT ?`
            )
            .all(this.agent, threadId, lim)
        : this.db
            .prepare(`SELECT * FROM messages WHERE to_agent = ? AND read_at IS NULL ORDER BY id LIMIT ?`)
            .all(this.agent, lim)
      ).map((r) => ({ ...r }));
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
