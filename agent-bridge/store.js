// SQLite-backed mailbox shared by every agent that points at the same DB file.
// Uses Node's built-in node:sqlite (Node >= 22.13), so there is nothing native to compile.

import { mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";
import { randomUUID } from "node:crypto";

// node:sqlite prints an "experimental" warning on load; keep stdout/stderr clean.
const originalEmitWarning = process.emitWarning;
process.emitWarning = (warning, ...args) => {
  if (String(warning).includes("SQLite")) return;
  return originalEmitWarning.call(process, warning, ...args);
};
const { DatabaseSync } = await import("node:sqlite");

export const MESSAGE_TYPES = ["request", "response", "fyi"];

export function resolveDbPath(p = process.env.AGENT_BRIDGE_DB) {
  const raw = p && p.trim() ? p.trim() : "~/.agent-bridge/bridge.db";
  return resolve(raw.startsWith("~") ? homedir() + raw.slice(1) : raw);
}

export class BridgeStore {
  constructor(dbPath = resolveDbPath()) {
    this.dbPath = dbPath;
    mkdirSync(dirname(dbPath), { recursive: true });
    this.db = new DatabaseSync(dbPath);
    // WAL + busy timeout so two agent processes can read/write concurrently.
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA busy_timeout = 5000;
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
        read_at     TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_inbox  ON messages (to_agent, read_at);
      CREATE INDEX IF NOT EXISTS idx_thread ON messages (thread_id, id);
    `);
  }

  now() {
    return new Date().toISOString();
  }

  heartbeat(name, { description = null, projectDir = null } = {}) {
    this.db
      .prepare(
        `INSERT INTO agents (name, description, project_dir, last_seen)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(name) DO UPDATE SET
           description = COALESCE(excluded.description, agents.description),
           project_dir = COALESCE(excluded.project_dir, agents.project_dir),
           last_seen   = excluded.last_seen`
      )
      .run(name, description, projectDir, this.now());
  }

  listAgents() {
    return this.db
      .prepare(`SELECT name, description, project_dir, last_seen FROM agents ORDER BY name`)
      .all();
  }

  send({ from, to, body, subject = null, threadId = null, type = "fyi", maxHops = 20 }) {
    if (!MESSAGE_TYPES.includes(type)) throw new Error(`type must be one of ${MESSAGE_TYPES.join(", ")}`);
    if (from === to) throw new Error("An agent cannot message itself.");
    const thread = threadId || randomUUID();
    const { n } = this.db
      .prepare(`SELECT COUNT(*) AS n FROM messages WHERE thread_id = ?`)
      .get(thread);
    if (threadId && n === 0) throw new Error(`Unknown thread_id ${threadId}. Omit it to start a new thread.`);
    const hop = n + 1;
    if (hop > maxHops) {
      throw new Error(
        `Thread ${thread} hit the ${maxHops}-message limit (loop protection). ` +
          `Ask a human before continuing, or start a new thread with a summary.`
      );
    }
    const info = this.db
      .prepare(
        `INSERT INTO messages (thread_id, from_agent, to_agent, type, subject, body, hop, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(thread, from, to, type, subject, body, hop, this.now());
    return this.getMessage(Number(info.lastInsertRowid));
  }

  getMessage(id) {
    return this.db.prepare(`SELECT * FROM messages WHERE id = ?`).get(id);
  }

  unreadCount(agent) {
    return this.db
      .prepare(`SELECT COUNT(*) AS n FROM messages WHERE to_agent = ? AND read_at IS NULL`)
      .get(agent).n;
  }

  unreadSummary(agent) {
    return this.db
      .prepare(
        `SELECT from_agent, COUNT(*) AS n FROM messages
         WHERE to_agent = ? AND read_at IS NULL GROUP BY from_agent`
      )
      .all(agent);
  }

  // Returns unread messages for `agent` (oldest first) and optionally marks them read.
  inbox(agent, { markRead = true, limit = 20, threadId = null } = {}) {
    const rows = threadId
      ? this.db
          .prepare(
            `SELECT * FROM messages WHERE to_agent = ? AND read_at IS NULL AND thread_id = ?
             ORDER BY id LIMIT ?`
          )
          .all(agent, threadId, limit)
      : this.db
          .prepare(`SELECT * FROM messages WHERE to_agent = ? AND read_at IS NULL ORDER BY id LIMIT ?`)
          .all(agent, limit);
    if (markRead && rows.length) {
      const mark = this.db.prepare(`UPDATE messages SET read_at = ? WHERE id = ?`);
      const ts = this.now();
      for (const r of rows) mark.run(ts, r.id);
    }
    return rows;
  }

  thread(threadId) {
    return this.db.prepare(`SELECT * FROM messages WHERE thread_id = ? ORDER BY id`).all(threadId);
  }

  recent(limit = 50) {
    return this.db.prepare(`SELECT * FROM messages ORDER BY id DESC LIMIT ?`).all(limit).reverse();
  }

  close() {
    this.db.close();
  }
}
