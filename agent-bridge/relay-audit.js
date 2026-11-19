// Tamper-evident audit log for relay.js: JSON Lines where every line carries
//   prev  SHA-256 (hex) of the previous line's exact text (64 zeros for the first line)
//   hash  SHA-256 (hex) of this line's JSON without the `hash` field (so `prev` is covered)
// Editing, deleting or reordering a line breaks the chain at the first affected line.
// Cutting lines off the END of the file is only detectable against a hash recorded elsewhere:
// `verify-audit` prints the final hash for that purpose.

import { closeSync, constants, fchmodSync, fstatSync, openSync, readFileSync, writeSync } from "node:fs";
import { createHash } from "node:crypto";

export const GENESIS = "0".repeat(64);
const sha256hex = (s) => createHash("sha256").update(s, "utf8").digest("hex");

// The text that `hash` covers: the entry with `hash` removed, key order as written.
const hashOf = (entry) => {
  const { hash: _drop, ...rest } = entry;
  return sha256hex(JSON.stringify(rest));
};

export class AuditLog {
  constructor(path, withBodies = false) {
    this.withBodies = withBodies;
    this.fd = null;
    this.last = GENESIS;
    if (!path) return;
    // continue the chain of an existing file
    try {
      const lines = readFileSync(path, "utf8").split("\n").filter(Boolean);
      if (lines.length) this.last = sha256hex(lines[lines.length - 1]);
    } catch (e) {
      if (e.code !== "ENOENT") throw e;
    }
    this.fd = openSync(path, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT, 0o600);
    if ((fstatSync(this.fd).mode & 0o077) !== 0) fchmodSync(this.fd, 0o600);
  }

  write(entry) {
    if (this.fd == null) return;
    const body = { ts: new Date().toISOString(), ...entry, prev: this.last };
    const line = JSON.stringify({ ...body, hash: hashOf(body) });
    try {
      writeSync(this.fd, line + "\n");
      this.last = sha256hex(line);
    } catch (e) {
      console.error(`relay: audit log write failed: ${e.code || e.message}`);
    }
  }

  // A message event: fingerprints of the body, the body itself only when asked for.
  message(action, agent, m) {
    this.write({
      action,
      agent,
      id: m.id,
      thread_id: m.thread_id,
      from: m.from_agent,
      to: m.to_agent,
      type: m.type,
      bytes: Buffer.byteLength(m.body),
      sha256: sha256hex(m.body),
      ...(this.withBodies ? { body: m.body } : {}),
    });
  }

  close() {
    if (this.fd != null) closeSync(this.fd);
    this.fd = null;
  }
}

// Returns { ok: true, lines, last } or { ok: false, line, reason }.
export function verifyAuditLog(path) {
  const text = readFileSync(path, "utf8");
  const lines = text.split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  let prev = GENESIS;
  for (let i = 0; i < lines.length; i++) {
    const n = i + 1;
    let entry;
    try {
      entry = JSON.parse(lines[i]);
    } catch {
      return { ok: false, line: n, reason: "not valid JSON" };
    }
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return { ok: false, line: n, reason: "not a JSON object" };
    if (entry.prev !== prev) return { ok: false, line: n, reason: "previous-line hash does not match (a line was removed, added or reordered before this one)" };
    if (entry.hash !== hashOf(entry)) return { ok: false, line: n, reason: "line content does not match its hash (edited)" };
    prev = sha256hex(lines[i]);
  }
  return { ok: true, lines: lines.length, last: prev };
}
