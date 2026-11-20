// Tamper-evident audit log for relay.js: JSON Lines where every line carries
//   prev  SHA-256 (hex) of the previous line's exact text (64 zeros for the first line)
//   hash  SHA-256 (hex) of this line's JSON without the `hash` field (so `prev` is covered)
// Editing, deleting or reordering a line breaks the chain at the first affected line.
// Cutting lines off the END of the file is only detectable against a hash recorded elsewhere:
// `verify-audit` prints the final hash for that purpose.
//
// A torn write (disk full, crash) leaves a partial line. The writer never appends to it: it ends the
// partial line with a newline and records a `chain.repair` entry whose `prev` is the hash of the junk
// and whose `after` is the hash of the last good line before it, so the chain continues and the
// verifier accepts exactly that junk (and nothing else) as long as the repair entry follows it.

import { closeSync, constants, fchmodSync, fstatSync, openSync, readFileSync, writeSync } from "node:fs";
import { createHash } from "node:crypto";

export const GENESIS = "0".repeat(64);
const sha256hex = (s) => createHash("sha256").update(s, "utf8").digest("hex");

// The text that `hash` covers: the entry with `hash` removed, key order as written.
const hashOf = (entry) => {
  const { hash: _drop, ...rest } = entry;
  return sha256hex(JSON.stringify(rest));
};

// A line that looks like one of our entries (as opposed to junk left by a torn write).
const parseEntry = (line) => {
  try {
    const e = JSON.parse(line);
    return e !== null && typeof e === "object" && !Array.isArray(e) ? e : null;
  } catch {
    return null;
  }
};
const looksLikeEntry = (line) => {
  const e = parseEntry(line);
  return !!e && typeof e.prev === "string" && typeof e.hash === "string";
};

// Thrown by AuditLog.write when the log is required (fail closed) and the line could not be written.
export class AuditError extends Error {}

// fs.writeSync can write less than asked; keep going until everything is out, or throw.
const writeAll = (fd, text) => {
  const buf = Buffer.from(text, "utf8");
  let off = 0;
  while (off < buf.length) {
    const n = writeSync(fd, buf, off, buf.length - off);
    if (!n) throw Object.assign(new Error("short write"), { code: "EIO" });
    off += n;
  }
};

export class AuditLog {
  // options.required: a write that fails throws AuditError instead of only being logged
  constructor(path, withBodies = false, { required = false } = {}) {
    this.withBodies = withBodies;
    this.required = required;
    this.path = path || null;
    this.fd = null;
    this.last = GENESIS; // `prev` of the next entry
    this.failed = false; // the last write failed (cleared by the next success)
    this.failures = 0;
    this.torn = null; // { after, junkHash, unterminated }: junk at the end of the file that needs a repair entry
    this.size = 0; // bytes we know are in the file
    this.writer = writeAll; // replaceable (tests simulate a full disk)
    if (!path) return;
    // continue the chain of an existing file
    let text = "";
    try {
      text = readFileSync(path, "utf8");
    } catch (e) {
      if (e.code !== "ENOENT") throw e;
    }
    this.#scan(text);
    this.fd = openSync(path, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT, 0o600);
    const st = fstatSync(this.fd);
    if (st.isFile() && (st.mode & 0o077) !== 0) fchmodSync(this.fd, 0o600);
    this.size = st.isFile() ? st.size : 0;
    if (this.torn) {
      try {
        this.#seal();
      } catch (e) {
        this.#failed(e, false); // the next write tries again
      }
    }
  }

  // Finds the chain position at the end of the file, and any junk after the last good line.
  #scan(text) {
    if (!text) return;
    const terminated = text.endsWith("\n");
    const lines = text.split("\n");
    if (terminated) lines.pop();
    let i = lines.length - 1;
    while (i >= 0 && !looksLikeEntry(lines[i])) i--;
    const after = i >= 0 ? sha256hex(lines[i]) : GENESIS;
    if (i === lines.length - 1) {
      this.last = after;
      return;
    }
    // junk after the last good line
    this.torn = { after, junkHash: sha256hex(lines[lines.length - 1]), unterminated: !terminated };
    this.last = after;
  }

  #line(entry, prev) {
    const body = { ts: new Date().toISOString(), ...entry, prev };
    return JSON.stringify({ ...body, hash: hashOf(body) });
  }

  // End the junk line and record the repair entry (two separate writes, so a failure can only ever leave one partial line).
  #seal() {
    const t = this.torn;
    if (t.unterminated) {
      this.writer(this.fd, "\n");
      this.size += 1;
      t.unterminated = false;
    }
    const rep = this.#line({ action: "chain.repair", reason: "torn or partial line sealed", after: t.after }, t.junkHash);
    this.writer(this.fd, rep + "\n");
    this.size += Buffer.byteLength(rep) + 1;
    this.last = sha256hex(rep);
    this.torn = null;
  }

  // After a failed write the file may hold a partial line: find out and arrange for it to be sealed.
  #resync() {
    if (this.fd == null || !this.path) return;
    const st = fstatSync(this.fd);
    if (!st.isFile() || st.size <= this.size) return;
    const partial = readFileSync(this.path).subarray(this.size).toString("utf8");
    this.size = st.size;
    if (!partial) return;
    const after = this.torn ? this.torn.after : this.last;
    const terminated = partial.endsWith("\n");
    const lastLine = partial.replace(/\n$/, "").split("\n").pop();
    this.torn = { after, junkHash: sha256hex(lastLine), unterminated: !terminated };
  }

  #failed(e, strict) {
    this.failed = true;
    this.failures++;
    console.error(`relay: audit log write failed: ${e.code || e.message}`);
    if (strict) throw new AuditError(`audit log write failed: ${e.code || e.message}`);
  }

  // Returns true when the line is in the file. A failed write is logged and returns false, or, for a
  // required log (or `strict: true`), throws AuditError.
  write(entry, { strict = this.required } = {}) {
    if (this.fd == null) return true;
    try {
      if (this.failed) this.#resync();
      if (this.torn) this.#seal();
      const line = this.#line(entry, this.last);
      this.writer(this.fd, line + "\n");
      this.size += Buffer.byteLength(line) + 1;
      this.last = sha256hex(line);
      this.failed = false;
      return true;
    } catch (e) {
      this.#failed(e, strict);
      return false;
    }
  }

  // After a failure: try to write again (a recorded `audit.recovered` line); throws AuditError if it still fails.
  ensureWritable() {
    if (this.fd == null || !this.failed) return;
    this.write({ action: "audit.recovered" }, { strict: true });
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

// Returns { ok: true, lines, last, repairs } or { ok: false, line, reason }.
export function verifyAuditLog(path) {
  const text = readFileSync(path, "utf8");
  const lines = text.split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  let prev = GENESIS; // hash of the last good line
  let junk = null; // a run of lines that are not entries: { start, reason, after, lastHash }
  let repairs = 0;
  const brokenJunk = (j, atEnd) => ({
    ok: false,
    line: j.start,
    reason: atEnd && !text.endsWith("\n") ? "incomplete last line (a torn write; the relay seals it with a repair entry when it next starts)" : j.reason,
  });
  for (let i = 0; i < lines.length; i++) {
    const n = i + 1;
    let entry;
    try {
      entry = JSON.parse(lines[i]);
    } catch {
      entry = undefined;
    }
    if (entry === undefined || entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      const reason = entry === undefined ? "not valid JSON" : "not a JSON object";
      if (junk) junk.lastHash = sha256hex(lines[i]);
      else junk = { start: n, reason, after: prev, lastHash: sha256hex(lines[i]) };
      continue;
    }
    if (junk) {
      // junk is only acceptable when the very next entry is the repair entry that covers it
      const covers = entry.action === "chain.repair" && entry.prev === junk.lastHash && entry.after === junk.after;
      if (!covers) return brokenJunk(junk, false);
      if (entry.hash !== hashOf(entry)) return { ok: false, line: n, reason: "line content does not match its hash (edited)" };
      repairs++;
      junk = null;
      prev = sha256hex(lines[i]);
      continue;
    }
    if (entry.prev !== prev) return { ok: false, line: n, reason: "previous-line hash does not match (a line was removed, added or reordered before this one)" };
    if (entry.hash !== hashOf(entry)) return { ok: false, line: n, reason: "line content does not match its hash (edited)" };
    prev = sha256hex(lines[i]);
  }
  if (junk) return brokenJunk(junk, true);
  return { ok: true, lines: lines.length, last: prev, repairs };
}
