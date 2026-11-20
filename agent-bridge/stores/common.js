import { applyDlp, dlpModeFromEnv } from "./dlp.js";

// Shared rules so both backends behave the same (the Supabase backend enforces the same
// limits again in SQL; these checks just give faster, friendlier errors).

export const MESSAGE_TYPES = ["request", "response", "fyi"];
export const LIMITS = { body: 50000, subject: 200, maxHopsCap: 100 };
export const AGENT_NAME_RE = /^[a-z0-9][a-z0-9_-]{0,39}$/;
// Everything a terminal, a log viewer or a tokenizer may treat as the end of a line: CR, LF, VT, FF, the C1 NEL, the
// Unicode line and paragraph separators, and the ASCII separators FS GS RS (which Python's splitlines also splits on).
// Messages are shown with every body line prefixed, and subjects must stay on one line, on ALL of these (R3-12).
const LINE_BREAK_CHARS = "\\n\\v\\f\\u0085\\u2028\\u2029\\u001c-\\u001e";
// A CR that is followed by LF is the first half of a CRLF and stays on its line (the LF ends it), as before.
export const LINE_BREAK_SPLIT = new RegExp(`\\r(?!\\n)|[${LINE_BREAK_CHARS}]`);
export const LINE_BREAK_RUN = new RegExp(`[\\r${LINE_BREAK_CHARS}]+`, "g");
export const hasLineBreak = (s) => new RegExp(`[\\r${LINE_BREAK_CHARS}]`).test(s);

// Abuse limits per sending agent (R1-03). Supabase keeps them in bridge_settings; the local
// backend reads these defaults, overridable with AGENT_BRIDGE_RATE_PER_MIN,
// AGENT_BRIDGE_MAX_UNREAD and AGENT_BRIDGE_MAX_BYTES_PER_DAY.
export const DEFAULT_ABUSE_LIMITS = { ratePerMinute: 60, maxUnreadPerSender: 200, maxBytesPerDay: 20_000_000 };

export class BridgeError extends Error {}
// Transport trouble (unreachable, timeout, 5xx). Only these are worth retrying or waiting out.
// `code` is the underlying network error code when there is one (ENOTFOUND, ECONNREFUSED,
// SELF_SIGNED_CERT_IN_CHAIN, ...), which `cli.js doctor` uses to suggest a fix.
export class NetworkError extends BridgeError {
  constructor(message, code = null) {
    super(message);
    this.code = code;
  }
}

export const isUuid = (s) =>
  typeof s === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);

// Length in Unicode code points: what Postgres char_length() counts on a UTF8 database (R1-11).
export const charLength = (s) => {
  let n = 0;
  for (const _ of s) n++;
  return n;
};

// Tokens and keys travel in headers, so a backend URL must be https:// (R-HD). Loopback hosts
// (what the tests and a local stand-in use) are exempt, and AGENT_BRIDGE_ALLOW_INSECURE_HTTP=1
// is an explicit, loud escape hatch for labs. Checked in the store constructors so every entry
// point (server, CLI, admin commands, doctor) gets it.
export const isLoopbackHost = (h) => {
  const host = String(h).replace(/^\[|\]$/g, "").toLowerCase();
  return host === "localhost" || host === "::1" || /^127(\.\d{1,3}){3}$/.test(host);
};

export function assertSecureUrl(url, what, { allowInsecure = process.env.AGENT_BRIDGE_ALLOW_INSECURE_HTTP === "1" } = {}) {
  let u;
  try {
    u = new URL(url);
  } catch {
    throw new BridgeError(`${what} is not a valid URL.`);
  }
  if (u.protocol === "https:") return;
  if (u.protocol === "http:" && (isLoopbackHost(u.hostname) || allowInsecure)) return;
  throw new BridgeError(
    `${what} must start with https:// (got ${u.protocol}//${u.host}): tokens and keys would travel unencrypted. ` +
      `Use the https URL. Only for a lab, AGENT_BRIDGE_ALLOW_INSECURE_HTTP=1 allows plain http.`
  );
}

export function validateAgentName(name, what = "agent name") {
  if (typeof name !== "string" || !AGENT_NAME_RE.test(name)) {
    throw new BridgeError(`Invalid ${what} ${JSON.stringify(name)}: use lowercase letters, digits, - and _ (max 40).`);
  }
}

// Backends may use their own thread ids (Slack: message timestamps) and their own
// recipient names (Slack: "human:<user>"), and may have a lower body limit.
//
// Returns { body, subject, dlp }: the text to actually send (DLP may have redacted it) and what
// the DLP scan found. Backends must send these values, not the ones they were given. In the
// default "block" mode a message containing secrets or card numbers/IBANs is refused here.
export function validateOutgoing({ from, to, body, type, subject, threadId }, {
  isThreadId = isUuid,
  validateRecipient = (t) => validateAgentName(t),
  maxBody = LIMITS.body,
  dlpMode = dlpModeFromEnv(),
} = {}) {
  if (!to || typeof to !== "string") throw new BridgeError("`to` is required.");
  validateRecipient(to);
  if (from && to === from) throw new BridgeError("An agent cannot message itself.");
  if (!MESSAGE_TYPES.includes(type)) throw new BridgeError(`type must be one of ${MESSAGE_TYPES.join(", ")}`);
  if (typeof body !== "string" || body.length === 0) throw new BridgeError("body must be a non-empty string.");
  if (charLength(body) > maxBody) throw new BridgeError(`body is too long (max ${maxBody} characters).`);
  if (subject != null) {
    if (charLength(subject) > LIMITS.subject) throw new BridgeError(`subject is too long (max ${LIMITS.subject} characters).`);
    if (hasLineBreak(subject)) throw new BridgeError("subject must be a single line.");
  }
  if (threadId != null && !isThreadId(threadId))
    throw new BridgeError(`Unknown thread_id ${threadId}. Omit it to start a new thread.`);
  const checked = applyDlp({ body, subject }, dlpMode);
  // Redaction can make a short match longer ("[REDACTED:payment-card]"): re-check the limit.
  if (checked.body !== body && charLength(checked.body) > maxBody) {
    throw new BridgeError(`body is too long after redaction (max ${maxBody} characters).`);
  }
  return checked;
}
