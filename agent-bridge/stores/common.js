// Shared rules so both backends behave the same (the Supabase backend enforces the same
// limits again in SQL; these checks just give faster, friendlier errors).

export const MESSAGE_TYPES = ["request", "response", "fyi"];
export const LIMITS = { body: 50000, subject: 200, maxHopsCap: 100 };
export const AGENT_NAME_RE = /^[a-z0-9][a-z0-9_-]{0,39}$/;

// Abuse limits per sending agent (R1-03). Supabase keeps them in bridge_settings; the local
// backend reads these defaults, overridable with AGENT_BRIDGE_RATE_PER_MIN,
// AGENT_BRIDGE_MAX_UNREAD and AGENT_BRIDGE_MAX_BYTES_PER_DAY.
export const DEFAULT_ABUSE_LIMITS = { ratePerMinute: 60, maxUnreadPerSender: 200, maxBytesPerDay: 20_000_000 };

export class BridgeError extends Error {}
// Transport trouble (unreachable, timeout, 5xx). Only these are worth retrying or waiting out.
export class NetworkError extends BridgeError {}

export const isUuid = (s) =>
  typeof s === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);

// Length in Unicode code points: what Postgres char_length() counts on a UTF8 database (R1-11).
export const charLength = (s) => {
  let n = 0;
  for (const _ of s) n++;
  return n;
};

export function validateAgentName(name, what = "agent name") {
  if (typeof name !== "string" || !AGENT_NAME_RE.test(name)) {
    throw new BridgeError(`Invalid ${what} ${JSON.stringify(name)}: use lowercase letters, digits, - and _ (max 40).`);
  }
}

export function validateOutgoing({ from, to, body, type, subject, threadId }) {
  if (!to || typeof to !== "string") throw new BridgeError("`to` is required.");
  validateAgentName(to);
  if (from && to === from) throw new BridgeError("An agent cannot message itself.");
  if (!MESSAGE_TYPES.includes(type)) throw new BridgeError(`type must be one of ${MESSAGE_TYPES.join(", ")}`);
  if (typeof body !== "string" || body.length === 0) throw new BridgeError("body must be a non-empty string.");
  if (charLength(body) > LIMITS.body) throw new BridgeError(`body is too long (max ${LIMITS.body} characters).`);
  if (subject != null) {
    if (charLength(subject) > LIMITS.subject) throw new BridgeError(`subject is too long (max ${LIMITS.subject} characters).`);
    if (/[\r\n]/.test(subject)) throw new BridgeError("subject must be a single line.");
  }
  if (threadId != null && !isUuid(threadId))
    throw new BridgeError(`Unknown thread_id ${threadId}. Omit it to start a new thread.`);
}
