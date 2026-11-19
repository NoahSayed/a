// Shared rules so both backends behave the same (the Supabase backend enforces the same
// limits again in SQL; these checks just give faster, friendlier errors).

export const MESSAGE_TYPES = ["request", "response", "fyi"];
export const LIMITS = { body: 50000, subject: 200, maxHopsCap: 100 };
export const AGENT_NAME_RE = /^[a-z0-9][a-z0-9_-]{0,39}$/;

export class BridgeError extends Error {}

export const isUuid = (s) =>
  typeof s === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);

export function validateOutgoing({ from, to, body, type, subject, threadId }) {
  if (!to || typeof to !== "string") throw new BridgeError("`to` is required.");
  if (from && to === from) throw new BridgeError("An agent cannot message itself.");
  if (!MESSAGE_TYPES.includes(type)) throw new BridgeError(`type must be one of ${MESSAGE_TYPES.join(", ")}`);
  if (typeof body !== "string" || body.length === 0) throw new BridgeError("body must be a non-empty string.");
  if (body.length > LIMITS.body) throw new BridgeError(`body is too long (max ${LIMITS.body} characters).`);
  if (subject != null && subject.length > LIMITS.subject)
    throw new BridgeError(`subject is too long (max ${LIMITS.subject} characters).`);
  if (threadId != null && !isUuid(threadId))
    throw new BridgeError(`Unknown thread_id ${threadId}. Omit it to start a new thread.`);
}
