// Data-loss prevention for outgoing messages: keeps secrets and regulated data (card numbers,
// IBANs) out of the bridge. Agents sometimes paste config files or logs into a message; in a
// regulated environment that is a leak. Every backend calls this from validateOutgoing().
//
// Modes (AGENT_BRIDGE_DLP):
//   block   refuse to send, naming the KIND of data found (never the data itself)  [default]
//   redact  replace each match with [REDACTED:<kind>] and send
//   warn    send unchanged; the tool result says what was found
//   off     no scanning
//
// The scanner is deliberately precise rather than broad: a card number must be Luhn-valid and in
// a known issuer range, an IBAN must pass mod-97 and have its country's length, a JWT's header
// must decode to JSON with "alg", a "password = ..." needs a value that doesn't look like code.
// Every regex is linear-time, so a 50,000-character body is scanned in a few milliseconds.

import { BridgeError } from "./common.js";

export const DLP_MODES = ["block", "redact", "warn", "off"];
export const DEFAULT_DLP_MODE = "block";

// Human names, used in messages. Keys are the kinds used in [REDACTED:<kind>].
export const KIND_LABELS = {
  "private-key": "private key",
  "aws-access-key": "AWS access key id",
  "aws-secret-key": "AWS secret access key",
  "github-token": "GitHub token",
  "slack-token": "Slack token",
  "stripe-key": "Stripe live key",
  "google-api-key": "Google API key",
  jwt: "JSON Web Token",
  "bridge-token": "agent-bridge token",
  "supabase-secret-key": "Supabase secret key",
  "secret-assignment": "password/secret/token assignment",
  "payment-card": "payment card number",
  iban: "IBAN",
};

export function dlpModeFromEnv(env = process.env) {
  const raw = (env.AGENT_BRIDGE_DLP ?? "").trim().toLowerCase();
  if (!raw) return DEFAULT_DLP_MODE;
  if (!DLP_MODES.includes(raw)) {
    throw new BridgeError(`AGENT_BRIDGE_DLP must be one of ${DLP_MODES.join(", ")}, got "${raw}".`);
  }
  return raw;
}

// ------------------------------------------------------------------ checksums

export function luhnValid(digits) {
  let sum = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

// Issuer ranges: [pattern on the leading digits, allowed lengths]
const IIN = [
  [/^4/, [13, 16, 19]], // Visa
  [/^(5[1-5]|2221|222[2-9]|22[3-9]\d|2[3-6]\d\d|27[01]\d|2720)/, [16]], // Mastercard (51-55, 2221-2720)
  [/^3[47]/, [15]], // American Express
  [/^(6011|65|64[4-9]|622(12[6-9]|1[3-9]\d|[2-8]\d\d|9[01]\d|92[0-5]))/, [16, 17, 18, 19]], // Discover
  [/^35(2[89]|[3-8]\d)/, [16, 17, 18, 19]], // JCB
  [/^62/, [16, 17, 18, 19]], // UnionPay
  [/^(30[0-5]|3095|36|38|39)/, [14, 15, 16, 17, 18, 19]], // Diners Club
];

export function isCardNumber(digits) {
  if (!/^\d{13,19}$/.test(digits)) return false;
  if (!IIN.some(([re, lens]) => re.test(digits) && lens.includes(digits.length))) return false;
  return luhnValid(digits);
}

// IBAN length per country (SWIFT IBAN registry).
const IBAN_LENGTHS = Object.fromEntries(
  (
    "AD24 AE23 AL28 AT20 AZ28 BA20 BE16 BG22 BH22 BR29 BY28 CH21 CR22 CY28 CZ24 DE22 DK18 DO28 EE20 EG29 ES24 FI18 FO18 FR27 " +
    "GB22 GE22 GI23 GL18 GR27 GT28 HR21 HU28 IE22 IL23 IQ23 IS26 IT27 JO30 KW30 KZ20 LB28 LC32 LI21 LT20 LU20 LV21 LY25 MC27 " +
    "MD24 ME22 MK19 MR27 MT31 MU30 NL18 NO15 PK24 PL28 PS29 PT25 QA29 RO24 RS22 SA24 SC31 SE24 SI19 SK24 SM27 ST25 SV28 TL23 " +
    "TN24 TR26 UA29 VA22 VG24 XK20"
  )
    .split(" ")
    .map((s) => [s.slice(0, 2), Number(s.slice(2))])
);

export function ibanMod97(iban) {
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let rem = 0;
  for (const ch of rearranged) {
    const v = ch >= "A" ? ch.charCodeAt(0) - 55 : ch.charCodeAt(0) - 48; // A=10 .. Z=35
    rem = v > 9 ? (rem * 100 + v) % 97 : (rem * 10 + v) % 97;
  }
  return rem === 1;
}

export function isIban(compact) {
  const len = IBAN_LENGTHS[compact.slice(0, 2)];
  if (!len || compact.length !== len) return false;
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(compact)) return false;
  return ibanMod97(compact);
}

// ------------------------------------------------------------------ detectors

// A finding is { kind, start, end } over the scanned string. Detectors run in priority order;
// when two overlap, the earlier detector wins (specific token formats beat the generic one).
const TOKEN_PATTERNS = [
  ["private-key", /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----(?:[\s\S]{0,10000}?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|(?:\r?\n[A-Za-z0-9+/=:, \t-]{8,})*)/g],
  ["aws-access-key", /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g],
  ["aws-secret-key", /\baws[\w.-]{0,24}?secret[\w.-]{0,24}?["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/gi],
  ["github-token", /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})(?![A-Za-z0-9_])/g],
  ["slack-token", /\b(?:xox[abprs]|xapp)-[A-Za-z0-9-]{10,}/g],
  ["stripe-key", /\b[sr]k_live_[A-Za-z0-9]{16,}/g],
  ["google-api-key", /\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g],
  ["bridge-token", /\babt_[0-9a-f]{64}(?![0-9a-f])/g],
  ["supabase-secret-key", /\bsb_secret_[A-Za-z0-9_-]{16,}/g],
];

function decodeB64urlJson(seg) {
  try {
    const s = JSON.parse(Buffer.from(seg.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
    return s && typeof s === "object" ? s : null;
  } catch {
    return null;
  }
}

function* jwtFindings(text) {
  const re = /(?<![A-Za-z0-9_-])(ey[A-Za-z0-9_-]{4,})\.([A-Za-z0-9_-]{4,})\.([A-Za-z0-9_-]*)(?![A-Za-z0-9_-])/g;
  for (const m of text.matchAll(re)) {
    const header = decodeB64urlJson(m[1]);
    if (header && typeof header.alg === "string") yield { kind: "jwt", start: m.index, end: m.index + m[0].length };
  }
}

// password / secret / api_key / token assignments with a value that looks like a real secret.
const ASSIGN_RE =
  /(?:passw(?:or)?d|passwd|secret(?:[_-]?(?:access[_-]?)?key)?|api[_-]?key|apikey|private[_-]?key|(?:access[_-]?|auth[_-]?|refresh[_-]?|bearer[_-]?)?token)["']?[ \t]{0,3}(?::=|=>|[:=](?!=))[ \t]{0,3}/gi;
const PLACEHOLDER = /^(?:x{3,}|\*+|\.{3,}|\?+|<.*>|\{\{.*\}\}|%.*%|your[-_ ].*|example.*|sample.*|placeholder.*|redacted.*|\[redacted.*|changeme|change[-_]me|dummy.*|fake.*|none|null|nil|undefined|true|false)$/i;
const SYMBOLS = /[!@#$%^&*+/=~]/;

function looksLikeSecret(v, quoted) {
  if (v.length < 8 || PLACEHOLDER.test(v)) return false;
  if (/[\s]/.test(v) || v.includes("${") || v.includes("{{") || v.startsWith("$")) return false;
  if (/^[A-Za-z_][\w]*(\.[A-Za-z_][\w]*)+$/.test(v)) return false; // property chain: process.env.KEY
  const digit = /\d/.test(v);
  const symbol = SYMBOLS.test(v);
  if (quoted) return digit || symbol || (/[a-z]/.test(v) && /[A-Z]/.test(v));
  if (/[([{<]/.test(v)) return false; // a call, an index, a placeholder
  return digit || symbol; // bare words are usually identifiers
}

// Each value is read at most this far, so a body of repeated "token=" can't make the scan quadratic (R3-01).
const MAX_ASSIGN_VALUE = 512;

function* assignmentFindings(text) {
  for (const m of text.matchAll(ASSIGN_RE)) {
    let i = m.index + m[0].length;
    const limit = Math.min(text.length, i + 1 + MAX_ASSIGN_VALUE);
    const q = text[i];
    let start;
    let end;
    let value;
    if (q === '"' || q === "'") {
      start = i + 1;
      end = start;
      while (end < limit && text[end] !== q && text[end] !== "\n") end++;
      // stopped by the length cap: judge the first MAX_ASSIGN_VALUE characters; a newline or the end
      // of the text means the quote was never closed
      if (text[end] !== q && end < limit) continue;
      value = text.slice(start, end);
      if (!looksLikeSecret(value, true)) continue;
    } else {
      start = i;
      end = start;
      while (end < limit && !/[\s,;"'`)}\]]/.test(text[end])) end++;
      value = text.slice(start, end);
      // "X.MD5Password = AuthenticationMD5Password;": a code statement assigning another name
      if (text[end] === ";" || !looksLikeSecret(value, false)) continue;
    }
    yield { kind: "secret-assignment", start, end };
  }
}

// Payment cards: a contiguous run of 13-19 digits, or the usual 4-4-4-4 / 4-6-5 groupings with one
// kind of separator. Never inside a longer word or number (hashes, ids, base64), never the
// digits of a longer dash-joined number such as a UUID or a date range.
const CARD_RES = [
  /(?<![A-Za-z0-9_-])\d{13,19}(?![A-Za-z0-9_])(?!-\d)/g,
  /(?<![A-Za-z0-9_-])\d{4}([ -])\d{4}\1\d{4}\1\d{4}(?:\1\d{1,3})?(?![A-Za-z0-9_])(?!-\d)/g,
  /(?<![A-Za-z0-9_-])\d{4}([ -])\d{6}\1\d{4,5}(?![A-Za-z0-9_])(?!-\d)/g,
];

function* cardFindings(text) {
  for (const re of CARD_RES) {
    for (const m of text.matchAll(re)) {
      if (isCardNumber(m[0].replace(/[ -]/g, ""))) yield { kind: "payment-card", start: m.index, end: m.index + m[0].length };
    }
  }
}

// IBANs: country code + 2 check digits, then enough [A-Z0-9] (single spaces allowed) to reach the
// country's length exactly, then mod-97.
function* ibanFindings(text) {
  const re = /(?<![A-Za-z0-9])([A-Z]{2})\d{2}(?=[ ]?[A-Z0-9])/g;
  for (const m of text.matchAll(re)) {
    const len = IBAN_LENGTHS[m[1]];
    if (!len) continue;
    let i = m.index;
    let compact = "";
    while (i < text.length && compact.length < len) {
      const ch = text[i];
      if (/[A-Z0-9]/.test(ch)) compact += ch;
      else if (ch === " " && /[A-Z0-9]/.test(text[i + 1] || "") && compact.length % 4 === 0) {
        // a group separator is only plausible after a full group of four
      } else break;
      i++;
    }
    if (compact.length !== len || /[A-Za-z0-9]/.test(text[i] || "")) continue;
    if (isIban(compact)) yield { kind: "iban", start: m.index, end: i };
  }
}

// ------------------------------------------------------------------ scanning

export function scanText(text) {
  if (typeof text !== "string" || !text) return [];
  const found = [];
  const add = (f) => {
    // earlier (more specific) detectors win over overlapping later ones
    if (!found.some((x) => f.start < x.end && x.start < f.end)) found.push(f);
  };
  for (const [kind, re] of TOKEN_PATTERNS) {
    for (const m of text.matchAll(re)) add({ kind, start: m.index, end: m.index + m[0].length });
  }
  for (const f of jwtFindings(text)) add(f);
  for (const f of cardFindings(text)) add(f);
  for (const f of ibanFindings(text)) add(f);
  for (const f of assignmentFindings(text)) add(f);
  return found.sort((a, b) => a.start - b.start);
}

export function redactText(text, findings) {
  let out = "";
  let at = 0;
  for (const f of findings) {
    out += text.slice(at, f.start) + `[REDACTED:${f.kind}]`;
    at = f.end;
  }
  return out + text.slice(at);
}

const plural = (n, s) => (n === 1 ? s : `${s}s`);

// "2 payment card numbers (body), 1 IBAN (subject)": kinds and places only, never the data.
export function describeFindings(findings) {
  const groups = new Map();
  for (const f of findings) {
    const key = `${f.field}\u0000${f.kind}`;
    groups.set(key, { ...f, n: (groups.get(key)?.n || 0) + 1 });
  }
  return [...groups.values()]
    .map((g) => `${g.n} ${plural(g.n, KIND_LABELS[g.kind] || g.kind)} (${g.field})`)
    .join(", ");
}

// Applies the mode to a message's text fields.
// Returns { body, subject, dlp: { mode, action, findings } }; action is
// "none" | "redacted" | "warned". Throws BridgeError in block mode.
export function applyDlp({ body, subject }, mode = DEFAULT_DLP_MODE) {
  const result = { body, subject, dlp: { mode, action: "none", findings: [] } };
  if (mode === "off") return result;
  const perField = { body: scanText(body), subject: scanText(subject ?? "") };
  const findings = [
    ...perField.body.map((f) => ({ field: "body", kind: f.kind })),
    ...perField.subject.map((f) => ({ field: "subject", kind: f.kind })),
  ];
  if (!findings.length) return result;
  result.dlp.findings = findings;
  if (mode === "block") {
    throw new BridgeError(
      `Message not sent: it appears to contain sensitive data: ${describeFindings(findings)}. ` +
        `Remove or replace it (for example with a placeholder or the last 4 digits) and send again. ` +
        `Never send secrets or regulated data over the bridge.`
    );
  }
  if (mode === "redact") {
    result.body = redactText(body, perField.body);
    if (subject != null) result.subject = redactText(subject, perField.subject);
    result.dlp.action = "redacted";
  } else {
    result.dlp.action = "warned";
  }
  return result;
}

// One-line summary for tool results, or "" when nothing was found.
export function dlpNotice(dlp) {
  if (!dlp || !dlp.findings?.length) return "";
  const what = describeFindings(dlp.findings);
  if (dlp.action === "redacted") {
    return `DLP: redacted before sending: ${what}. The recipient sees [REDACTED:<kind>] in their place.`;
  }
  return (
    `DLP warning: the message was sent but appears to contain sensitive data: ${what}. ` +
    `Treat anything exposed as compromised (rotate keys, tell your security team) and don't repeat it.`
  );
}
