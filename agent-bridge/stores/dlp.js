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
// Every regex is linear-time (bounded quantifiers, no nested repetition over unbounded input), so a
// 50,000-character body is scanned in a few milliseconds.
//
// Text is scanned through a NORMALISED view (R3-14): NFKC, zero-width/format characters and combining
// marks dropped, every Unicode decimal digit mapped to 0-9. Match offsets are mapped back to the original
// text, so redaction removes exactly what was sent. The subject and the body are scanned as one text, so a
// number split across them is still found.
//
// DLP is pattern-based, a safety net and not a guarantee: a secret in a shape no detector knows (a bare
// password with no label, a token from an unlisted vendor, a card number spelled out in words, base64 of a
// card) still goes through.

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
  "anthropic-key": "Anthropic API key",
  "openai-key": "OpenAI API key",
  "gitlab-token": "GitLab token",
  "npm-token": "npm token",
  "sendgrid-key": "SendGrid API key",
  "slack-webhook": "Slack webhook URL",
  "azure-credential": "Azure storage key or SAS signature",
  "google-oauth-token": "Google OAuth access token",
  "twilio-key": "Twilio API key",
  "stripe-webhook-secret": "Stripe webhook secret",
  "url-password": "password in a URL",
  "authorization-header": "Authorization header credential",
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

// Issuer ranges: [pattern on the leading digits, allowed lengths]. Table-driven (R3-13). Ranges that no
// real scheme uses stay out (a Luhn-valid number starting with 1 is far more often an id or a timestamp
// than a UATP card, so UATP is deliberately not here).
const IIN = [
  [/^4/, [13, 14, 15, 16, 17, 18, 19]], // Visa
  [/^(5[1-5]|2221|222[2-9]|22[3-9]\d|2[3-6]\d\d|27[01]\d|2720)/, [16, 17, 18, 19]], // Mastercard (51-55, 2221-2720)
  [/^3[47]/, [15]], // American Express
  [/^(6011|65|64[4-9]|622(12[6-9]|1[3-9]\d|[2-8]\d\d|9[01]\d|92[0-5]))/, [16, 17, 18, 19]], // Discover
  [/^(35(2[89]|[3-8]\d)|308[89]|309[0-4]|309[6-9]|310[0-2]|311[2-9]|3120|315[89]|33(3[7-9]|4\d))/, [16, 17, 18, 19]], // JCB
  [/^62/, [16, 17, 18, 19]], // UnionPay
  [/^81/, [16, 17, 18, 19]], // UnionPay (81xx)
  [/^(30[0-5]|3095|36|38|39)/, [14, 15, 16, 17, 18, 19]], // Diners Club
  [/^(50|5[6-9]|6)/, [12, 13, 14, 15, 16, 17, 18, 19]], // Maestro (50, 56-69), RuPay, Verve, Elo (5067, 6363...), Dankort 5019
  [/^220[0-4]/, [16, 17, 18, 19]], // Mir
  [/^9792/, [16]], // Troy
  [/^(8600|9860)/, [16]], // Uzcard, Humo
];

export function isCardNumber(digits) {
  if (!/^\d{12,19}$/.test(digits)) return false;
  if (!IIN.some(([re, lens]) => re.test(digits) && lens.includes(digits.length))) return false;
  return luhnValid(digits);
}

// IBAN length per country (SWIFT IBAN registry).
const IBAN_LENGTHS = Object.fromEntries(
  (
    "AD24 AE23 AL28 AT20 AZ28 BA20 BE16 BG22 BH22 BR29 BY28 CH21 CR22 CY28 CZ24 DE22 DK18 DO28 EE20 EG29 ES24 FI18 FO18 FR27 " +
    "GB22 GE22 GI23 GL18 GR27 GT28 HR21 HU28 IE22 IL23 IQ23 IS26 IT27 JO30 KW30 KZ20 LB28 LC32 LI21 LT20 LU20 LV21 LY25 MC27 " +
    "MD24 ME22 MK19 MR27 MT31 MU30 NL18 NO15 PK24 PL28 PS29 PT25 QA29 RO24 RS22 SA24 SC31 SE24 SI19 SK24 SM27 ST25 SV28 TL23 " +
    "TN24 TR26 UA29 VA22 VG24 XK20 " +
    "RU33 SD18 NI28 OM23 BI27 DJ27 SO23 MN20 FK18 " +
    "AO25 BF28 BJ28 CF27 CG27 CI28 CM27 CV25 DZ26 GA27 GQ27 GW25 HN28 IR26 KM27 MA28 MG27 ML28 MZ25 NE28 SN28 TD27 TG28 YE30"
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
  ["aws-access-key", /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g],
  ["aws-secret-key", /\baws[\w.-]{0,24}?secret[\w.-]{0,24}?["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/gi],
  ["github-token", /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})(?![A-Za-z0-9_])/g],
  ["slack-token", /\b(?:xox[abprs]|xapp)-[A-Za-z0-9-]{10,}/g],
  ["slack-webhook", /\bhttps:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9/_-]{20,}/g],
  ["stripe-key", /\b[sr]k_live_[A-Za-z0-9]{16,}/g],
  ["stripe-webhook-secret", /\bwhsec_[A-Za-z0-9]{24,}/g],
  ["google-api-key", /\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g],
  ["google-oauth-token", /\bya29\.[0-9A-Za-z_-]{20,}/g],
  ["bridge-token", /\babt_[0-9a-f]{64}(?![0-9a-f])/g],
  ["supabase-secret-key", /\bsb_secret_[A-Za-z0-9_-]{16,}/g],
  ["anthropic-key", /\bsk-ant-[A-Za-z0-9_-]{20,}/g],
  // OpenAI: sk-..., sk-proj-...; the (bounded) lookahead wants a digit so a kebab-case word is not a key
  ["openai-key", /\bsk-(?:proj-|svcacct-|admin-)?(?=[A-Za-z0-9_-]{0,64}\d)[A-Za-z0-9_-]{32,}/g],
  ["gitlab-token", /\bglpat-[A-Za-z0-9_-]{20,}/g],
  ["npm-token", /\bnpm_[A-Za-z0-9]{36}(?![A-Za-z0-9])/g],
  ["sendgrid-key", /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g],
  ["twilio-key", /\bSK[0-9a-f]{32}(?![0-9a-f])/g],
  ["azure-credential", /\bAccountKey=[A-Za-z0-9+/]{40,}={0,2}|[?&;]sig=[A-Za-z0-9%+/]{30,}={0,2}/g],
];

// ---- private keys (R3-02, R3-15)
// BEGIN header, then the body: base64 lines separated by real newlines OR by the literal escapes that JSON,
// logs and .env dumps use (`\n`, `\r\n`, `\\n`, `%0A`). The body is consumed to the END marker, or, when the
// key is truncated, to the end of the base64 run: there is no length cap. A header alone (in prose: "a
// file starting with -----BEGIN PRIVATE KEY-----") is not a key; it takes a body of 20+ base64 characters
// (with a digit or + / =), or a complete BEGIN...END block.
const PEM_BEGIN = /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/gi;
const PEM_END = /-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/iy;
const PUTTY_PRIVATE = /\bPrivate-Lines:[ \t]{0,3}\d{1,4}/g;
const NL_SEP = /(?:\r\n|\n|\r|\\{1,2}r\\{1,2}n|\\{1,2}[nr]|%0[AaDd])+/y;
const B64_LINE = /[A-Za-z0-9+/=]+/y;
const PEM_HEADER_LINE = /[A-Za-z][A-Za-z0-9-]{1,30}:[ \t]{0,2}[A-Za-z0-9+/=:,. -]{1,120}/y;
const MAX_KEY_LINES = 100000; // far above any key; keeps the loop obviously bounded

function matchAt(re, text, pos) {
  re.lastIndex = pos;
  const m = re.exec(text);
  return m ? m[0].length : -1;
}

function pemBodyEnd(text, from) {
  let pos = from;
  let lastGood = from; // end of the last accepted body line
  let b64 = 0;
  let hasSpecial = false;
  for (let n = 0; n < MAX_KEY_LINES; n++) {
    const sep = matchAt(NL_SEP, text, pos);
    if (sep <= 0) break;
    const linePos = pos + sep;
    const endLen = matchAt(PEM_END, text, linePos);
    if (endLen > 0) return b64 >= 4 || lastGood > from ? linePos + endLen : -1;
    let len = matchAt(PEM_HEADER_LINE, text, linePos); // Proc-Type: 4,ENCRYPTED / DEK-Info: ...
    if (len <= 0) {
      len = matchAt(B64_LINE, text, linePos);
      if (len <= 0) break;
      const line = text.slice(linePos, linePos + len);
      // a short line, or a plain word ("Thanks"), is prose after the key, unless the END marker follows
      const proseish = len < 8 || (len < 40 && /^[A-Z]?[a-z]+$/.test(line));
      if (proseish) {
        const after = pos + sep + len;
        const nl = matchAt(NL_SEP, text, after);
        if (nl <= 0 || matchAt(PEM_END, text, after + nl) <= 0) break;
      }
      b64 += len;
      if (/[\d+/=]/.test(line)) hasSpecial = true;
    }
    pos = linePos + len;
    lastGood = pos;
  }
  // truncated: no END marker. A key body of any real size is a key.
  return b64 >= 20 && hasSpecial ? lastGood : -1;
}

function* privateKeyFindings(text) {
  for (const re of [PEM_BEGIN, PUTTY_PRIVATE]) {
    for (const m of text.matchAll(re)) {
      const end = pemBodyEnd(text, m.index + m[0].length);
      if (end > 0) yield { kind: "private-key", start: m.index, end };
    }
  }
}

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

// ---- values that are not secrets
// Whole-value placeholders (exact: R3-19, a prefix such as "fake-" must not excuse a real password).
const PLACEHOLDER = /^(?:x{3,}|\*+|\.{3,}|\?+|<[A-Za-z][A-Za-z _.-]*>|\{\{[^{}]*\}\}|%[A-Za-z0-9_.-]*%|\[redacted.*|changeme|change[-_]me|none|null|nil|undefined|true|false)$/i;
// A placeholder WORD followed only by more words ("your-password-here", "example_password", "fake-secret"),
// never by digits or symbols: "fake-Xk39sLq02mZ!" is a password somebody dressed up.
const PLACEHOLDER_WORDS = /^(?:your|example|sample|placeholder|redacted|dummy|fake|test|todo|insert|enter|my|some|the|xxx+)[A-Za-z _.-]*$/i;
const SYMBOLS = /[!@#$%^&*+/=~]/;
// $VAR, ${VAR}, $(cmd), $1: a reference, not a value. "$uperS3cret!9x" is not (digits, symbols, mixed case).
const VAR_REF = /^\$(?:\{[^}]*\}|\([^)]*\)|\d+|[A-Z_][A-Z0-9_]*|[a-z_]+)$/;
// path/to/key.pem, ./secrets/token.txt: where a secret lives, not the secret
const PATHLIKE = /^(?:[~.]{0,2}\/[\w./@-]*|[\w.@-]+\/[\w./@-]*\.[A-Za-z]{2,5})$/;
// my_api_key_1, undefined_value1, some-config-name: lowercase words, at most two trailing digits each
const WORD_IDENT = /^[a-z]+\d{0,2}(?:[_-](?:[a-z]+\d{0,2}|\d{1,2}))+$/;
const PROSE = /\b(?:must|should|is|are|be|to|the|your|you|a|an|and|or|for|of|in|at|least|required|enter|invalid|incorrect|expired|please|not|was|were|has|have|do|does|with|can|cannot|will)\b/i;

function placeholderish(v) {
  return PLACEHOLDER.test(v) || PLACEHOLDER_WORDS.test(v);
}

// "correct horse battery staple 9" is a passphrase; "Password must be at least 8 characters" is a message.
function phraseLooksLikeSecret(v) {
  if (v.length < 12 || PROSE.test(v) || /^[A-Z][a-z]+ [a-z]/.test(v)) return false;
  const words = v.trim().split(/\s+/);
  if (words.length > 8) return false;
  if (/\d/.test(v) || SYMBOLS.test(v)) return true;
  return words.length >= 4 && words.every((w) => /^[a-z]+$/.test(w));
}

// `pw`: the key names a password (not a token/secret/key), so a long all-lowercase value or all digits counts.
function looksLikeSecret(v, quoted, pw = false) {
  if (v.length < 8 || PLACEHOLDER.test(v)) return false;
  if (PLACEHOLDER_WORDS.test(v) || v.includes("${") || v.includes("{{") || VAR_REF.test(v)) return false;
  if (/\s/.test(v)) return quoted && phraseLooksLikeSecret(v);
  if (PATHLIKE.test(v) || WORD_IDENT.test(v)) return false;
  if (/^[A-Za-z_][\w]*(\.[A-Za-z_][\w]*)+$/.test(v)) return false; // property chain: process.env.KEY
  if (/^\d+$/.test(v)) return pw; // a number is a timestamp or an id, unless the key says password
  const digit = /\d/.test(v);
  const symbol = SYMBOLS.test(v);
  if (quoted) return digit || symbol || (/[a-z]/.test(v) && /[A-Z]/.test(v));
  const angled = /^<([^<>]+)>$/.exec(v); // <your-password> is a placeholder, <Xk39sLq02mZ!> is a password in brackets
  if (angled) return looksLikeSecret(angled[1], false, pw);
  if (/[([{<]/.test(v)) return false; // a call, an index, a placeholder
  if (pw && /^[a-z]{16,}$/.test(v)) return true; // a long lowercase run after "password=": a passphrase
  return digit || symbol; // bare words are usually identifiers
}

// password / secret / api_key / token assignments with a value that looks like a real secret.
const ASSIGN_RE =
  /(?:passw(?:or)?d|passwd|(?<![A-Za-z])pass(?:phrase)?|(?<![A-Za-z])pwd|credentials?|secret(?:[_-]?(?:access[_-]?)?key)?|api[_-]?key|apikey|private[_-]?key|(?:access[_-]?|auth[_-]?|refresh[_-]?|bearer[_-]?)?token)\\?["']?[ \t]{0,3}(?::=|=>|[:=](?!=))[ \t]{0,3}/gi;
// `--password Xk39`, `--db-token Xk39`, `sshpass -p Xk39`: the value follows after blanks
const FLAG_RE = /(?<![\w-])(?:--(?:[a-z]{2,12}-){0,3}(?:password|passwd|pass|passphrase|pwd|secret|token|api-?key)|sshpass[ \t]{1,4}-p)[ \t]{1,4}(?=[^\s-])/gi;
// mysql -pSECRET99x: no blank, so the value must pass flagValueOk (not -p8080:80, -pedantic, -pthread)
const SHORT_P_RE = /(?<![\w-])-p(?=[^\s-])/g;
const PORT_LIKE = /^(?:\d{1,3}(?:\.\d{1,3}){3}:)?\d+(?::\d+)*(?:\/\w+)?$/;

// Each value is read at most this far, so a body of repeated "token=" can't make the scan quadratic (R3-01).
const MAX_ASSIGN_VALUE = 512;
const QUOTES = `"'\``;

// Reads the value starting at i. Returns { start, end, value, quoted } or null.
function readValue(text, i) {
  const limit = Math.min(text.length, i + 1 + MAX_ASSIGN_VALUE);
  let start = i;
  let q = text[i];
  if (q === "\\" && QUOTES.includes(text[i + 1] ?? "x")) {
    // JSON inside JSON: password\":\"value\"
    q = text[i + 1];
    start = i + 2;
  } else if (q !== undefined && QUOTES.includes(q)) {
    start = i + 1;
  } else q = null;
  let end = start;
  if (q) {
    while (end < limit && text[end] !== q && text[end] !== "\n") end++;
    // stopped by the length cap: judge the first MAX_ASSIGN_VALUE characters; a newline or the end
    // of the text means the quote was never closed
    if (text[end] !== q && end < limit) return null;
    if (text[end - 1] === "\\" && end > start) end--; // escaped closing quote
    return { start, end, value: text.slice(start, end), quoted: true };
  }
  while (end < limit && !/[\s,;"'`)}\]]/.test(text[end])) end++;
  return { start, end, value: text.slice(start, end), quoted: false, semicolon: text[end] === ";" };
}

// a value given to a flag: the user typed it on purpose, so the bar is lower than for `key = value`
const flagValueOk = (v) =>
  v.length >= 6 && !placeholderish(v) && !VAR_REF.test(v) && !v.includes("${") &&
  (/\d/.test(v) || SYMBOLS.test(v) || (/[a-z]/.test(v) && /[A-Z]/.test(v)));

function* assignmentFindings(text) {
  for (const m of text.matchAll(ASSIGN_RE)) {
    const r = readValue(text, m.index + m[0].length);
    if (!r) continue;
    const pw = /pass|pwd/i.test(m[0]);
    // "X.MD5Password = AuthenticationMD5Password;": a code statement assigning another name
    if (r.semicolon || !looksLikeSecret(r.value, r.quoted, pw)) continue;
    yield { kind: "secret-assignment", start: r.start, end: r.end };
  }
  for (const m of text.matchAll(FLAG_RE)) {
    const r = readValue(text, m.index + m[0].length);
    if (!r || !flagValueOk(r.value)) continue;
    if (!r.quoted && (/[([{<]/.test(r.value) || PATHLIKE.test(r.value))) continue;
    yield { kind: "secret-assignment", start: r.start, end: r.end };
  }
  for (const m of text.matchAll(SHORT_P_RE)) {
    const r = readValue(text, m.index + 2);
    if (!r || !flagValueOk(r.value) || PORT_LIKE.test(r.value)) continue;
    if (/[([{<]/.test(r.value)) continue;
    yield { kind: "secret-assignment", start: r.start, end: r.end };
  }
}

// ---- credentials in URLs and Authorization headers (R3-13)
// scheme://user:password@host: the password is the finding (user and host stay readable).
const URL_CRED_RE = /\b[A-Za-z][A-Za-z0-9+.-]{1,19}:\/\/[^\s/:@?#]{1,64}:([^\s/@]{3,128})@/g;
function* urlPasswordFindings(text) {
  for (const m of text.matchAll(URL_CRED_RE)) {
    const pass = m[1];
    if (placeholderish(pass) || VAR_REF.test(pass) || pass.includes("${") || /^[<{[%$]/.test(pass) || /^\*+$/.test(pass)) continue;
    if (/^(?:pass(?:word|wd)?|pwd|secret|user|username|root|admin|token|key)$/i.test(pass)) continue;
    const end = m.index + m[0].length - 1;
    yield { kind: "url-password", start: end - pass.length, end };
  }
}

const AUTH_RE = /\b(?:proxy-)?authorization\\?["']?[ \t]{0,3}[:=][ \t]{0,3}\\?["']?(?:Bearer|Basic|Token|Digest|Negotiate|ApiKey)[ \t]{1,8}([A-Za-z0-9._~+/=-]{12,})/gi;
function* authHeaderFindings(text) {
  for (const m of text.matchAll(AUTH_RE)) {
    const tok = m[1];
    if (placeholderish(tok) || /^[A-Z_]+$/.test(tok)) continue;
    const end = m.index + m[0].length;
    yield { kind: "authorization-header", start: end - tok.length, end };
  }
}

// ---- payment cards (R3-13, R3-14, R3-15)
// A chain of digit runs joined by at most two separator characters (space, tab, newline, dot, dash,
// slash, underscore; NBSP and friends are spaces after normalisation). Every window of consecutive runs
// holding 12-19 digits is tried, longest first; the Luhn check and the issuer table decide. Never inside
// a longer word or a longer digit run (hashes, ids, base64), never the digits of a longer dash-joined
// number such as a UUID or a date range.
const CARD_SEP = /^[ \t\r\n.\-/_\u2028\u2029]{1,2}$/;
// A contiguous number right after an id-like key (`user_id=`, `ts:`) is an id, not a card (R3-15). Grouped
// numbers ("4111 1111 ...") are always checked: nobody writes an id in groups of four.
const ID_KEY = /(?:^|[^A-Za-z0-9])(?:[A-Za-z0-9]+[_-])?(?:id|ids|uid|guid|uuid|ts|time|timestamp|epoch|nonce)\\?["']?\s{0,3}(?:[:=]|is)\s{0,3}#?\\?["']?$/i;
const ID_KEY_CAMEL = /[a-z0-9]Id\\?["']?\s{0,3}[:=]\s{0,3}#?\\?["']?$/;

// UUIDs (8-4-4-4-12 hex) are never cards, even all-digit ones such as thread ids: a card window can start
// inside the chain (`...-4444-555555555555`), where the chain-start checks don't apply.
const UUID = /(?<![0-9A-Fa-f-])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(?![0-9A-Fa-f-])/g;

function* cardFindings(text) {
  const uuids = [...text.matchAll(UUID)].map((m) => [m.index, m.index + m[0].length]);
  const inUuid = (s, e) => uuids.some(([us, ue]) => s >= us && e <= ue);
  const runs = [];
  for (const m of text.matchAll(/\d+/g)) runs.push({ s: m.index, e: m.index + m[0].length });
  let i = 0;
  while (i < runs.length) {
    const atChainStart = i === 0 || !CARD_SEP.test(text.slice(runs[i - 1].e, runs[i].s));
    let hit = null;
    let digits = 0;
    for (let j = i; j < runs.length; j++) {
      const len = runs[j].e - runs[j].s;
      if (len > 19) break;
      if (j > i && !CARD_SEP.test(text.slice(runs[j - 1].e, runs[j].s))) break;
      digits += len;
      if (digits > 19) break;
      if (digits < 12) continue;
      const first = runs[i].s;
      const last = runs[j].e;
      const after = text[last] ?? "";
      if (/[A-Za-z0-9_]/.test(after) || (after === "-" && /\d/.test(text[last + 1] ?? ""))) continue;
      if (atChainStart && /[A-Za-z0-9_-]/.test(text[first - 1] ?? "")) continue;
      let num = "";
      for (let k = i; k <= j; k++) num += text.slice(runs[k].s, runs[k].e);
      if (!isCardNumber(num)) continue;
      if (inUuid(first, last)) continue;
      if (j === i) {
        const lead = text.slice(Math.max(0, first - 40), first);
        if (ID_KEY.test(lead) || ID_KEY_CAMEL.test(lead)) continue;
      }
      hit = { j, start: first, end: last };
    }
    if (hit) {
      yield { kind: "payment-card", start: hit.start, end: hit.end };
      i = hit.j + 1;
    } else i++;
  }
}

// IBANs: country code + 2 check digits, then enough [A-Z0-9] (one or two separators allowed between
// characters, any grouping) to reach the country's length exactly, then mod-97. Runs on the upper-cased
// view, so lower-case IBANs are found too.
const IBAN_SEP = /[ \t\r\n.\-/_]/;
function* ibanFindings(text) {
  const re = /(?<![A-Za-z0-9])([A-Z]{2})\d{2}(?=[ \t\r\n.\-/_]{0,2}[A-Z0-9])/g;
  for (const m of text.matchAll(re)) {
    const len = IBAN_LENGTHS[m[1]];
    if (!len) continue;
    let i = m.index;
    let compact = "";
    while (i < text.length && compact.length < len) {
      const ch = text[i];
      if (/[A-Z0-9]/.test(ch)) compact += ch;
      else if (IBAN_SEP.test(ch) && /[A-Z0-9]/.test(text[i + 1] || "")) {
        // a separator between characters
      } else if (IBAN_SEP.test(ch) && IBAN_SEP.test(text[i + 1] || "") && /[A-Z0-9]/.test(text[i + 2] || "")) {
        i++; // two separators in a row
      } else break;
      i++;
    }
    if (compact.length !== len || /[A-Za-z0-9]/.test(text[i] || "")) continue;
    if (isIban(compact)) yield { kind: "iban", start: m.index, end: i };
  }
}

// ------------------------------------------------------------------ normalisation (R3-14)

const ASCII_ONLY = /^[\x00-\x7f]*$/;
const DROP = /^[\p{Cf}\p{M}]$/u;
const DECIMAL = /^\p{Nd}$/u;

function digitValue(cp) {
  let z = cp;
  for (let n = 0; n < 60 && DECIMAL.test(String.fromCodePoint(z - 1)); n++) z--;
  return (cp - z) % 10;
}

// Returns { norm, start, end }: start[k] / end[k] are the original offsets of normalised char k.
// Pure ASCII needs no mapping (start/end null).
function normalise(text) {
  if (ASCII_ONLY.test(text)) return { norm: text, start: null, end: null };
  const parts = [];
  const start = [];
  const end = [];
  for (let i = 0; i < text.length; ) {
    const cp = text.codePointAt(i);
    const w = cp > 0xffff ? 2 : 1;
    let out;
    if (cp < 128) out = text[i];
    else {
      const ch = String.fromCodePoint(cp);
      if (DROP.test(ch)) out = "";
      else if (DECIMAL.test(ch)) out = String(digitValue(cp));
      else out = ch.normalize("NFKC");
    }
    for (let k = 0; k < out.length; k++) {
      start.push(i);
      end.push(i + w);
    }
    parts.push(out);
    i += w;
  }
  return { norm: parts.join(""), start, end };
}

// ------------------------------------------------------------------ scanning

export function scanText(text) {
  if (typeof text !== "string" || !text) return [];
  const { norm, start: smap, end: emap } = normalise(text);
  const found = [];
  const add = (f) => {
    // earlier (more specific) detectors win over overlapping later ones
    if (!found.some((x) => f.start < x.end && x.start < f.end)) found.push(f);
  };
  for (const f of privateKeyFindings(norm)) add(f);
  for (const [kind, re] of TOKEN_PATTERNS) {
    for (const m of norm.matchAll(re)) add({ kind, start: m.index, end: m.index + m[0].length });
  }
  for (const f of jwtFindings(norm)) add(f);
  for (const f of urlPasswordFindings(norm)) add(f);
  for (const f of authHeaderFindings(norm)) add(f);
  for (const f of cardFindings(norm)) add(f);
  // IBANs are matched on the upper-cased view (same length, so the same offsets)
  for (const f of ibanFindings(norm.replace(/[a-z]/g, (c) => c.toUpperCase()))) add(f);
  for (const f of assignmentFindings(norm)) add(f);
  if (smap) {
    for (const f of found) {
      f.start = smap[f.start];
      f.end = emap[f.end - 1];
    }
  }
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


// The subject limit (stores/common.js LIMITS.subject). Redaction can make a short match longer
// ("[REDACTED:payment-card]" is 23 characters), so a redacted subject is cut back to this (R3-03).
const SUBJECT_LIMIT = 200;

// Cuts a (redacted) subject to the limit without splitting a code point or leaving half a
// [REDACTED:...] marker, and ends it with an ellipsis.
function fitSubject(s, limit = SUBJECT_LIMIT) {
  const chars = Array.from(s);
  if (chars.length <= limit) return s;
  let cut = chars.slice(0, limit - 1).join("");
  const open = cut.lastIndexOf("[");
  if (open >= 0 && !cut.includes("]", open) && (cut.slice(open).startsWith("[REDACTED:") || "[REDACTED:".startsWith(cut.slice(open)))) cut = cut.slice(0, open);
  return cut + "…";
}

// Splits the findings of the combined text `subject + "\n" + body` back into the two fields. A finding that
// crosses the boundary (a card number split between them) is redacted in both halves and reported once as
// "subject+body".
function splitFindings(found, subjectLen) {
  const out = { subject: [], body: [], report: [] };
  for (const f of found) {
    if (subjectLen < 0) {
      out.body.push(f);
      out.report.push({ field: "body", kind: f.kind });
    } else if (f.end <= subjectLen) {
      out.subject.push(f);
      out.report.push({ field: "subject", kind: f.kind });
    } else if (f.start > subjectLen) {
      out.body.push({ ...f, start: f.start - subjectLen - 1, end: f.end - subjectLen - 1 });
      out.report.push({ field: "body", kind: f.kind });
    } else {
      if (f.start < subjectLen) out.subject.push({ ...f, end: subjectLen });
      if (f.end > subjectLen + 1) out.body.push({ ...f, start: 0, end: f.end - subjectLen - 1 });
      out.report.push({ field: "subject+body", kind: f.kind });
    }
  }
  // report body findings before subject ones (the order the messages have always used)
  const rank = { body: 0, subject: 1, "subject+body": 2 };
  out.report.sort((a, b) => rank[a.field] - rank[b.field]);
  return out;
}

// Applies the mode to a message's text fields.
// Returns { body, subject, dlp: { mode, action, findings } }; action is
// "none" | "redacted" | "warned". Throws BridgeError in block mode.
// The subject and the body are scanned as one text, so a secret split between them is still found.
export function applyDlp({ body, subject }, mode = DEFAULT_DLP_MODE) {
  const result = { body, subject, dlp: { mode, action: "none", findings: [] } };
  if (mode === "off") return result;
  const hasSubject = subject != null;
  const perField = splitFindings(scanText(hasSubject ? `${subject}\n${body}` : body), hasSubject ? subject.length : -1);
  const findings = perField.report;
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
    if (result.subject != null && result.subject !== subject) {
      const fitted = fitSubject(result.subject);
      if (fitted !== result.subject) {
        result.subject = fitted;
        result.dlp.subjectShortened = true;
      }
    }
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
    return (
      `DLP: redacted before sending: ${what}. The recipient sees [REDACTED:<kind>] in their place.` +
      (dlp.subjectShortened ? ` The subject was shortened to fit its ${SUBJECT_LIMIT}-character limit.` : "")
    );
  }
  return (
    `DLP warning: the message was sent but appears to contain sensitive data: ${what}. ` +
    `Treat anything exposed as compromised (rotate keys, tell your security team) and don't repeat it.`
  );
}
