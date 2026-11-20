// Mutations for the DLP findings of adversary round 3 (R3-02, R3-03, R3-13, R3-14, R3-15, R3-19).
// Same shape as the entries in test/mutations.js: { name, file, find, replace, suite }; `find` occurs exactly once.
// Every guard added for these findings has an entry here, and test/regressions-r3-dlp.js must fail with it applied.
// (String.raw keeps the regex backslashes exactly as they are in the source.)
const R = ["test/regressions-r3-dlp.js"];
const RD = ["test/regressions-r3-dlp.js", "test/dlp.js"];
const F = "stores/dlp.js";
const never = String.raw`/(?!)/g`;

// swaps a card-table row's issuer pattern for one that matches nothing
const row = (name, find) => ({ name: `R3-13 card table: ${name} row removed`, file: F, find, replace: find.replace(/\[\/.*?\/, \[/, "[/^(?!)/, ["), suite: R });

export default [
  // --- R3-02 / R3-15: private keys
  { name: "R3-02 private key body: literal \\n / \\r\\n / %0A separators not understood", file: F,
    find: String.raw`(?:\r\n|\n|\r|\\{1,2}r\\{1,2}n|\\{1,2}[nr]|%0[AaDd])+`, replace: String.raw`(?:\r\n|\n|\r)+`, suite: R },
  { name: "R3-02 truncated key (no END marker) is not redacted", file: F,
    find: `  return b64 >= 20 && hasSpecial ? lastGood : -1;`, replace: `  return -1;`, suite: R },
  { name: "R3-02 the END marker is left in the text", file: F,
    find: `    if (endLen > 0) return b64 >= 4 || lastGood > from ? linePos + endLen : -1;`, replace: `    if (endLen > 0) return lastGood;`, suite: R },
  { name: "R3-02 key body capped at 10,000 characters again", file: F,
    find: `    const sep = matchAt(NL_SEP, text, pos);\n    if (sep <= 0) break;`, replace: `    const sep = matchAt(NL_SEP, text, pos);\n    if (sep <= 0 || pos - from > 10000) break;`, suite: R },
  { name: "R3-15 a bare BEGIN header in prose is flagged as a key", file: F,
    find: `  return b64 >= 20 && hasSpecial ? lastGood : -1;`, replace: `  return lastGood;`, suite: R },
  { name: "R3-15 a short truncated body (under 20 characters) is enough for a key", file: F,
    find: `  return b64 >= 20 && hasSpecial ? lastGood : -1;`, replace: `  return b64 >= 1 ? lastGood : -1;`, suite: RD },
  { name: "R3-15 an empty BEGIN...END pair is a key", file: F,
    find: `    if (endLen > 0) return b64 >= 4 || lastGood > from ? linePos + endLen : -1;`, replace: `    if (endLen > 0) return linePos + endLen;`, suite: RD },
  { name: "R3-02 prose after a truncated key is swallowed as key lines", file: F,
    find: `      if (proseish) {`, replace: `      if (false) {`, suite: R },
  { name: "R3-02 Proc-Type / DEK-Info header lines of an encrypted key not understood", file: F,
    find: `    let len = matchAt(PEM_HEADER_LINE, text, linePos);`, replace: `    let len = -1;`, suite: R },
  { name: "R3-02 PuTTY .ppk private blocks ignored", file: F,
    find: `  for (const re of [PEM_BEGIN, PUTTY_PRIVATE]) {`, replace: `  for (const re of [PEM_BEGIN]) {`, suite: R },

  // --- R3-03: subject limit after redaction
  { name: "R3-03 a redacted subject is not cut back to the limit", file: F,
    find: `      const fitted = fitSubject(result.subject);`, replace: `      const fitted = result.subject;`, suite: R },
  { name: "R3-03 the cut can split a [REDACTED:...] marker", file: F,
    find: `  if (open >= 0 && !cut.includes("]", open) && (cut.slice(open).startsWith("[REDACTED:") || "[REDACTED:".startsWith(cut.slice(open)))) cut = cut.slice(0, open);`, replace: ``, suite: R },
  { name: "R3-03 the sender is not told the subject was shortened", file: F,
    find: `        result.dlp.subjectShortened = true;`, replace: ``, suite: R },

  // --- R3-13: card table
  row("Maestro/RuPay/Elo (50, 56-69)", String.raw`  [/^(50|5[6-9]|6)/, [12, 13, 14, 15, 16, 17, 18, 19]],`),
  row("Mir", String.raw`  [/^220[0-4]/, [16, 17, 18, 19]],`),
  row("Troy", String.raw`  [/^9792/, [16]],`),
  row("Uzcard/Humo", String.raw`  [/^(8600|9860)/, [16]],`),
  row("UnionPay 81", String.raw`  [/^81/, [16, 17, 18, 19]],`),
  { name: "R3-13 card table: JCB 3088-3094 not recognised", file: F, find: String.raw`[/^(35(2[89]|[3-8]\d)|308[89]|`, replace: String.raw`[/^(35(2[89]|[3-8]\d)|3000|`, suite: R },
  { name: "R3-13 card table: Visa 18 digits not recognised", file: F, find: `[/^4/, [13, 14, 15, 16, 17, 18, 19]],`, replace: `[/^4/, [13, 16, 19]],`, suite: R },
  { name: "R3-13 card table: Mastercard 17 digits not recognised", file: F,
    find: String.raw`2[3-6]\d\d|27[01]\d|2720)/, [16, 17, 18, 19]],`, replace: String.raw`2[3-6]\d\d|27[01]\d|2720)/, [16]],`, suite: R },
  { name: "R3-13 card table: 12-digit Maestro not read", file: F,
    find: `  if (!/^\\d{12,19}$/.test(digits)) return false;`, replace: `  if (!/^\\d{13,19}$/.test(digits)) return false;`, suite: R },
  { name: "R3-13 IBAN registry: RU, SD, OM, MN, FK... missing", file: F,
    find: `"RU33 SD18 NI28 OM23 BI27 DJ27 SO23 MN20 FK18 " +`, replace: `"" +`, suite: R },

  // --- R3-13: credential formats
  { name: "R3-13 no Anthropic key detector", file: F, find: String.raw`["anthropic-key", /\bsk-ant-[A-Za-z0-9_-]{20,}/g],`, replace: `["anthropic-key", ${never}],`, suite: R },
  { name: "R3-13 no OpenAI key detector", file: F, find: String.raw`["openai-key", /\bsk-(?:proj-|svcacct-|admin-)?(?=[A-Za-z0-9_-]{0,64}\d)[A-Za-z0-9_-]{32,}/g],`, replace: `["openai-key", ${never}],`, suite: R },
  { name: "R3-13 OpenAI detector matches kebab-case words (no digit required)", file: F, find: String.raw`(?=[A-Za-z0-9_-]{0,64}\d)[A-Za-z0-9_-]{32,}`, replace: String.raw`[A-Za-z0-9_-]{32,}`, suite: R },
  { name: "R3-13 no GitLab token detector", file: F, find: String.raw`["gitlab-token", /\bglpat-[A-Za-z0-9_-]{20,}/g],`, replace: `["gitlab-token", ${never}],`, suite: R },
  { name: "R3-13 no npm token detector", file: F, find: String.raw`["npm-token", /\bnpm_[A-Za-z0-9]{36}(?![A-Za-z0-9])/g],`, replace: `["npm-token", ${never}],`, suite: R },
  { name: "R3-13 no SendGrid key detector", file: F, find: String.raw`["sendgrid-key", /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g],`, replace: `["sendgrid-key", ${never}],`, suite: R },
  { name: "R3-13 no Slack webhook detector", file: F, find: String.raw`["slack-webhook", /\bhttps:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9/_-]{20,}/g],`, replace: `["slack-webhook", ${never}],`, suite: R },
  { name: "R3-13 no Azure key / SAS detector", file: F, find: String.raw`["azure-credential", /\bAccountKey=[A-Za-z0-9+/]{40,}={0,2}|[?&;]sig=[A-Za-z0-9%+/]{30,}={0,2}/g],`, replace: `["azure-credential", ${never}],`, suite: R },
  { name: "R3-13 no Google OAuth token detector", file: F, find: String.raw`["google-oauth-token", /\bya29\.[0-9A-Za-z_-]{20,}/g],`, replace: `["google-oauth-token", ${never}],`, suite: R },
  { name: "R3-13 passwords in URLs not detected", file: F, find: `  for (const f of urlPasswordFindings(norm)) add(f);\n`, replace: ``, suite: R },
  { name: "R3-13 URL password: placeholders such as your-password-here flagged", file: F, find: `    if (placeholderish(pass) || VAR_REF.test(pass)`, replace: `    if (VAR_REF.test(pass)`, suite: R },
  { name: "R3-13 URL password: the word 'password' itself flagged", file: F, find: String.raw`    if (/^(?:pass(?:word|wd)?|pwd|secret|user|username|root|admin|token|key)$/i.test(pass)) continue;`, replace: ``, suite: R },
  { name: "R3-13 URL password: the whole URL is redacted, not just the password", file: F, find: `    yield { kind: "url-password", start: end - pass.length, end };`, replace: `    yield { kind: "url-password", start: m.index, end: end + 1 };`, suite: R },
  { name: "R3-13 Authorization headers not detected", file: F, find: `  for (const f of authHeaderFindings(norm)) add(f);\n`, replace: ``, suite: R },
  { name: "R3-13 Authorization header: placeholder tokens flagged", file: F, find: String.raw`    if (placeholderish(tok) || /^[A-Z_]+$/.test(tok)) continue;`, replace: ``, suite: R },

  // --- R3-14: normalisation
  { name: "R3-14 zero-width / format characters and combining marks are not dropped", file: F, find: `      if (DROP.test(ch)) out = "";`, replace: `      if (false) out = "";`, suite: R },
  { name: "R3-14 non-ASCII digits are not mapped to 0-9", file: F, find: `      else if (DECIMAL.test(ch)) out = String(digitValue(cp));`, replace: ``, suite: R },
  { name: "R3-14 no NFKC (NBSP, ideographic space, full-width letters stay as they are)", file: F, find: `      else out = ch.normalize("NFKC");`, replace: `      else out = ch;`, suite: R },
  { name: "R3-14 match offsets are not mapped back to the original text", file: F, find: `      f.end = emap[f.end - 1];`, replace: `      f.end = f.end;`, suite: R },
  { name: "R3-14 match start is not mapped back to the original text", file: F, find: `      f.start = smap[f.start];`, replace: ``, suite: R },
  { name: "R3-14 card digit groups: only one separator character allowed", file: F, find: String.raw`const CARD_SEP = /^[ \t\r\n.\-/_\u2028\u2029]{1,2}$/;`, replace: String.raw`const CARD_SEP = /^[ \t\r\n.\-/_\u2028\u2029]{1}$/;`, suite: R },
  { name: "R3-14 card digit groups: dots, slashes and newlines not separators", file: F, find: String.raw`const CARD_SEP = /^[ \t\r\n.\-/_\u2028\u2029]{1,2}$/;`, replace: String.raw`const CARD_SEP = /^[ \-]{1,2}$/;`, suite: R },
  { name: "R3-14 a number inside a longer chain (1-4111 ...) is only tried from the chain start", file: F, find: `    const atChainStart = i === 0 || !CARD_SEP.test(text.slice(runs[i - 1].e, runs[i].s));`, replace: `    const atChainStart = true;`, suite: R },
  { name: "R3-14 IBANs only matched in upper case", file: F, find: `ibanFindings(norm.replace(/[a-z]/g, (c) => c.toUpperCase()))`, replace: `ibanFindings(norm)`, suite: R },
  { name: "R3-14 IBAN groups: only single spaces", file: F, find: String.raw`const IBAN_SEP = /[ \t\r\n.\-/_]/;`, replace: String.raw`const IBAN_SEP = /[ ]/;`, suite: R },
  { name: "R3-14 IBAN groups: no double separators", file: F, find: `      } else if (IBAN_SEP.test(ch) && IBAN_SEP.test(text[i + 1] || "") && /[A-Z0-9]/.test(text[i + 2] || "")) {`, replace: `      } else if (false) {`, suite: R },
  { name: "R3-14 subject and body are scanned separately again (a split number is missed)", file: F,
    find: `    } else {\n      if (f.start < subjectLen) out.subject.push({ ...f, end: subjectLen });`, replace: `    } else if (false) {\n      if (f.start < subjectLen) out.subject.push({ ...f, end: subjectLen });`, suite: R },
  { name: "R3-14 a split number is redacted in the subject half only", file: F,
    find: `      if (f.end > subjectLen + 1) out.body.push({ ...f, start: 0, end: f.end - subjectLen - 1 });`, replace: ``, suite: R },
  { name: "R3-14 a split number is redacted in the body half only", file: F,
    find: `      if (f.start < subjectLen) out.subject.push({ ...f, end: subjectLen });`, replace: ``, suite: R },
  { name: "R3-14 a split number is not reported", file: F,
    find: `      out.report.push({ field: "subject+body", kind: f.kind });`, replace: ``, suite: R },

  // --- R3-19: the assignment heuristic
  { name: "R3-19 a value starting with $ is a variable reference", file: F,
    find: `  if (PLACEHOLDER_WORDS.test(v) || v.includes("\${") || v.includes("{{") || VAR_REF.test(v)) return false;`,
    replace: `  if (PLACEHOLDER_WORDS.test(v) || v.includes("\${") || v.includes("{{") || v.startsWith("$")) return false;`, suite: R },
  { name: "R3-19 any value that starts with a placeholder word is a placeholder", file: F,
    find: String.raw`|the|xxx+)[A-Za-z _.-]*$/i;`, replace: String.raw`|the|xxx+).*$/i;`, suite: R },
  { name: "R3-19 <...> placeholders are not looked into", file: F, find: `  if (angled) return looksLikeSecret(angled[1], false, pw);`, replace: `  if (angled) return false;`, suite: R },
  { name: "R3-19 %...% placeholders: any value between percent signs", file: F, find: String.raw`|%[A-Za-z0-9_.-]*%|`, replace: String.raw`|%.*%|`, suite: R },
  { name: "R3-19 backtick-quoted values not read", file: F, find: `  } else if (q !== undefined && QUOTES.includes(q)) {`, replace: `  } else if (q !== undefined && "\\"'".includes(q)) {`, suite: R },
  { name: "R3-19 JSON-escaped quotes (\\\") not read", file: F, find: `  if (q === "\\\\" && QUOTES.includes(text[i + 1] ?? "x")) {`, replace: `  if (false) {`, suite: R },
  { name: "R3-19 escaped key names (password\\\":) not matched", file: F, find: String.raw`?token)\\?["']?[ \t]{0,3}(?::=|=>`, replace: String.raw`?token)["']?[ \t]{0,3}(?::=|=>`, suite: R },
  { name: "R3-19 a quoted value with spaces is never a secret", file: F, find: `  if (/\\s/.test(v)) return quoted && phraseLooksLikeSecret(v);`, replace: `  if (/\\s/.test(v)) return false;`, suite: R },
  { name: "R3-19 a four-word lowercase passphrase is not a secret", file: F, find: `  return words.length >= 4 && words.every((w) => /^[a-z]+$/.test(w));`, replace: `  return false;`, suite: R },
  { name: "R3-19 error messages in quotes are flagged (prose words not checked)", file: F, find: `  if (v.length < 12 || PROSE.test(v) || /^[A-Z][a-z]+ [a-z]/.test(v)) return false;`, replace: `  if (v.length < 12 || /^[A-Z][a-z]+ [a-z]/.test(v)) return false;`, suite: R },
  { name: "R3-19 sentence-case messages in quotes are flagged", file: F, find: `  if (v.length < 12 || PROSE.test(v) || /^[A-Z][a-z]+ [a-z]/.test(v)) return false;`, replace: `  if (v.length < 12 || PROSE.test(v)) return false;`, suite: R },
  { name: "R3-19 a long lowercase value after password= is an identifier", file: F, find: `  if (pw && /^[a-z]{16,}$/.test(v)) return true; // a long lowercase run after "password=": a passphrase`, replace: ``, suite: R },
  { name: "R3-19 pwd / pass / credentials are not key names", file: F, find: String.raw`(?<![A-Za-z])pass(?:phrase)?|(?<![A-Za-z])pwd|credentials?|`, replace: ``, suite: R },
  { name: "R3-19 'pass' matches inside other words (bypass:)", file: F, find: String.raw`(?<![A-Za-z])pass(?:phrase)?|`, replace: String.raw`pass(?:phrase)?|`, suite: R },
  { name: "R3-19 --password VALUE (flag with a space) not detected", file: F, find: `  for (const m of text.matchAll(FLAG_RE)) {`, replace: `  for (const m of []) {`, suite: R },
  { name: "R3-19 flag values: variables and placeholders flagged", file: F, find: `  v.length >= 6 && !placeholderish(v) && !VAR_REF.test(v) && !v.includes("\${") &&`, replace: `  v.length >= 6 &&`, suite: R },
  { name: "R3-19 flag values: any word of 6+ letters flagged (prompt)", file: F, find: String.raw`  (/\d/.test(v) || SYMBOLS.test(v) || (/[a-z]/.test(v) && /[A-Z]/.test(v)));`, replace: `  true;`, suite: R },
  { name: "R3-19 mysql -pPASSWORD not detected", file: F, find: `  for (const m of text.matchAll(SHORT_P_RE)) {`, replace: `  for (const m of []) {`, suite: R },
  { name: "R3-19 -p<port mapping> flagged", file: F, find: `!flagValueOk(r.value) || PORT_LIKE.test(r.value)) continue;`, replace: `!flagValueOk(r.value)) continue;`, suite: R },

  // --- R3-15: false positives
  { name: "R3-15 a number after id/ts/time keys is checked as a card", file: F, find: `        if (ID_KEY.test(lead) || ID_KEY_CAMEL.test(lead)) continue;`, replace: ``, suite: R },
  { name: "R3-15 camelCase id keys (userId) are not recognised", file: F, find: `        if (ID_KEY.test(lead) || ID_KEY_CAMEL.test(lead)) continue;`, replace: `        if (ID_KEY.test(lead)) continue;`, suite: R },
  { name: "R3-15 grouped numbers after an id key are skipped too", file: F, find: `      if (j === i) {\n        const lead`, replace: `      if (true) {\n        const lead`, suite: R },
  { name: "R3-15 an all-digit value is a secret whatever the key", file: F, find: `  if (/^\\d+$/.test(v)) return pw; // a number is a timestamp or an id, unless the key says password`, replace: `  if (/^\\d+$/.test(v)) return true;`, suite: R },
  { name: "R3-15 an all-digit value is never a secret (password=12345678)", file: F, find: `  if (/^\\d+$/.test(v)) return pw; // a number is a timestamp or an id, unless the key says password`, replace: `  if (/^\\d+$/.test(v)) return false;`, suite: R },
  { name: "R3-15 file paths are secrets", file: F, find: `  if (PATHLIKE.test(v) || WORD_IDENT.test(v)) return false;`, replace: `  if (WORD_IDENT.test(v)) return false;`, suite: R },
  { name: "R3-15 lowercase snake_case identifiers are secrets", file: F, find: `  if (PATHLIKE.test(v) || WORD_IDENT.test(v)) return false;`, replace: `  if (PATHLIKE.test(v)) return false;`, suite: R },
  { name: "R3-15 identifiers ending in _1 are secrets", file: F, find: String.raw`(?:[_-](?:[a-z]+\d{0,2}|\d{1,2}))+$/;`, replace: String.raw`(?:[_-](?:[a-z]+\d{0,2}))+$/;`, suite: R },
];
