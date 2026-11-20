// Regression tests for the DLP findings of adversary round 3 (docs/adversary/round-03.md):
// R3-02, R3-03, R3-13, R3-14, R3-15, R3-19. Written before the fixes: each (except the "still works"
// guards) must fail on commit 25981ee, then pass.
//   node test/regressions-r3-dlp.js
// Fixtures are assembled from pieces so this file holds no literal secret.
import assert from "node:assert/strict";
import { applyDlp, dlpNotice, ibanMod97, luhnValid, redactText, scanText } from "../stores/dlp.js";
import { validateOutgoing } from "../stores/common.js";
import { summary, test } from "./harness.js";

const kinds = (t) => scanText(t).map((f) => f.kind);
const hit = (t, kind) => assert.ok(kinds(t).includes(kind), `${kind} not found in: ${t.slice(0, 120)}`);
const clean = (t) => assert.deepEqual(kinds(t), [], t.slice(0, 120));
const redact = (t) => redactText(t, scanText(t));
const rep = (s, n) => s.repeat(n);

function luhnNumber(prefix, len) {
  const body = (prefix + rep("7", len)).slice(0, len - 1);
  for (let c = 0; c < 10; c++) if (luhnValid(body + c)) return body + c;
}
function ibanWith(cc, bban) {
  for (let c = 2; c <= 98; c++) {
    const cand = cc + String(c).padStart(2, "0") + bban;
    if (ibanMod97(cand)) return cand;
  }
}

const VISA = "4111111111111111";
const IBAN = "DE89370400440532013000";
const B64 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKjMzEfYyjiWA4R4/";
const BEGIN = "-----BEGIN PRIVATE " + "KEY-----";
const END = "-----END PRIVATE " + "KEY-----";
const hasKeyMaterial = (s) => /[A-Za-z0-9+/]{20,}/.test(s);
const fullwidth = (s) => s.replace(/\d/g, (d) => String.fromCharCode(0xff10 + Number(d)));

console.log("\n=== round-3 DLP regressions ===");

// ------------------------------------------------------------------------------------ R3-02
await test("R3-02 a JSON-escaped, truncated private key (no END marker) is redacted whole", async () => {
  const log = `{"private_key":"${BEGIN}\\n${B64}\\n${B64}\\n${B64.slice(0, 30)}`;
  hit(log, "private-key");
  const out = redact(log);
  assert.ok(!hasKeyMaterial(out), out);
  assert.match(out, /\[REDACTED:private-key\]/);
  // doubly escaped (JSON inside JSON) and \r\n
  const twice = `{"log":"{\\"k\\":\\"${BEGIN}\\\\n${B64}\\\\n${B64}`;
  assert.ok(!hasKeyMaterial(redact(twice)), redact(twice));
  const crlf = `${BEGIN}\\r\\n${B64}\\r\\n${B64}`;
  assert.ok(!hasKeyMaterial(redact(crlf)), redact(crlf));
});

await test("R3-02 a key with more than 10,000 characters between the markers is redacted whole", async () => {
  const body = rep(B64 + "\\n", 160); // ~12,800 characters of escaped body
  const complete = `{"k":"${BEGIN}\\n${body}${END}\\n"} thanks`;
  const out = redact(complete);
  assert.ok(!hasKeyMaterial(out), out.slice(0, 200));
  assert.match(out, /thanks$/);
  const real = `${BEGIN}\n${rep(B64 + "\n", 400)}${END}\nafter`; // real newlines, 30,000 characters
  assert.equal(redact(real), "[REDACTED:private-key]\nafter");
  const truncated = `${BEGIN}\n${rep(B64 + "\n", 400)}`; // no END at all
  assert.equal(redact(truncated), "[REDACTED:private-key]\n");
});

await test("R3-02 text after a truncated key is kept; the key's own lines are not", async () => {
  const t = `${BEGIN}\n${B64}\n${B64}\n\nThanks, please rotate it. Also see ticket 42.`;
  const out = redact(t);
  assert.ok(!hasKeyMaterial(out.replace(/\[REDACTED[^\]]*\]/g, "")), out);
  assert.match(out, /Thanks, please rotate it\. Also see ticket 42\.$/);
});

// ------------------------------------------------------------------------------------ R3-15 (keys)
await test("R3-15 talking ABOUT a private key header is not a private key", async () => {
  clean(`the PRIVATE KEY block starts with ${BEGIN} and ends with ${END}`);
  clean(`grep for '-----BEGIN RSA ${"PRIVATE KEY"}-----' in the repo`);
  clean(`headers look like ${BEGIN}\nand then the body follows`);
  clean(BEGIN);
});

await test("R3-15 a real key is still a key (complete, and truncated after a few lines)", async () => {
  hit(`${BEGIN}\n${B64}\n${END}`, "private-key");
  hit(`${BEGIN}\n${B64}`, "private-key");
  hit(`-----BEGIN OPENSSH ${"PRIVATE KEY"}-----\nb3BlbnNzaC1rZXktdjEAAAAA`, "private-key");
  hit(`-----BEGIN ENCRYPTED ${"PRIVATE KEY"}-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,ABCDEF0123456789\n\n${B64}`, "private-key");
  clean(`-----BEGIN PUBLIC KEY-----\n${B64}\n-----END PUBLIC KEY-----`);
  // PuTTY .ppk private block, and an empty BEGIN/END pair is not a key
  hit(`PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\nPrivate-Lines: 14\n${B64}\n${B64}`, "private-key");
  clean(`${BEGIN}\n${END}`);
  clean(`${BEGIN}\nAbC123xyz789`); // a 12-character fragment is not worth blocking a message for
  clean(`${BEGIN}\nabc\n${END} is how a block looks`.replace("abc\n", ""));
});

// ------------------------------------------------------------------------------------ R3-03
await test("R3-03 a redacted subject stays within 200 characters (validateOutgoing, redact mode)", async () => {
  const card = luhnNumber("4", 13);
  const subject = rep(card + " ", 11).trim(); // 153 characters, 11 findings
  assert.ok(subject.length <= 200);
  const r = validateOutgoing({ from: "a", to: "b", body: "hi", type: "fyi", subject }, { dlpMode: "redact" });
  assert.ok([...r.subject].length <= 200, `subject is ${r.subject.length} characters`);
  assert.match(r.subject, /^\[REDACTED:payment-card\]/);
  assert.doesNotMatch(r.subject.replace(/…$/, ""), /\[[^\]]*$/, "a marker was cut in half");
  assert.match(dlpNotice(r.dlp), /shortened/);
});

await test("R3-03 a subject that shrinks or keeps its length is left alone, and block mode still refuses", async () => {
  const r = applyDlp({ body: "hi", subject: "key " + "gh" + "p_" + rep("a1B2", 9) }, "redact");
  assert.equal(r.subject, "key [REDACTED:github-token]");
  assert.ok(!r.dlp.subjectShortened);
  assert.throws(() => validateOutgoing({ from: "a", to: "b", body: "hi", type: "fyi", subject: rep(VISA + " ", 11).trim() }, { dlpMode: "block" }), /sensitive/);
});

// ------------------------------------------------------------------------------------ R3-13
await test("R3-13 more card brands: Maestro, Mir, Dankort, Elo, Troy, JCB 308x, UnionPay 81, long Visa/Mastercard", async () => {
  const cards = {
    maestro50: "5018185296307414",
    maestro67: "6759185296307415",
    maestro12: luhnNumber("6759", 12),
    mir: luhnNumber("2201", 16),
    dankort: luhnNumber("5019", 16),
    elo: luhnNumber("636368", 16),
    troy: luhnNumber("9792", 16),
    jcb3088: luhnNumber("3088", 16),
    unionpay81: luhnNumber("81", 16),
    visa18: luhnNumber("4", 18),
    mc17: luhnNumber("51", 17),
    uzcard: luhnNumber("8600", 16),
  };
  for (const [name, n] of Object.entries(cards)) assert.deepEqual(kinds(`card ${n} exp 12/30`), ["payment-card"], `${name} ${n}`);
});

await test("R3-13 more IBAN countries (RU, SD, OM, NI, MN, FK) and lower-case IBANs", async () => {
  hit("pay RU0304452522540817810538091310419 now", "iban");
  for (const [cc, n] of [["SD", 14], ["OM", 19], ["MN", 16], ["FK", 14]]) {
    const iban = ibanWith(cc, "123456789012345678901234".slice(0, n));
    hit(`IBAN ${iban}`, "iban");
  }
  hit("iban: " + IBAN.toLowerCase(), "iban");
  hit("iban: " + IBAN.toLowerCase().replace(/(.{4})/g, "$1 ").trim(), "iban");
});

await test("R3-13 vendor credentials: Anthropic, OpenAI, GitLab, npm, SendGrid, Slack webhook, Azure, Google OAuth", async () => {
  const samples = {
    "anthropic-key": "sk-" + "ant-api03-" + "AbCdEfGh1234567890-_AbCdEfGh1234567890",
    "openai-key": "sk-" + "proj-" + "Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78",
    "gitlab-token": "glp" + "at-" + "AbCdEfGh1234567890xy",
    "npm-token": "npm" + "_" + "AbCdEfGh1234567890AbCdEfGh1234567890",
    "sendgrid-key": "SG" + "." + "AbCdEfGh1234567890-_" + "." + "AbCdEfGh1234567890-_",
    "slack-webhook": "https://hooks." + "slack.com/services/T01234567/B01234567/AbCdEfGh1234567890abcdEF",
    "azure-credential": "DefaultEndpointsProtocol=https;AccountName=x;Account" + "Key=" + "AbCdEfGh1234567890AbCdEfGh1234567890AbCdEfGh==",
    "google-oauth-token": "ya" + "29." + "a0AfH6SMBAbCdEfGh1234567890AbCdEf",
  };
  for (const [kind, s] of Object.entries(samples)) assert.deepEqual([...new Set(kinds(`config: ${s} ok`))], [kind], kind);
});

await test("R3-13 passwords in connection URLs are found (and only the password is redacted)", async () => {
  for (const u of [
    "postgres://admin:Sup3rS3cret@db.internal/app",
    "mongodb+srv://u:pw123@cluster0.example.net/db",
    "https://bob:s3cretpass@host/path",
    "redis://default:hunter2hunter2@cache:6379/0",
  ]) {
    hit(`DATABASE_URL=${u}`, "url-password");
  }
  assert.equal(redact("use postgres://admin:Sup3rS3cret@db.internal/app please"), "use postgres://admin:[REDACTED:url-password]@db.internal/app please");
});

await test("R3-13 Authorization headers: Bearer, Basic, Token", async () => {
  hit("curl -H 'Authorization: Bearer " + "q8Zk2m4Xv9Lp3Rt7Yw1Nc5Bd6Fh0Jg' https://api.example.com", "authorization-header");
  hit("Authorization: Basic dXNlcjpwYXNzd29yZDEyMw==", "authorization-header");
  hit('{"Authorization": "Token abcdef0123456789abcdef"}', "authorization-header");
  assert.equal(redact("Authorization: Bearer q8Zk2m4Xv9Lp3Rt7Yw1Nc5Bd6Fh0Jg"), "Authorization: Bearer [REDACTED:authorization-header]");
});

await test("R3-13 the new detectors don't fire on placeholders and ordinary text", async () => {
  for (const t of [
    "postgres://user:password@localhost/db",
    "postgres://${DB_USER}:${DB_PASS}@host/db",
    "postgres://user:<password>@host/db",
    "postgres://user:your-password-here@host/db",
    "https://user:$PASSWORD@example.com",
    "http://localhost:8080/path and https://example.com:443/x@y",
    "git clone ssh://git@github.com:2222/org/repo.git",
    "Authorization: Bearer <token>",
    "Authorization: Bearer ${TOKEN}",
    "Authorization: Bearer YOUR_TOKEN_HERE",
    "send an Authorization header with the Bearer scheme",
    "sk-some-long-kebab-case-identifier-with-no-digits-at-all",
    "sk-learn is a library; the task-queue-worker-service-name-with-many-parts-here-2 is a job",
    "https://hooks.slack.com/ is where webhooks live",
  ]) {
    clean(t);
  }
});

// ------------------------------------------------------------------------------------ R3-14
await test("R3-14 cards behind zero-width characters, full-width digits, NBSP, dots, slashes, odd groupings", async () => {
  const g = (s, sep, n = 4) => s.match(new RegExp(`.{1,${n}}`, "g")).join(sep);
  const variants = {
    zwsp: g(VISA, "\u200b"),
    "zwsp+spaces": g(VISA, " \u200b"),
    fullwidth: fullwidth(VISA),
    "fullwidth grouped": g(fullwidth(VISA), "\u3000"),
    nbsp: g(VISA, "\u00a0"),
    dots: g(VISA, "."),
    slashes: g(VISA, "/"),
    "8-8": g(VISA, " ", 8),
    "6-6-4": `${VISA.slice(0, 6)} ${VISA.slice(6, 12)} ${VISA.slice(12)}`,
    "two spaces": g(VISA, "  "),
    newline: g(VISA, "\n"),
    "soft hyphen": VISA.slice(0, 8) + "\u00ad" + VISA.slice(8),
    "arabic-indic digits": VISA.replace(/\d/g, (d) => String.fromCharCode(0x0660 + Number(d))),
  };
  for (const [name, v] of Object.entries(variants)) assert.deepEqual(kinds(`pay with ${v} thanks`), ["payment-card"], name);
});

await test("R3-14 IBANs behind lower case, ZWSP, NBSP, dashes, line breaks, odd grouping", async () => {
  const variants = {
    lower: IBAN.toLowerCase(),
    zwsp: IBAN.slice(0, 4) + "\u200b" + IBAN.slice(4),
    nbsp: IBAN.replace(/(.{4})/g, "$1\u00a0").trim(),
    "two spaces": IBAN.replace(/(.{4})/g, "$1  ").trim(),
    dashes: IBAN.replace(/(.{4})/g, "$1-").replace(/-$/, ""),
    linebreak: IBAN.slice(0, 11) + "\n" + IBAN.slice(11),
    odd: `${IBAN.slice(0, 4)} ${IBAN.slice(4, 7)} ${IBAN.slice(7, 14)} ${IBAN.slice(14)}`,
    fullwidth: IBAN.slice(0, 2) + fullwidth(IBAN.slice(2)),
  };
  for (const [name, v] of Object.entries(variants)) assert.deepEqual(kinds(`wire to ${v} today`), ["iban"], name);
});

await test("R3-14 a number split between subject and body is found (block) and redacted in both halves (redact)", async () => {
  const subject = "pay 4111 1111 1111";
  const body = "1111 please";
  assert.throws(() => applyDlp({ body, subject }, "block"), /payment card number \(subject\+body\)/);
  const r = applyDlp({ body, subject }, "redact");
  assert.ok(!/\d{4}/.test(r.subject + r.body), `${r.subject} | ${r.body}`);
  assert.match(r.subject, /^pay \[REDACTED:payment-card\]/);
  assert.match(r.body, /^\[REDACTED:payment-card\] please$/);
  // a private key whose header is in the subject
  const k = applyDlp({ subject: BEGIN, body: `${B64}\n${B64}` }, "redact");
  assert.ok(!hasKeyMaterial(k.subject + k.body), `${k.subject} | ${k.body}`);
});

await test("R3-14 redaction removes exactly the original characters (zero-width and full-width included)", async () => {
  assert.equal(redact(`card ${fullwidth(VISA)} ok`), "card [REDACTED:payment-card] ok");
  assert.equal(redact(`card 4111\u200b1111\u200b1111\u200b1111 ok`), "card [REDACTED:payment-card] ok");
  assert.equal(redact(`ключ ${IBAN.toLowerCase()} ok`), "ключ [REDACTED:iban] ok");
  // the offsets stay right after characters that were dropped from the scanned view
  assert.equal(redact(`x\u200b\u200b\u200b ${VISA} y`), `x\u200b\u200b\u200b [REDACTED:payment-card] y`);
});

await test("R3-14 secrets still found when the text has other non-ASCII (positions stay right)", async () => {
  const t = "Привет 👋 пароль: password=Xk39sLq02mZ!ab и карта " + VISA + " конец";
  assert.equal(redact(t), "Привет 👋 пароль: password=[REDACTED:secret-assignment] и карта [REDACTED:payment-card] конец");
});

// ------------------------------------------------------------------------------------ R3-19
await test("R3-19 passwords the heuristic used to let through are found", async () => {
  const P = "Xk39sLq02mZ9ab";
  for (const t of [
    "DB_PASSWORD=$uperS3cret!9x",
    'password: "$3cr3tP@ss"',
    "password=fake-Xk39sLq02mZ!",
    "password=example-Xk39sLq02mZ!",
    "password=your-Xk39sLq02mZ!",
    "password=<Xk39sLq02mZ!>",
    "password=%Xk39sLq02mZ!%",
    "password=`Xk39sLq02mZ!`",
    'password: "correct horse battery staple 9"',
    'password: "correct horse battery staple"',
    "password=correcthorsebatterystaple",
    `cli --password ${P}`,
    `cli --db-password '${P}'`,
    `mysql -u root -p${P}`,
    `sshpass -p ${P} ssh host`,
    `pwd=${P}`,
    `pass=${P}`,
    `credentials: ${P}`,
    `{\\"password\\":\\"${P}\\"}`,
    `passphrase = "${P}"`,
  ]) {
    hit(t, "secret-assignment");
  }
  assert.equal(redact("DB_PASSWORD=$uperS3cret!9x"), "DB_PASSWORD=[REDACTED:secret-assignment]");
  assert.equal(redact("mysql -pXk39sLq02mZ9 db"), "mysql -p[REDACTED:secret-assignment] db");
});

await test("R3-19 what is still not a secret: variables, templates, whole-value placeholders, prose, ports, other flags", async () => {
  for (const t of [
    "password=$DB_PASSWORD",
    'password: "${DB_PASSWORD}"',
    "password=$(cat /run/secrets/pw)",
    "password=your-password-here",
    "password=example_password",
    "password = <your password here>",
    "password=fake-password",
    'password: "Password must be at least 8 characters"',
    'password: "Enter your password"',
    'password: "must be at least 8 chars"',
    'password: "Password too weak!"',
    "docker run -p3000:3000/tcp img",
    "cli --password $PW",
    "cli --password $DB_PASSWORD",
    "cli --password ${DB_PASSWORD}",
    "docker run -p127.0.0.1:8080:80 img",
    'cli --password "$PW"',
    "cli --password <password>",
    "cli --password prompt",
    "docker run -p 8080:80 -p 3000:3000 img",
    "docker run -p8080:80 img",
    "gcc -pthread -pedantic main.c",
    "bypass: abcd1234efgh",
    "credentials: include",
    "pass: true",
  ]) {
    clean(t);
  }
});

// ------------------------------------------------------------------------------------ R3-15
await test("R3-15 ordinary engineering text is not flagged (timestamps, paths, identifiers, Luhn-valid ids)", async () => {
  for (const t of [
    "token=1700000000",
    "secret = 20240101",
    "private_key: path/to/key.pem",
    "private_key: ./keys/server.key",
    "api_key=my_api_key_1",
    "auth_token: undefined_value1",
    "user_id=4000000000000002 not found",
    "id: 5105105105105100",
    '{"userId":"5105105105105100"}',
    "request_id = 4111111111111111",
    "ts=4111111111111111",
  ]) {
    clean(t);
  }
});

await test("R3-15 ...without reopening the gaps: grouped numbers and real values after those keys are still found", async () => {
  hit("user_id: 4111 1111 1111 1111", "payment-card"); // an id is never written in groups of four
  hit("ref 1-4111 1111 1111 1111", "payment-card"); // a short number and a dash in front do not hide a card
  hit("card 4111111111111111 for user_id 7", "payment-card");
  hit("password=12345678", "secret-assignment"); // a number is a password when the key says password
  hit("token=Xk39sLq02mZ9ab", "secret-assignment");
  hit("api_key=my_api_key_1X9!", "secret-assignment");
});

await test("R3-15 still works: real secrets are found, ordinary text passes", async () => {
  hit("password = \"Sup3rS3cret!\"", "secret-assignment");
  hit("DB_PASSWORD=Xk9#mQ2!vL7p", "secret-assignment");
  hit("pay with " + VISA, "payment-card");
  hit("IBAN " + IBAN, "iban");
  hit("AKIA" + "IOSFODNN7EXAMPLE", "aws-access-key");
  clean("550e8400-e29b-41d4-a716-446655440000 and commit 0123456789abcdef0123456789abcdef01234567");
  clean("1700000000.123456 and 2026-11-19T12:34:56.789Z and +1 (415) 555-0132");
});

// ------------------------------------------------------------------------------------ R3-01 for the new code
await test("the new scanners stay linear: 50,000 characters of adversarial text each scan in under 300 ms", async () => {
  const nasty = [
    rep(BEGIN + "\\n", 1800),
    BEGIN + "\n" + rep(B64 + "\n", 700),
    BEGIN + rep("\\n" + B64, 700),
    rep("-----BEGIN A A A A A ", 2400),
    rep("4 ", 25000),
    rep("4111 1111 ", 5000),
    rep("0\u200b", 25000),
    rep("４", 50000),
    rep("sk-", 16000),
    rep("sk-" + rep("a", 60), 800),
    rep("a://b:", 8000),
    rep("http://u:", 5000) + rep("x", 40000),
    rep("--password ", 4500),
    rep("-p", 25000),
    rep("-pa1b2c3 ", 5000),
    rep("Authorization: Bearer ", 2200),
    "Authorization: Bearer " + rep(" ", 50000),
    rep("password: '", 4500),
    rep("password=" + rep("a", 600) + " ", 80),
    rep("DE89 ", 10000),
    rep("de89 3704 ", 5000),
    rep("id=", 16000),
  ];
  for (const n of nasty) {
    const t0 = performance.now();
    scanText(n.slice(0, 50000));
    const ms = performance.now() - t0;
    assert.ok(ms < 300, `scan took ${ms.toFixed(0)} ms for ${JSON.stringify(n.slice(0, 16))}...`);
  }
});

process.exit(summary() ? 1 : 0);
