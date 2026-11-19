// DLP suite: secrets and regulated data must not leave in a message.
//   node test/dlp.js [sqlite] [supabase-local] [slack-local]     (default: all three)
// Fixtures are assembled from pieces at run time so this file holds no literal secret (a secret
// scanner, or this very DLP, would flag it).
import assert from "node:assert/strict";
import { backendsFromArgs } from "./backends.js";
import { connectAgent, runServerExpectExit, summary, test, threadOf } from "./harness.js";

const dlp = await import("../stores/dlp.js").catch(() => null);
const need = () => assert.ok(dlp, "stores/dlp.js does not exist");
const kinds = (text) => (dlp ? dlp.scanText(text).map((f) => f.kind) : []);
const rep = (s, n) => s.repeat(n);
const hex = (n) => rep("0123456789abcdef", Math.ceil(n / 16)).slice(0, n);
const b64u = (o) => Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url");

// a Luhn-valid number: prefix + filler digits + check digit
function luhnNumber(prefix, len) {
  const body = (prefix + rep("7", len)).slice(0, len - 1);
  for (let c = 0; c < 10; c++) if (dlp.luhnValid(body + c)) return body + c;
}

const SECRETS = {
  "private-key": "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn\n-----END RSA " + "PRIVATE KEY-----",
  "aws-access-key": "AK" + "IA" + "IOSFODNN7EXAMPLE",
  "aws-secret-key": "aws_secret_" + "access_key = " + "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY",
  "github-token": "gh" + "p_" + rep("a1B2", 9),
  "slack-token": "xox" + "b-" + "123456789012-1234567890123-abcdefABCDEF123456",
  "stripe-key": "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc",
  "google-api-key": "AI" + "za" + "SyA-" + rep("x9Z_", 7) + "abc",
  jwt:
    b64u({ alg: "HS256", typ: "JWT" }) + "." + b64u({ sub: "1234567890", name: "x" }) + "." + b64u("signaturesignature"),
  "bridge-token": "ab" + "t_" + hex(64),
  "supabase-secret-key": "sb_" + "secret_" + "AbCdEfGhIjKlMnOpQrStUv",
  "secret-assignment": 'DB_PASS' + 'WORD="hunter2hunter2"',
};

// ---------------------------------------------------------------------------------- scanner

console.log("\n=== dlp: scanner ===");

await test("every secret kind is detected, and named correctly", async () => {
  need();
  for (const [kind, text] of Object.entries(SECRETS)) {
    assert.deepEqual([...new Set(kinds(`here is the config:\n${text}\nthanks`))], [kind], kind);
  }
  for (const t of ["gho_", "ghs_", "ghu_"]) assert.deepEqual(kinds("gh" + t.slice(2) + rep("Z9", 18)), ["github-token"], t);
  assert.deepEqual(kinds("github_" + "pat_11ABCDEFG0abcdefghij_" + rep("k1", 20)), ["github-token"]);
  for (const t of ["xoxa-", "xoxp-", "xoxr-", "xoxs-", "xapp-"]) assert.deepEqual(kinds(t + "1-A0123456789-abcdef"), ["slack-token"], t);
  assert.deepEqual(kinds("rk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"), ["stripe-key"]);
  assert.deepEqual(kinds("AS" + "IA" + "IOSFODNN7EXAMPLE"), ["aws-access-key"]);
});

await test("a truncated private key header alone is still caught", async () => {
  need();
  assert.deepEqual(kinds("-----BEGIN OPENSSH " + "PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA"), ["private-key"]);
  assert.deepEqual(kinds("-----BEGIN " + "PRIVATE KEY-----"), ["private-key"]);
  assert.deepEqual(kinds("-----BEGIN PGP " + "PRIVATE KEY BLOCK-----"), ["private-key"]);
  assert.deepEqual(kinds("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq\n-----END PUBLIC KEY-----"), [], "public keys are fine");
  assert.deepEqual(kinds("-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIE\n-----END CERTIFICATE-----"), []);
});

await test("generic assignments: key = value, in the usual syntaxes", async () => {
  need();
  const flagged = [
    'password = "Sup3rS3cret!"',
    "password=hunter2hunter2",
    "passwd: s3cr3t-value-123",
    '"api_key": "abcd1234efgh5678"',
    "API_KEY=zx81-ab92-77cd",
    "client_secret: 'AbCdEfGh12345'",
    "export GITHUB_TOKEN=Tok3nValue99",
    "db.secret = 'CorrectHorseBattery'",
    "token: 9f8a7b6c5d4e3f2a",
    'secret_key => "Zz9!yyyyyyyy"',
  ];
  for (const t of flagged) assert.deepEqual(kinds(t), ["secret-assignment"], t);
});

await test("payment cards: Luhn-valid numbers of every major scheme, with or without separators", async () => {
  need();
  const cards = {
    visa16: luhnNumber("4", 16),
    visa13: luhnNumber("4", 13),
    visa19: luhnNumber("4", 19),
    mc51: luhnNumber("51", 16),
    mc55: luhnNumber("55", 16),
    mc2221: luhnNumber("2221", 16),
    mc2720: luhnNumber("2720", 16),
    amex34: luhnNumber("34", 15),
    amex37: luhnNumber("37", 15),
    disc6011: luhnNumber("6011", 16),
    disc65: luhnNumber("65", 16),
    disc644: luhnNumber("644", 16),
    jcb: luhnNumber("3530", 16),
    unionpay: luhnNumber("62", 16),
    diners: luhnNumber("3056", 14),
  };
  for (const [name, n] of Object.entries(cards)) {
    assert.deepEqual(kinds(`card ${n} exp 12/30`), ["payment-card"], `${name} ${n}`);
  }
  const v = cards.visa16;
  assert.deepEqual(kinds(`pay with ${v.replace(/(.{4})/g, "$1 ").trim()} please`), ["payment-card"], "spaces");
  assert.deepEqual(kinds(`pay with ${v.replace(/(.{4})/g, "$1-").slice(0, -1)} please`), ["payment-card"], "dashes");
  const a = cards.amex37;
  assert.deepEqual(kinds(`amex ${a.slice(0, 4)} ${a.slice(4, 10)} ${a.slice(10)}`), ["payment-card"], "amex 4-6-5");
  assert.deepEqual(kinds(`4111111111111111`), ["payment-card"]);
  assert.deepEqual(kinds(`4242 4242 4242 4242`), ["payment-card"]);
});

await test("card-shaped numbers that are NOT cards are left alone", async () => {
  need();
  const v = luhnNumber("4", 16);
  const badLuhn = v.slice(0, 15) + ((Number(v[15]) + 1) % 10); // Luhn check digit off by one
  const unknownIin = luhnNumber("1", 16); // Luhn-valid, but no issuer owns 1xxx
  for (const t of [
    `order ${badLuhn}`,
    `ORD-${badLuhn}`,
    `ref ${unknownIin}`,
    "1234567890123456",
    "invoice 20261119123456789",
    "ts 1700000000123", // epoch milliseconds
    "slack 1700000000.123456",
    "4111-1111-1111", // too short
    `${v}${v}`, // 32 digits
    "id=12345678901234567890123", // 23 digits
    `ref${v}`, // glued to letters, underscores or hyphens: an identifier, not a card
    `${v}abc`,
    `tx_${v}`,
    `tx-${v}`,
    `${v}-7`,
  ]) {
    assert.deepEqual(kinds(t), [], t);
  }
});

await test("IBANs: valid ones are caught (compact and grouped), wrong checksum or length are not", async () => {
  need();
  const valid = [
    "GB82WEST12345698765432",
    "DE89370400440532013000",
    "FR1420041010050500013M02606",
    "NL91ABNA0417164300",
    "ES9121000418450200051332",
    "IT60X0542811101000000123456",
    "CH9300762011623852957",
    "BE68539007547034",
    "NO9386011117947",
    "SA0380000000608010167519",
  ];
  const group = (s) => s.replace(/(.{4})/g, "$1 ").trim();
  for (const i of valid) {
    assert.deepEqual(kinds(`IBAN: ${i}`), ["iban"], i);
    assert.deepEqual(kinds(`please wire to ${group(i)} today`), ["iban"], group(i));
  }
  // the right checksum is not enough: the length must be the country's
  const withChecksum = (cc, bban) => {
    for (let c = 2; c <= 98; c++) {
      const cand = cc + String(c).padStart(2, "0") + bban;
      if (dlp.ibanMod97(cand)) return cand;
    }
  };
  assert.deepEqual(kinds(withChecksum("DE", "370400440532013000")), ["iban"], "control: DE with 18 digits is a real length");
  assert.deepEqual(kinds(withChecksum("DE", "37040044053201300")), [], "DE, mod-97 valid, one digit short");
  assert.deepEqual(kinds(withChecksum("DE", "3704004405320130000")), [], "DE, mod-97 valid, one digit long");
  assert.deepEqual(kinds(withChecksum("GB", "WEST1234569876543")), [], "GB, mod-97 valid, one char long");
  assert.deepEqual(kinds("GB82WEST12345698765433"), [], "checksum off");
  assert.deepEqual(kinds("DE8937040044053201300"), [], "one char short");
  assert.deepEqual(kinds("DE893704004405320130001"), [], "one char long");
  assert.deepEqual(kinds("XX89370400440532013000"), [], "unknown country");
  assert.deepEqual(kinds("GB82 WEST 1234"), [], "partial");
  assert.deepEqual(kinds("GB82WEST12345698765432X"), [], "trailing alnum glued on");
  assert.deepEqual(kinds("DE89 3704 0044 0532 0130 00 AND MORE TEXT"), ["iban"], "stops at the exact length");
});

await test("false positives: the everyday strings of an engineering chat are not flagged", async () => {
  need();
  const sha = hex(40);
  const png = "data:image/png;base64," + Buffer.from(rep("\x89PNG\r\n\x1a\nAKIA", 3000)).toString("base64");
  const clean = [
    "550e8400-e29b-41d4-a716-446655440000",
    "thread 123e4567-e89b-12d3-a456-426614174000 hop 3",
    sha,
    `commit ${sha.slice(0, 7)} fixes #1234; merged ${sha}`,
    "1700000000.123456",
    "thread_ts=1731961234.000200",
    "2026-11-19T12:34:56.789Z",
    "2026-11-19 12:34:56 +0100",
    "call me on +1 (415) 555-0132 or +44 20 7946 0958 or 4155550132",
    "tel: 020 7946 0958 / 0049 30 901820",
    "order #4000000000000 failed; order 1000000000012; ticket 99887766554433",
    "version 1.2.3, v22.13.0, 10.20.30-beta.1+build.5, node 22.23.5",
    png,
    "abt_" + hex(63),
    "abt_" + hex(10) + " (an agent token, truncated)",
    "ab" + "t_" + hex(64).toUpperCase().slice(0, 10),
    "sb_publishable_test",
    "the word password without a value, and a token is mentioned in prose",
    "const token = getToken()",
    "const token = await getToken();",
    "const token = getToken2();",
    "const token = refreshToken;",
    "password = prompt",
    "let password = prompt('Password?')",
    "password: string",
    "token: Optional[str] = None",
    'const secret = process.env.SECRET_KEY',
    "api_key = os.environ['API_KEY']",
    "password = $DB_PASSWORD",
    "password=${DB_PASSWORD}",
    "password = <your password here>",
    "password = ********",
    "token=changeme",
    "const token = req.headers.authorization",
    "token = tokens[0]",
    "max_tokens = 4096, tokens: 12345678",
    '{"token": string, "user": {"id": 1}}',
    "password == 'abcdefgh1'",
    "secretary: abcd1234efgh",
    "AGENT_BRIDGE_TOKEN_FILE=/home/u/.agent-bridge/tokens/a.token",
    "SELECT * FROM users WHERE password_hash = 'x'; DROP TABLE t; --",
    "'); drop table bridge_messages; -- and $$ dollar $$",
    "a.b.c and foo.bar.baz and eyJ.not.jwt and eyJhbGci.x.y",
    b64u({ typ: "JWT" }) + "." + b64u({ sub: "1" }) + "." + b64u("s"), // header without alg: not a JWT
    "AKIA is the prefix of AWS access key ids; AKIAIOSFODNN7 is short",
    "AIza is Google's prefix",
    "-----BEGIN PUBLIC KEY-----",
    "ghp_ tokens start with ghp_; gho_short",
    "xoxb- tokens look like xoxb-short",
    "DE89 is a country code; GB82 too; IBAN formats vary",
    "TL;DR ABCD1234 EFGH5678 IJKL9012",
  ];
  for (const t of clean) assert.deepEqual(kinds(t), [], t.length > 90 ? t.slice(0, 90) + "…" : t);
});

await test("the same secret twice, adjacent secrets, and overlapping detectors are each reported once", async () => {
  need();
  const a = SECRETS["aws-access-key"];
  assert.deepEqual(kinds(`${a} ${a}`), ["aws-access-key", "aws-access-key"]);
  // a bridge token assigned to a variable is one finding (the token), not two
  assert.deepEqual(kinds(`AGENT_BRIDGE_TOKEN=${SECRETS["bridge-token"]}`), ["bridge-token"]);
  assert.deepEqual(kinds(`token=${SECRETS.jwt}`), ["jwt"]);
});

await test("scanning a maximum-size body is fast (no catastrophic regex)", async () => {
  need();
  const nasty = [
    rep("password = ", 4000),
    rep("-----BEGIN PRIVATE KEY-----\n", 2000),
    rep("-----BEGIN PRIVATE KEY-----\n!\n", 1700),
    rep("4111 ", 10000),
    rep("GB82 ", 10000),
    rep("eyJhb.", 8000),
    rep("a", 50000),
    rep("0", 50000),
    rep("aws_secret ", 4000),
    rep(" ", 50000),
  ];
  for (const n of nasty) {
    const t0 = Date.now();
    dlp.scanText(n.slice(0, 50000));
    assert.ok(Date.now() - t0 < 1500, `${n.slice(0, 20)} took ${Date.now() - t0}ms`);
  }
});

await test("modes: block names kinds but never the secret; redact masks; warn/off pass through", async () => {
  need();
  const body = `use ${SECRETS["aws-access-key"]} and card ${luhnNumber("4", 16)} to pay`;
  const subject = "key " + SECRETS["github-token"];
  assert.throws(() => dlp.applyDlp({ body, subject }, "block"), (e) => {
    assert.match(e.message, /AWS access key id \(body\)/);
    assert.match(e.message, /payment card number \(body\)/);
    assert.match(e.message, /GitHub token \(subject\)/);
    for (const secret of [SECRETS["aws-access-key"], luhnNumber("4", 16), SECRETS["github-token"]]) {
      assert.ok(!e.message.includes(secret), "the error echoed the secret");
    }
    return true;
  });
  const r = dlp.applyDlp({ body, subject }, "redact");
  assert.equal(r.body, `use [REDACTED:aws-access-key] and card [REDACTED:payment-card] to pay`);
  assert.equal(r.subject, "key [REDACTED:github-token]");
  assert.equal(r.dlp.action, "redacted");
  const w = dlp.applyDlp({ body, subject }, "warn");
  assert.equal(w.body, body);
  assert.equal(w.dlp.action, "warned");
  assert.equal(w.dlp.findings.length, 3);
  const o = dlp.applyDlp({ body, subject }, "off");
  assert.equal(o.body, body);
  assert.deepEqual(o.dlp.findings, []);
  assert.equal(dlp.applyDlp({ body: "hello", subject: null }, "block").dlp.action, "none");
});

await test("redaction keeps the text around a secret, including a generic assignment's key", async () => {
  need();
  const t = `DB_PASSWORD="hunter2hunter2"\nhost=db1`;
  assert.equal(dlp.redactText(t, dlp.scanText(t)), `DB_PASSWORD="[REDACTED:secret-assignment]"\nhost=db1`);
});

await test("the mode comes from AGENT_BRIDGE_DLP: default block, case-insensitive, typos are errors", async () => {
  need();
  assert.equal(dlp.dlpModeFromEnv({}), "block");
  assert.equal(dlp.dlpModeFromEnv({ AGENT_BRIDGE_DLP: "" }), "block");
  assert.equal(dlp.dlpModeFromEnv({ AGENT_BRIDGE_DLP: " Redact " }), "redact");
  assert.equal(dlp.dlpModeFromEnv({ AGENT_BRIDGE_DLP: "off" }), "off");
  assert.throws(() => dlp.dlpModeFromEnv({ AGENT_BRIDGE_DLP: "blok" }), /must be one of block, redact, warn, off/);
});

await test("a server refuses to start with a mistyped AGENT_BRIDGE_DLP (no silent loss of protection)", async () => {
  const b = (await backendsFromArgs(["sqlite"]))[0]();
  const be = await b;
  try {
    const r = await runServerExpectExit({ ...be.envFor("frontend"), AGENT_BRIDGE_DLP: "blok" });
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /AGENT_BRIDGE_DLP must be one of/);
  } finally {
    await be.cleanup();
  }
});

// ---------------------------------------------------------------------------------- through the stores

const CARD = dlp ? luhnNumber("51", 16) : "";
const LEAKY = () => `deploy with ${SECRETS["aws-access-key"]} and pay with ${CARD}`;

for (const make of await backendsFromArgs(process.argv.length > 2 ? undefined : ["sqlite", "supabase-local", "slack-local"])) {
  const b = await make();
  const N = b.nameOf;
  console.log(`\n=== dlp through ${b.name} ===`);
  const open = [];
  const agent = async (name, env = {}) => {
    const a = await connectAgent(b, name, env);
    open.push(a);
    return a;
  };
  try {
    for (const a of ["frontend", "backend"]) await b.addAgent(a);
    const be = await agent("backend");

    await test("default (block): a message with secrets is refused, names the kinds, never echoes them", async () => {
      const fe = await agent("frontend");
      const r = await fe.call("send_message", { to: N("backend"), body: LEAKY(), subject: "token " + SECRETS["github-token"] });
      assert.equal(r.isError, true, r.text);
      assert.match(r.text, /AWS access key id \(body\)/);
      assert.match(r.text, /payment card number \(body\)/);
      assert.match(r.text, /GitHub token \(subject\)/);
      assert.ok(!r.text.includes(SECRETS["aws-access-key"]) && !r.text.includes(CARD) && !r.text.includes(SECRETS["github-token"]), "echoed a secret");
      assert.match((await be.call("check_inbox")).text, /Inbox empty/, "a blocked message must not arrive");
      const who = JSON.parse((await fe.call("whoami")).text);
      assert.equal(who.dlp, "block");
    });

    await test("default (block): clean messages still go through, replies included", async () => {
      const fe = await agent("frontend");
      const sent = await fe.call("send_message", {
        to: N("backend"),
        subject: "build 7 at 2026-11-19T10:00:00Z",
        body: "commit " + hex(40) + " order 4111111111111112 uuid 550e8400-e29b-41d4-a716-446655440000 const token = getToken()",
      });
      assert.equal(sent.isError, false, sent.text);
      assert.ok(!/DLP/.test(sent.text), sent.text);
      const got = await be.call("check_inbox");
      assert.match(got.text, /order 4111111111111112/);
      const reply = await be.call("send_message", { to: N("frontend"), body: "ack", type: "response", thread_id: threadOf(sent.text) });
      assert.equal(reply.isError, false, reply.text);
    });

    await test("a secret in a reply is blocked too (every send path, not just new threads)", async () => {
      const fe = await agent("frontend");
      const sent = await fe.call("send_message", { to: N("backend"), body: "hi again" });
      const thread = threadOf(sent.text);
      await be.call("check_inbox");
      const r = await be.call("send_message", { to: N("frontend"), body: "key " + SECRETS["aws-access-key"], type: "response", thread_id: thread });
      assert.equal(r.isError, true, r.text);
      assert.match(r.text, /AWS access key id/);
    });

    await test("redact: the message is sent with [REDACTED:<kind>] in place of each match, and the sender is told", async () => {
      const fe = await agent("frontend", { AGENT_BRIDGE_DLP: "redact" });
      await be.call("check_inbox");
      const r = await fe.call("send_message", { to: N("backend"), body: LEAKY(), subject: "key " + SECRETS["github-token"] });
      assert.equal(r.isError, false, r.text);
      assert.match(r.text, /DLP: redacted before sending: .*AWS access key id \(body\).*payment card number \(body\).*GitHub token \(subject\)/);
      assert.ok(!r.text.includes(SECRETS["aws-access-key"]));
      const got = (await be.call("check_inbox")).text;
      assert.match(got, /\[REDACTED:aws-access-key\]/);
      assert.match(got, /\[REDACTED:payment-card\]/);
      assert.match(got, /subject: key \[REDACTED:github-token\]/);
      for (const s of [SECRETS["aws-access-key"], CARD, SECRETS["github-token"]]) assert.ok(!got.includes(s), "the secret reached the recipient");
      assert.equal(JSON.parse((await fe.call("whoami")).text).dlp, "redact");
    });

    await test("redact: the stored thread holds the redacted text, not the original", async () => {
      const fe = await agent("frontend", { AGENT_BRIDGE_DLP: "redact" });
      const r = await fe.call("send_message", { to: N("backend"), body: "pw " + SECRETS["secret-assignment"] });
      await be.call("check_inbox");
      const hist = (await fe.call("get_thread", { thread_id: threadOf(r.text) })).text;
      assert.match(hist, /\[REDACTED:secret-assignment\]/);
      assert.ok(!hist.includes("hunter2hunter2"));
    });

    await test("warn: the message is sent unchanged and the sender is warned what it contained", async () => {
      const fe = await agent("frontend", { AGENT_BRIDGE_DLP: "warn" });
      await be.call("check_inbox");
      const r = await fe.call("send_message", { to: N("backend"), body: LEAKY() });
      assert.equal(r.isError, false, r.text);
      assert.match(r.text, /DLP warning: .*AWS access key id \(body\).*payment card number \(body\)/);
      assert.ok(!r.text.includes(SECRETS["aws-access-key"]), "the warning must not repeat the secret");
      assert.ok((await be.call("check_inbox")).text.includes(SECRETS["aws-access-key"]));
      assert.equal(JSON.parse((await fe.call("whoami")).text).dlp, "warn");
    });

    await test("off: nothing is scanned and nothing is said", async () => {
      const fe = await agent("frontend", { AGENT_BRIDGE_DLP: "off" });
      await be.call("check_inbox");
      const r = await fe.call("send_message", { to: N("backend"), body: LEAKY() });
      assert.equal(r.isError, false, r.text);
      assert.ok(!/DLP/.test(r.text), r.text);
      assert.ok((await be.call("check_inbox")).text.includes(CARD));
      assert.equal(JSON.parse((await fe.call("whoami")).text).dlp, "off");
    });

    await test("max-length bodies still work, and redaction growth past the limit is refused", async () => {
      const fe = await agent("frontend", { AGENT_BRIDGE_DLP: "redact" });
      const limit = b.maxBody;
      const ok = await fe.call("send_message", { to: N("backend"), body: "x".repeat(limit - 10) + " " + "word" });
      assert.equal(ok.isError, false, ok.text);
      await be.call("check_inbox", { limit: 100 });
      // a 16-digit card (16 chars) becomes "[REDACTED:payment-card]" (23 chars)
      const grow = (limit - 1) - Math.floor((limit - 1) / 17) * 17;
      const body = (" " + CARD).repeat(Math.floor((limit - 1) / 17)) + " ".repeat(grow);
      assert.ok(body.length <= limit);
      const r = await fe.call("send_message", { to: N("backend"), body });
      assert.equal(r.isError, true, r.text);
      assert.match(r.text, /too long after redaction/);
    });
  } finally {
    for (const a of open) await a.close().catch(() => {});
    await b.cleanup();
  }
}

process.exit(summary() ? 1 : 0);
