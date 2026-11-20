// Regression tests for adversary round 2, relay findings (docs/adversary/round-02.md):
// R2-01 02 03 04 05 09 10 13 14 15. One or more tests per finding. Written before the fixes: each must
// fail on the code the round attacked, then pass.
//   node test/regressions-r2-relay.js
import assert from "node:assert/strict";
import net from "node:net";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { appendFileSync, mkdtempSync, readFileSync, writeFileSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { randomBytes } from "node:crypto";
import { startRelayProcess } from "./backends.js";
import { rmrf, skip, summary, test } from "./harness.js";
import { SupabaseAdmin } from "../stores/supabase.js";
import { AuditLog, verifyAuditLog } from "../relay-audit.js";
import { loadConfig, startRelay } from "../relay.js";

const sh = promisify(execFile);
const tmp = mkdtempSync(join(tmpdir(), "agent-bridge-r2-relay-"));
const key = () => randomBytes(32).toString("hex");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const openSockTls = (port) =>
  new Promise((resolve, reject) => {
    const t0 = Date.now();
    const sock = net.connect(port, "127.0.0.1", () => resolve({ sock, closed: new Promise((r) => sock.once("close", () => r(Date.now() - t0))) }));
    sock.resume(); // read (and discard) so that the server closing the connection is noticed at once
    sock.on("error", () => {});
    sock.once("error", reject);
  });
let n = 0;
const fresh = (name) => join(tmp, `${name}-${n++}`);
const readAudit = (p) => readFileSync(p, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
// like readAudit, but a torn (junk) line is skipped instead of throwing
const readAuditLoose = (p) =>
  readFileSync(p, "utf8")
    .split("\n")
    .filter(Boolean)
    .flatMap((l) => {
      try {
        return [JSON.parse(l)];
      } catch {
        return [];
      }
    });

async function rpc(base, fn, body, apikey, { raw } = {}) {
  const res = await fetch(`${base}/rest/v1/rpc/${fn}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(apikey ? { apikey } : {}) },
    body: raw ?? JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {}
  return { status: res.status, json, text };
}

async function relayWith(env = {}, args = []) {
  const dbPath = env.RELAY_DB ?? fresh("db") + ".db";
  const r = await startRelayProcess({ env: { RELAY_DB: dbPath, ...env }, args });
  r.dbPath = dbPath;
  r.admin = new SupabaseAdmin({ url: r.url, secretKey: r.adminKey });
  r.call = (fn, body, apikey = "relay", opts) => rpc(r.url, fn, body, apikey, opts);
  r.tokens = {};
  r.addAgents = async (...names) => {
    for (const nm of names) r.tokens[nm] = await r.admin.createAgent(nm, `agent ${nm}`);
  };
  r.send = (from, to, body) => r.call("bridge_send", { p_token: r.tokens[from], p_to: to, p_body: body, p_type: "fyi" });
  return r;
}
const refusedAtStart = async (env, args = []) => {
  try {
    const r = await startRelayProcess({ env: { RELAY_DB: fresh("db") + ".db", ...env }, args });
    await r.stop();
    return null;
  } catch (e) {
    return e;
  }
};
const messageCount = (dbPath, where = "1=1") => {
  const db = new DatabaseSync(dbPath, { readOnly: true, timeout: 5000 });
  const c = db.prepare(`SELECT COUNT(*) AS n FROM messages WHERE ${where}`).get().n;
  db.close();
  return c;
};

// an in-process relay (to reach into its audit writer and server settings)
async function inProcess(env = {}) {
  const config = loadConfig({ RELAY_ADMIN_KEY: key(), RELAY_PORT: "0", RELAY_DB: fresh("db") + ".db", ...env }, []);
  const relay = await startRelay(config);
  relay.config = config;
  relay.call = (fn, body, apikey = "relay", opts) => rpc(relay.url, fn, body, apikey, opts);
  relay.admin = new SupabaseAdmin({ url: relay.url, secretKey: config.adminKey });
  return relay;
}

const opensslOk = await sh("openssl", ["version"]).then(() => true, () => false);

// ------------------------------------------------------------------ R2-01 / R2-03 / R2-10: security switches fail closed

console.log("\n=== R2-01: RELAY_LEGAL_HOLD and the other switches ===");

await test("R2-01 every spelling of 'on' really turns the legal hold on (purge and delete-agent refuse)", async () => {
  for (const v of ["1", "true", "TRUE", "yes", "On", "ON", " yes "]) {
    const r = await relayWith({ RELAY_LEGAL_HOLD: v });
    try {
      await r.addAgents("alice", "bob");
      await r.send("alice", "bob", "held");
      const purge = await r.call("bridge_admin_purge", { p_older_than: "0 seconds" }, r.adminKey);
      assert.equal(purge.status, 400, `RELAY_LEGAL_HOLD=${JSON.stringify(v)}: purge was ${purge.status} ${purge.text}`);
      assert.match(purge.text, /Legal hold/);
      const del = await r.call("bridge_admin_delete_agent", { p_name: "alice" }, r.adminKey);
      assert.equal(del.status, 400, `RELAY_LEGAL_HOLD=${JSON.stringify(v)}: delete-agent was ${del.status}`);
      assert.equal(messageCount(r.dbPath), 1);
    } finally {
      await r.stop();
    }
  }
});

await test("R2-01 'off' spellings (0 false no off empty) start with the hold off; anything else refuses to start", async () => {
  for (const v of ["0", "false", "No", "OFF", ""]) {
    const r = await relayWith({ RELAY_LEGAL_HOLD: v });
    try {
      await r.addAgents("alice", "bob");
      await r.send("alice", "bob", "x");
      assert.equal((await r.call("bridge_admin_purge", { p_older_than: "0 seconds" }, r.adminKey)).status, 200, `RELAY_LEGAL_HOLD=${JSON.stringify(v)}`);
    } finally {
      await r.stop();
    }
  }
  for (const v of ["maybe", "2", "tru", "enabled", "y"]) {
    const e = await refusedAtStart({ RELAY_LEGAL_HOLD: v });
    assert.ok(e, `RELAY_LEGAL_HOLD=${JSON.stringify(v)} was accepted`);
    assert.match(e.stderr, /RELAY_LEGAL_HOLD/);
  }
});

await test("R2-01 RELAY_AUDIT_BODIES is parsed the same strict way", async () => {
  const audit = fresh("bodies") + ".jsonl";
  const r = await relayWith({ RELAY_AUDIT_LOG: audit, RELAY_AUDIT_BODIES: "true" });
  await r.addAgents("alice", "bob");
  await r.send("alice", "bob", "BODY-IN-AUDIT-LOG");
  await r.stop();
  assert.ok(readFileSync(audit, "utf8").includes("BODY-IN-AUDIT-LOG"), "RELAY_AUDIT_BODIES=true was ignored");
  const e = await refusedAtStart({ RELAY_AUDIT_BODIES: "sometimes", RELAY_AUDIT_LOG: fresh("a") });
  assert.match(e?.stderr ?? "", /RELAY_AUDIT_BODIES/);
});

await test("R2-01 the effective security posture is printed at startup", async () => {
  const audit = fresh("posture") + ".jsonl";
  const r = await relayWith({ RELAY_LEGAL_HOLD: "yes", RELAY_MIN_RETENTION_DAYS: "30", RELAY_AUDIT_LOG: audit });
  await r.stop();
  const out = r.stdout();
  assert.match(out, /posture: TLS: off/);
  assert.match(out, /mTLS: off/);
  assert.match(out, /legal hold: ON/);
  assert.match(out, /minimum retention: 30 day/);
  assert.match(out, /audit: on/);
  const plain = await relayWith();
  await plain.stop();
  assert.match(plain.stdout(), /legal hold: off/);
  assert.match(plain.stdout(), /audit: off/);
});

console.log("\n=== R2-03: an empty RELAY_TLS_CA must not turn mutual TLS off ===");

if (!opensslOk) {
  skip("R2-03 tests", "openssl is not installed");
} else {
  const pkiDir = mkdtempSync(join(tmp, "pki-"));
  const o = (...a) => sh("openssl", a, { cwd: pkiDir });
  await o("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=test-ca");
  await o("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key", "-out", "server.csr", "-subj", "/CN=localhost");
  writeFileSync(join(pkiDir, "server.ext"), "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n");
  await o("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "server.pem", "-days", "2", "-extfile", "server.ext");
  const pki = (f) => join(pkiDir, f);
  const good = { RELAY_TLS_CERT: pki("server.pem"), RELAY_TLS_KEY: pki("server.key") };
  const empty = fresh("empty");
  writeFileSync(empty, "");
  const notPem = fresh("notpem");
  writeFileSync(notPem, "hello, not a certificate\n");

  await test("R2-03 set-but-empty RELAY_TLS_CA / CERT / KEY, empty or non-PEM files: the relay refuses to start", async () => {
    for (const [env, name] of [
      [{ ...good, RELAY_TLS_CA: "" }, "RELAY_TLS_CA"],
      [{ ...good, RELAY_TLS_CA: "   " }, "RELAY_TLS_CA"],
      [{ ...good, RELAY_TLS_CERT: "" }, "RELAY_TLS_CERT"],
      [{ ...good, RELAY_TLS_KEY: "" }, "RELAY_TLS_KEY"],
      [{ ...good, RELAY_TLS_CA: empty }, "RELAY_TLS_CA"],
      [{ ...good, RELAY_TLS_CA: notPem }, "RELAY_TLS_CA"],
      [{ ...good, RELAY_TLS_CA: join(tmp, "no-such-ca.pem") }, "RELAY_TLS_CA"],
      [{ ...good, RELAY_TLS_KEY: empty }, "RELAY_TLS_KEY"],
      [{ ...good, RELAY_TLS_CERT: notPem }, "RELAY_TLS_CERT"],
    ]) {
      const e = await refusedAtStart(env);
      assert.ok(e, `started with ${JSON.stringify(env)}`);
      assert.match(e.stderr, new RegExp(name), e.stderr);
    }
    // a set-but-empty CA also refuses when given as a flag
    const e = await refusedAtStart(good, ["--tls-ca", ""]);
    assert.ok(e, "--tls-ca '' was accepted");
  });

  await test("R2-03 startup says whether client certificates are required", async () => {
    const mtls = await relayWith({ ...good, RELAY_TLS_CA: pki("ca.pem") });
    await mtls.stop();
    assert.match(mtls.stdout(), /posture: TLS: on/);
    assert.match(mtls.stdout(), /mTLS: required/);
    const tlsOnly = await relayWith(good);
    await tlsOnly.stop();
    assert.match(tlsOnly.stdout(), /posture: TLS: on/);
    assert.match(tlsOnly.stdout(), /mTLS: off/);
  });

  await test("R2-15 a client that connects to the TLS port and never starts the handshake is dropped within the timeout", async () => {
    const r = await relayWith({ ...good, RELAY_IDLE_TIMEOUT_MS: "1000", RELAY_HEADERS_TIMEOUT_MS: "1000" });
    try {
      const socks = [];
      for (let i = 0; i < 5; i++) socks.push(await openSockTls(r.port));
      const timedOut = Symbol("open");
      const res = await Promise.all(socks.map((s) => Promise.race([s.closed, sleep(6000).then(() => timedOut)])));
      assert.equal(res.filter((x) => x === timedOut).length, 0, "a silent TLS connection was still open after 6 s");
    } finally {
      await r.stop();
    }
  });
}

await test("R2-03 empty admin/auditor key files and unreadable ones refuse to start", async () => {
  const empty = fresh("emptykey");
  writeFileSync(empty, "\n");
  assert.match((await refusedAtStart({ RELAY_ADMIN_KEY: undefined, RELAY_ADMIN_KEY_FILE: empty }))?.stderr ?? "", /RELAY_ADMIN_KEY/);
  assert.match((await refusedAtStart({ RELAY_ADMIN_KEY_FILE: "" , RELAY_ADMIN_KEY: undefined }))?.stderr ?? "", /RELAY_ADMIN_KEY_FILE/);
  const e1 = await refusedAtStart({ RELAY_AUDITOR_KEY_FILE: empty });
  assert.ok(e1, "an empty auditor key file silently disabled export");
  assert.match(e1.stderr, /RELAY_AUDITOR_KEY_FILE/);
  const e2 = await refusedAtStart({ RELAY_AUDITOR_KEY_FILE: "" });
  assert.ok(e2, "a set-but-empty RELAY_AUDITOR_KEY_FILE was accepted");
  assert.match(e2.stderr, /RELAY_AUDITOR_KEY_FILE/);
});

console.log("\n=== R2-10: two sources for one key ===");

await test("R2-10 RELAY_ADMIN_KEY and RELAY_ADMIN_KEY_FILE both set: refuse to start (also the flag, also the auditor key)", async () => {
  const f = fresh("adminkey");
  writeFileSync(f, key() + "\n", { mode: 0o600 });
  const both = await refusedAtStart({ RELAY_ADMIN_KEY: key(), RELAY_ADMIN_KEY_FILE: f });
  assert.ok(both, "started with both an admin key variable and a key file");
  assert.match(both.stderr, /RELAY_ADMIN_KEY/);
  assert.match(both.stderr, /both/);
  const flag = await refusedAtStart({ RELAY_ADMIN_KEY: key() }, ["--admin-key-file", f]);
  assert.ok(flag, "the --admin-key-file flag silently outranked the environment key");
  const af = fresh("auditorkey");
  writeFileSync(af, key() + "\n", { mode: 0o600 });
  const aud = await refusedAtStart({ RELAY_AUDITOR_KEY: key(), RELAY_AUDITOR_KEY_FILE: af });
  assert.ok(aud, "started with both an auditor key variable and a key file");
  assert.match(aud.stderr, /RELAY_AUDITOR_KEY/);
  // each source alone is fine
  const ok1 = await startRelayProcess({ env: { RELAY_DB: fresh("db") + ".db", RELAY_ADMIN_KEY: undefined, RELAY_ADMIN_KEY_FILE: f, RELAY_AUDITOR_KEY_FILE: af } });
  const k = readFileSync(f, "utf8").trim();
  assert.equal((await rpc(ok1.url, "bridge_admin_purge", { p_older_than: "30 days" }, k)).status, 200);
  await ok1.stop();
});

// ------------------------------------------------------------------ R2-15

console.log("\n=== R2-15: slowloris ===");

// opens a socket; resolves { sock, closed: Promise<ms> }
const openSock = (port, firstWrite) =>
  new Promise((resolve, reject) => {
    const t0 = Date.now();
    const sock = net.connect(port, "127.0.0.1", () => {
      if (firstWrite) sock.write(firstWrite);
      resolve({ sock, closed: new Promise((r) => sock.once("close", () => r(Date.now() - t0))) });
    });
    sock.resume(); // a socket nobody reads from never notices that the server closed it
    sock.on("error", () => {});
    sock.once("error", reject);
  });
const health = async (url, ms = 2000) => {
  const res = await fetch(`${url}/healthz`, { signal: AbortSignal.timeout(ms) });
  return res.status;
};

await test("R2-15 half-open and idle sockets are closed within the timeout", async () => {
  const r = await relayWith({ RELAY_IDLE_TIMEOUT_MS: "1000", RELAY_HEADERS_TIMEOUT_MS: "1000", RELAY_MAX_CONNECTIONS: "200" });
  try {
    const socks = [];
    for (let i = 0; i < 5; i++) socks.push(await openSock(r.port, "POST /rest/v1/rpc/bridge_whoami HTTP/1.1\r\nHost: x\r\n")); // half a header block
    for (let i = 0; i < 5; i++) socks.push(await openSock(r.port)); // nothing at all
    socks.push(await openSock(r.port, "P")); // one byte
    const timedOut = Symbol("open");
    const results = await Promise.all(socks.map((s) => Promise.race([s.closed, sleep(6000).then(() => timedOut)])));
    const stillOpen = results.filter((x) => x === timedOut).length;
    assert.equal(stillOpen, 0, `${stillOpen} of ${socks.length} half-open sockets were still open after 6 s`);
    assert.ok(Math.max(...results) < 5000, `slowest close: ${Math.max(...results)} ms`);
    assert.equal(await health(r.url), 200);
  } finally {
    await r.stop();
  }
});

await test("R2-15 a request whose body stalls is cut by the socket idle timeout (long before the request timeout)", async () => {
  const r = await relayWith({ RELAY_IDLE_TIMEOUT_MS: "1000", RELAY_HEADERS_TIMEOUT_MS: "5000", RELAY_REQUEST_TIMEOUT_MS: "20000" });
  try {
    const s = await openSock(r.port, "POST /rest/v1/rpc/bridge_whoami HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 200\r\n\r\n{\"p_to");
    const ms = await Promise.race([s.closed, sleep(6000).then(() => Infinity)]);
    assert.ok(ms < 5000, `a stalled body was still open after ${ms} ms`);
  } finally {
    await r.stop();
  }
});

await test("R2-15 a dripping client (a header byte every 300 ms) is cut by the header timeout", async () => {
  const r = await relayWith({ RELAY_IDLE_TIMEOUT_MS: "5000", RELAY_HEADERS_TIMEOUT_MS: "1000" });
  try {
    const s = await openSock(r.port, "GET /healthz HTTP/1.1\r\nHost: x\r\n");
    const iv = setInterval(() => s.sock.writable && s.sock.write("X-A: 1\r\n"), 300);
    const ms = await Promise.race([s.closed, sleep(6000).then(() => Infinity)]);
    clearInterval(iv);
    assert.ok(ms < 5000, `still open after ${ms} ms`);
  } finally {
    await r.stop();
  }
});

await test("R2-15 /healthz stays up under a burst of idle connections, and the connection cap holds", async () => {
  const cap = 60;
  const r = await relayWith({ RELAY_IDLE_TIMEOUT_MS: "1500", RELAY_HEADERS_TIMEOUT_MS: "1500", RELAY_MAX_CONNECTIONS: String(cap), RELAY_MAX_CONNECTIONS_PER_IP: "1000" }); // this test is about the global cap (the per-address share is R3-09)
  try {
    const held = [];
    for (let i = 0; i < 40; i++) held.push(await openSock(r.port));
    const t0 = Date.now();
    assert.equal(await health(r.url), 200, "healthz failed with 40 idle connections");
    assert.ok(Date.now() - t0 < 1500);
    // a burst far above the cap: the relay must not keep them all
    const burst = [];
    for (let i = 0; i < 300; i++) burst.push(openSock(r.port).catch(() => null));
    const opened = (await Promise.all(burst)).filter(Boolean);
    // the over-cap connections are dropped by the relay at once (a loaded machine may be slow to show the close,
    // so look for up to 1 s, still inside the 1.5 s idle timeout)
    const aliveNow = () => [...held, ...opened].filter((s) => !s.sock.destroyed && s.sock.readyState === "open").length;
    const t0b = Date.now();
    let alive = aliveNow();
    while (alive > cap + 5 && Date.now() - t0b < 1000) {
      await sleep(25);
      alive = aliveNow();
    }
    assert.ok(alive <= cap + 5, `${alive} connections were held open at once (cap ${cap})`);
    // after the idle timeout everything is reaped and the relay answers again
    const openCount = () => [...held, ...opened].filter((s) => s.sock.readyState === "open").length;
    const t1 = Date.now();
    while (openCount() > 0 && Date.now() - t1 < 6000) await sleep(100);
    assert.equal(openCount(), 0, `${openCount()} idle connections survived 6 s (timeout 1.5 s)`);
    assert.equal(await health(r.url), 200, "healthz did not recover after the idle timeout");
  } finally {
    await r.stop();
  }
});

await test("R2-15 the defaults are sane for an internal service", async () => {
  const relay = await inProcess();
  try {
    const s = relay.server;
    assert.ok(s.headersTimeout > 0 && s.headersTimeout <= 20_000, `headersTimeout ${s.headersTimeout}`);
    assert.ok(s.requestTimeout > 0 && s.requestTimeout <= 60_000, `requestTimeout ${s.requestTimeout}`);
    assert.ok(s.timeout > 0 && s.timeout <= 120_000, `socket idle timeout ${s.timeout}`);
    assert.ok(s.keepAliveTimeout > 0 && s.keepAliveTimeout <= 10_000, `keepAliveTimeout ${s.keepAliveTimeout}`);
    assert.ok(Number.isFinite(s.maxConnections) && s.maxConnections > 0 && s.maxConnections <= 10_000, `maxConnections ${s.maxConnections}`);
    assert.ok(s.connectionsCheckingInterval <= 5000, `connectionsCheckingInterval ${s.connectionsCheckingInterval}`);
  } finally {
    await relay.close();
  }
  // nonsense values refuse to start rather than disabling the protection
  for (const [k, v] of [["RELAY_IDLE_TIMEOUT_MS", "0"], ["RELAY_HEADERS_TIMEOUT_MS", "-5"], ["RELAY_MAX_CONNECTIONS", "abc"]]) {
    const e = await refusedAtStart({ [k]: v });
    assert.ok(e, `${k}=${v} was accepted`);
    assert.match(e.stderr, new RegExp(k));
  }
});

// ------------------------------------------------------------------ R2-13 / R2-02

console.log("\n=== R2-13 and R2-02: malformed input is a 400 ===");

await test("R2-13 deeply nested argument values get a 400 PostgREST-style error, not a 500", async () => {
  const r = await relayWith();
  try {
    const depth = 100_000;
    const arr = "[".repeat(depth) + "]".repeat(depth);
    const obj = '{"a":'.repeat(40_000) + "1" + "}".repeat(40_000);
    for (const [fn, field, nested, apikey] of [
      ["bridge_whoami", "p_token", arr, "relay"],
      ["bridge_whoami", "p_token", obj, "relay"],
      ["bridge_send", "p_body", arr, "relay"],
      ["bridge_admin_create_agent", "p_name", arr, r.adminKey],
      ["bridge_admin_purge", "p_older_than", arr, r.adminKey],
    ]) {
      const extra = fn === "bridge_send" ? '"p_token":"abt_x","p_to":"b",' : fn === "bridge_whoami" ? "" : "";
      const res = await r.call(fn, null, apikey, { raw: `{${extra}"${field}":${nested}}` });
      assert.equal(res.status, 400, `${fn}.${field}: ${res.status} ${res.text.slice(0, 120)}`);
      assert.ok(res.json && typeof res.json.code === "string" && typeof res.json.message === "string", res.text.slice(0, 120));
      assert.match(res.json.code, /^2/);
      assert.ok(res.text.length < 2000);
    }
    assert.ok(!/internal error/.test(r.stderr()), r.stderr());
    assert.equal(await health(r.url), 200);
  } finally {
    await r.stop();
  }
});

await test("R2-02 an absurd purge interval is a 400 (not a 500) and the failed attempt is audited", async () => {
  const audit = fresh("purge") + ".jsonl";
  const r = await relayWith({ RELAY_AUDIT_LOG: audit });
  try {
    await r.addAgents("alice", "bob");
    await r.send("alice", "bob", "keep me");
    for (const v of ["99999999999999999999 days", "1e30 days", "400000 weeks"]) {
      const res = await r.call("bridge_admin_purge", { p_older_than: v }, r.adminKey);
      assert.equal(res.status, 400, `${v}: ${res.status} ${res.text}`);
      assert.match(res.json.code, /^22/);
    }
    assert.equal(messageCount(r.dbPath), 1);
    assert.ok(!/internal error/.test(r.stderr()), r.stderr());
    // ordinary values still work, including a long retention
    assert.equal((await r.call("bridge_admin_purge", { p_older_than: "36000 days" }, r.adminKey)).status, 200);
    await r.stop();
    const failed = readAudit(audit).filter((l) => l.action === "admin.purge" && l.outcome === "failed");
    assert.equal(failed.length, 3, JSON.stringify(failed));
  } finally {
    if (r.child.exitCode === null) await r.stop();
  }
});

await test("R2-02 an unexpected error inside an admin function is audited too, and stays a generic 500", async () => {
  const audit = fresh("unexpected") + ".jsonl";
  const relay = await inProcess({ RELAY_AUDIT_LOG: audit });
  const errs = [];
  const orig = console.error;
  console.error = (...a) => errs.push(a.join(" "));
  try {
    relay.core.db.close(); // makes every database call throw a plain Error, not an RpcError
    const res = await relay.call("bridge_admin_create_agent", { p_name: "zed" }, relay.config.adminKey);
    assert.equal(res.status, 500);
    assert.equal(res.json.message, "internal error");
  } finally {
    console.error = orig;
    await new Promise((r) => relay.server.close(r));
    relay.server.closeAllConnections?.();
    relay.audit.close();
  }
  const entry = readAudit(audit).find((l) => l.action === "admin.create_agent");
  assert.ok(entry, "the failed admin call left no audit line");
  assert.equal(entry.outcome, "failed");
  assert.equal(entry.agent, "zed");
});

// ------------------------------------------------------------------ R2-04

console.log("\n=== R2-04: failed-auth floods ===");

await test("R2-04 failed authentications are rate-limited in the audit log, with a summary of what was suppressed", async () => {
  const audit = fresh("flood") + ".jsonl";
  const r = await relayWith({ RELAY_AUDIT_LOG: audit, RELAY_AUTH_FAIL_AUDIT_MAX: "5", RELAY_AUTH_FAIL_AUDIT_WINDOW_MS: "1000" });
  let lines;
  try {
    for (let i = 0; i < 120; i++) {
      const a = await r.call("bridge_whoami", { p_token: "abt_" + "0".repeat(60) + String(i).padStart(4, "0") });
      assert.equal(a.status, 403);
      const b = await r.call("bridge_admin_purge", { p_older_than: "1 day" }, "wrong-key-" + i);
      assert.equal(b.status, 401);
    }
    await sleep(2600); // the window ends and the summary is written (by the timer, while the relay keeps running)
    lines = readAudit(audit);
  } finally {
    await r.stop();
  }
  for (const scope of ["agent", "admin"]) {
    const kept = lines.filter((l) => l.action === "auth_failed" && l.scope === scope);
    assert.ok(kept.length >= 1 && kept.length <= 10, `${kept.length} auth_failed lines for scope ${scope}`);
    const sum = lines.filter((l) => l.action === "auth_failed.summary" && l.scope === scope);
    assert.ok(sum.length >= 1, `no summary line for scope ${scope}`);
    const suppressed = sum.reduce((a, l) => a + l.suppressed, 0);
    const keptN = kept.length;
    assert.equal(keptN + suppressed, 120, `scope ${scope}: ${keptN} kept + ${suppressed} suppressed`);
    assert.ok(sum[0].ip, "summary names the source");
  }
  assert.ok(lines.length < 40, `${lines.length} audit lines for 240 failed requests`);
  assert.equal(verifyAuditLog(audit).ok, true);
});

// ------------------------------------------------------------------ R2-05

console.log("\n=== R2-05: the audit chain survives a torn or failed write ===");

await test("R2-05 a torn last line is sealed with a recorded repair entry at startup; verification passes", async () => {
  const f = fresh("torn") + ".jsonl";
  let a = new AuditLog(f);
  a.write({ action: "one" });
  a.write({ action: "two" });
  a.close();
  const last = readFileSync(f, "utf8").trim().split("\n").pop();
  appendFileSync(f, last.slice(0, 60)); // half a line, no newline
  a = new AuditLog(f);
  a.write({ action: "three" });
  a.write({ action: "four" });
  a.close();
  const v = verifyAuditLog(f);
  assert.equal(v.ok, true, JSON.stringify(v));
  const lines = readAuditLoose(f);
  assert.ok(lines.some((l) => l.action === "chain.repair"), "no repair entry");
  assert.deepEqual(lines.filter((l) => !l.action.startsWith("chain.")).map((l) => l.action), ["one", "two", "three", "four"]);
});

await test("R2-05 a short write at run time is repaired before the next entry", async () => {
  const f = fresh("short") + ".jsonl";
  const a = new AuditLog(f);
  a.write({ action: "one" });
  const real = a.writer;
  a.writer = (fd, text) => {
    writeSync(fd, text.slice(0, 40)); // ENOSPC after 40 bytes
    throw Object.assign(new Error("no space"), { code: "ENOSPC" });
  };
  const origErr = console.error;
  console.error = () => {};
  try {
    a.write({ action: "lost" });
  } finally {
    console.error = origErr;
  }
  a.writer = real;
  a.write({ action: "two" });
  a.write({ action: "three" });
  a.close();
  const v = verifyAuditLog(f);
  assert.equal(v.ok, true, JSON.stringify(v));
  assert.ok(readAuditLoose(f).some((l) => l?.action === "chain.repair"));
});

await test("R2-05 verify-audit still rejects junk that is not followed by a matching repair entry", async () => {
  const f = fresh("junk") + ".jsonl";
  const a = new AuditLog(f);
  for (const x of ["one", "two", "three", "four"]) a.write({ action: x });
  a.close();
  const lines = readFileSync(f, "utf8").split("\n").filter(Boolean);
  // a middle line replaced by junk
  writeFileSync(f, [lines[0], "garbage", ...lines.slice(2)].join("\n") + "\n");
  assert.equal(verifyAuditLog(f).ok, false);
  assert.equal(verifyAuditLog(f).line, 2);
  // junk followed by a repair entry that does not cover it
  const b = fresh("junk2") + ".jsonl";
  const x = new AuditLog(b);
  x.write({ action: "one" });
  x.close();
  appendFileSync(b, "half a li");
  const y = new AuditLog(b);
  y.close();
  const t = readFileSync(b, "utf8").split("\n").filter(Boolean);
  assert.equal(verifyAuditLog(b).ok, true);
  t[1] = "different junk";
  writeFileSync(b, t.join("\n") + "\n");
  assert.equal(verifyAuditLog(b).ok, false, "a changed junk line was accepted");
  // a repair entry may not hide a deleted line
  // a repair entry must continue from the last good line: it can't be used to hide a deleted entry before the junk
  const d = fresh("junk4") + ".jsonl";
  const w1 = new AuditLog(d);
  w1.write({ action: "one" });
  w1.write({ action: "two" });
  w1.close();
  appendFileSync(d, "half a li");
  new AuditLog(d).close(); // seals the junk with a repair entry
  assert.equal(verifyAuditLog(d).ok, true);
  const dl = readFileSync(d, "utf8").split("\n").filter(Boolean);
  writeFileSync(d, [dl[0], ...dl.slice(2)].join("\n") + "\n"); // entry "two" removed
  assert.equal(verifyAuditLog(d).ok, false, "a repair entry hid a deleted audit line");
  const c = fresh("junk3") + ".jsonl";
  const z = new AuditLog(c);
  for (const w of ["one", "two", "three"]) z.write({ action: w });
  z.close();
  const cl = readFileSync(c, "utf8").split("\n").filter(Boolean);
  writeFileSync(c, [cl[0], cl[2]].join("\n") + "\n");
  assert.equal(verifyAuditLog(c).ok, false);
});

await test("R2-05 RELAY_AUDIT_REQUIRED=1: a request fails when its audit line can't be written, and nothing leaks or changes", async () => {
  const audit = fresh("required") + ".jsonl";
  const relay = await inProcess({ RELAY_AUDIT_LOG: audit, RELAY_AUDIT_REQUIRED: "1" });
  const tokens = {};
  const call = relay.call;
  const origErr = console.error;
  try {
    for (const nm of ["alice", "bob"]) tokens[nm] = await relay.admin.createAgent(nm, nm);
    // a message that is already waiting
    const sent = await call("bridge_send", { p_token: tokens.alice, p_to: "bob", p_body: "first" });
    assert.equal(sent.status, 200);
    const real = relay.audit.writer;
    relay.audit.writer = () => {
      throw Object.assign(new Error("no space"), { code: "ENOSPC" });
    };
    console.error = () => {};
    // send: refused, and the message is not left behind
    const s2 = await call("bridge_send", { p_token: tokens.alice, p_to: "bob", p_body: "second" });
    assert.equal(s2.status, 503, s2.text);
    assert.equal(relay.core.db.prepare(`SELECT COUNT(*) AS n FROM messages`).get().n, 1, "a message was stored without its audit line");
    // reads: nothing is disclosed, and nothing is marked read
    for (const [fn, body] of [
      ["bridge_inbox", { p_token: tokens.bob }],
      ["bridge_inbox", { p_token: tokens.bob, p_mark_read: false }],
      ["bridge_recent", { p_token: tokens.bob }],
      ["bridge_thread", { p_token: tokens.bob, p_thread_id: sent.json.thread_id }],
    ]) {
      const res = await call(fn, body);
      assert.equal(res.status, 503, `${fn}: ${res.status} ${res.text.slice(0, 100)}`);
      assert.ok(!res.text.includes("first"), `${fn} leaked the body`);
    }
    assert.equal(relay.core.db.prepare(`SELECT COUNT(*) AS n FROM messages WHERE read_at IS NULL`).get().n, 1, "a message was claimed without its audit line");
    // admin actions are refused before they happen
    const del = await call("bridge_admin_delete_agent", { p_name: "alice" }, relay.config.adminKey);
    assert.equal(del.status, 503, del.text);
    assert.equal(relay.core.db.prepare(`SELECT COUNT(*) AS n FROM relay_agents`).get().n, 2);
    // health says so
    const h = await fetch(`${relay.url}/healthz`);
    assert.equal(h.status, 503);
    // the disk comes back: service resumes and the chain verifies
    relay.audit.writer = real;
    console.error = origErr;
    const ok = await call("bridge_inbox", { p_token: tokens.bob });
    assert.equal(ok.status, 200, ok.text);
    assert.equal(ok.json.length, 1);
    assert.equal((await fetch(`${relay.url}/healthz`)).status, 200);
  } finally {
    console.error = origErr;
    await relay.close();
  }
  assert.equal(verifyAuditLog(audit).ok, true, JSON.stringify(verifyAuditLog(audit)));
});

await test("R2-05 without RELAY_AUDIT_REQUIRED a failed audit write is logged and the request goes on (documented best effort)", async () => {
  const audit = fresh("besteffort") + ".jsonl";
  const relay = await inProcess({ RELAY_AUDIT_LOG: audit });
  const origErr = console.error;
  try {
    const t = await relay.admin.createAgent("alice", "a");
    await relay.admin.createAgent("bob", "b");
    relay.audit.writer = () => {
      throw Object.assign(new Error("no space"), { code: "ENOSPC" });
    };
    console.error = () => {};
    assert.equal((await relay.call("bridge_send", { p_token: t, p_to: "bob", p_body: "x" })).status, 200);
  } finally {
    console.error = origErr;
    await relay.close();
  }
});

await test("R2-05 RELAY_AUDIT_REQUIRED needs an audit log, and is parsed strictly", async () => {
  const e = await refusedAtStart({ RELAY_AUDIT_REQUIRED: "1" });
  assert.ok(e, "RELAY_AUDIT_REQUIRED=1 without RELAY_AUDIT_LOG was accepted");
  assert.match(e.stderr, /RELAY_AUDIT_REQUIRED/);
  const e2 = await refusedAtStart({ RELAY_AUDIT_REQUIRED: "maybe", RELAY_AUDIT_LOG: fresh("a") });
  assert.match(e2?.stderr ?? "", /RELAY_AUDIT_REQUIRED/);
  const ok = await relayWith({ RELAY_AUDIT_REQUIRED: "true", RELAY_AUDIT_LOG: fresh("a") });
  assert.match(ok.stdout(), /audit: on \(no bodies, required\)/);
  await ok.stop();
});

// ------------------------------------------------------------------ R2-09

console.log("\n=== R2-09: export timestamps ===");

await test("R2-09 a zone-less export timestamp is refused (400), whatever the relay host's TZ; explicit zones work", async () => {
  const auditor = key();
  for (const tz of ["UTC", "America/Los_Angeles"]) {
    const audit = fresh("export") + ".jsonl";
    const r = await relayWith({ TZ: tz, RELAY_AUDITOR_KEY: auditor, RELAY_AUDIT_LOG: audit });
    try {
      await r.addAgents("alice", "bob");
      const s = await r.send("alice", "bob", "exported");
      const sentAt = Date.parse(s.json.created_at);
      const iso = (ms) => new Date(ms).toISOString();
      const exp = (extra) => r.call("bridge_admin_export", extra, auditor);
      // 1 hour before the message, written as a UTC wall clock with no zone
      const wall = iso(sentAt - 3600e3).slice(0, 19);
      for (const bad of [wall, wall + ".500", wall.replace("T", " "), wall.slice(0, 16)]) {
        const res = await exp({ p_to: bad });
        assert.equal(res.status, 400, `TZ=${tz} p_to=${JSON.stringify(bad)} -> ${res.status} ${res.text.slice(0, 100)}`);
        assert.equal(res.json.code, "22007");
        assert.equal((await exp({ p_from: bad })).status, 400);
      }
      // with an explicit zone the range means what it says
      assert.equal((await exp({ p_to: wall + "Z" })).json.length, 0);
      assert.equal((await exp({ p_to: wall + "+00:00" })).json.length, 0);
      assert.equal((await exp({ p_to: iso(sentAt + 3600e3) })).json.length, 1);
      assert.equal((await exp({ p_from: iso(sentAt - 1000), p_to: iso(sentAt + 1000) })).json.length, 1);
      // the same instant written with an offset
      const plus2 = new Date(sentAt - 3600e3 + 2 * 3600e3).toISOString().slice(0, 19) + "+02:00";
      assert.equal((await exp({ p_to: plus2 })).json.length, 0);
      const minus8 = new Date(sentAt + 1000 - 8 * 3600e3).toISOString().slice(0, 19) + "-08:00";
      assert.equal((await exp({ p_to: minus8 })).json.length, 1);
      // a date alone is a UTC date
      assert.equal((await exp({ p_from: "2000-01-01", p_to: "2999-01-01" })).json.length, 1);
      assert.equal((await exp({ p_from: iso(sentAt).slice(0, 10) })).status, 200);
      // the audit line keeps the string the auditor typed
      await r.stop();
      const line = readAudit(audit).filter((l) => l.action === "auditor.export" && l.outcome === "ok").find((l) => l.to_raw === plus2);
      assert.ok(line, "the export audit line does not carry the original timestamp text");
      assert.equal(line.to, new Date(Date.parse(plus2)).toISOString());
    } finally {
      if (r.child.exitCode === null) await r.stop();
    }
  }
});

// ------------------------------------------------------------------ R2-14

console.log("\n=== R2-14: reads leave a usable audit record ===");

await test("R2-14 bridge_recent, bridge_thread and peeks record the ids of the messages they disclosed", async () => {
  const audit = fresh("reads") + ".jsonl";
  const r = await relayWith({ RELAY_AUDIT_LOG: audit });
  let ids;
  let threadId;
  try {
    await r.addAgents("alice", "bob");
    const m1 = (await r.send("alice", "bob", "secret-1")).json;
    const m2 = (await r.send("alice", "bob", "secret-2")).json;
    ids = [m1.id, m2.id];
    threadId = m1.thread_id;
    const recent = await r.call("bridge_recent", { p_token: r.tokens.bob });
    assert.equal(recent.json.length, 2);
    const peek = await r.call("bridge_inbox", { p_token: r.tokens.bob, p_mark_read: false });
    assert.equal(peek.json.length, 2);
    assert.equal((await r.call("bridge_thread", { p_token: r.tokens.bob, p_thread_id: threadId })).status, 200);
  } finally {
    await r.stop();
  }
  const lines = readAudit(audit);
  const rec = lines.find((l) => l.action === "recent");
  assert.ok(rec, "bridge_recent left no audit line");
  assert.equal(rec.agent, "bob");
  assert.equal(rec.count, 2);
  assert.deepEqual([...rec.ids].sort((a, b) => a - b), [...ids].sort((a, b) => a - b));
  const peek = lines.find((l) => l.action === "peek");
  assert.deepEqual([...peek.ids].sort((a, b) => a - b), [...ids].sort((a, b) => a - b));
  const th = lines.find((l) => l.action === "thread");
  assert.deepEqual(th.ids, [ids[0]]); // the thread of the first message
  assert.ok(!readFileSync(audit, "utf8").includes("secret-1"));
});

rmrf(tmp);
process.exit(summary() ? 1 : 0);
