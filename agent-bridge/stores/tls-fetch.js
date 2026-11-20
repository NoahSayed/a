// A minimal fetch() for the relay backend over (mutual) TLS. Node's built-in fetch can't be given a
// client certificate without an extra dependency, so this speaks https directly. It implements only
// what stores/supabase.js uses: status, ok, text(), the abort signal, and no redirect following.
//
// Proxy (R3-11): a Node https.Agent built with its own TLS options connects directly and ignores
// HTTPS_PROXY / NODE_USE_ENV_PROXY, which would send the relay's traffic around the company proxy while
// `init` and `doctor` say the proxy is active. So when a proxy is in effect (an HTTPS_PROXY / https_proxy is
// set, the process asked for env proxying the same way fetch() needs it: NODE_USE_ENV_PROXY=1 or
// --use-env-proxy, and NO_PROXY doesn't exempt the host) the request is made through an HTTP CONNECT
// tunnel to the proxy, and TLS to the relay runs inside it, with the same CA and client certificate.
// This does not depend on the Node version (the node:https agents only learned proxies in Node 24.5).

import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { readFileSync } from "node:fs";
import { BridgeError } from "./common.js";
import { expandHome } from "../store.js";

// The proxy URL to use for `url`, or null: no proxy configured, env proxying not requested, or NO_PROXY says no.
export function proxyFor(url, env = process.env, execArgv = process.execArgv) {
  const raw = (env.HTTPS_PROXY || env.https_proxy || "").trim();
  if (!raw) return null;
  const requested = env.NODE_USE_ENV_PROXY === "1" || execArgv.includes("--use-env-proxy") || /(^|\s)--use-env-proxy(\s|$)/.test(env.NODE_OPTIONS || "");
  if (!requested) return null;
  const target = new URL(url);
  if (noProxy(target, (env.NO_PROXY ?? env.no_proxy ?? "").trim())) return null;
  try {
    const p = new URL(raw.includes("://") ? raw : `http://${raw}`);
    return p.protocol === "http:" || p.protocol === "https:" ? p : null;
  } catch {
    return null;
  }
}

// NO_PROXY: comma or space separated host names (a leading "." or "*." matches subdomains), "*" for everything,
// each optionally with a :port.
function noProxy(target, list) {
  if (!list) return false;
  const host = target.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const port = target.port || "443";
  for (let entry of list.split(/[,\s]+/).filter(Boolean)) {
    if (entry === "*") return true;
    entry = entry.toLowerCase();
    let ePort = null;
    const m = /^(.*):(\d+)$/.exec(entry);
    if (m && !entry.includes("]")) [, entry, ePort] = m;
    if (ePort && ePort !== port) continue;
    entry = entry.replace(/^\*?\./, "");
    if (host === entry || host.endsWith(`.${entry}`)) return true;
  }
  return false;
}

// Opens a tunnel to host:port through the proxy and resolves the connected raw socket.
function connectThroughProxy(proxy, host, port, { signal } = {}) {
  return new Promise((resolve, reject) => {
    const pPort = Number(proxy.port) || (proxy.protocol === "https:" ? 443 : 80);
    const pHost = proxy.hostname.replace(/^\[|\]$/g, "");
    const sock = proxy.protocol === "https:" ? tls.connect({ host: pHost, port: pPort, servername: net.isIP(pHost) ? undefined : pHost }) : net.connect({ host: pHost, port: pPort });
    const fail = (e) => {
      sock.destroy();
      reject(Object.assign(new Error(e.message), { cause: e.cause ?? e, code: e.code }));
    };
    sock.once("error", fail);
    sock.setTimeout(30000, () => fail(Object.assign(new Error("the proxy did not answer the CONNECT request"), { code: "ETIMEDOUT" })));
    const onConnect = () => {
      const auth = proxy.username || proxy.password ? `Proxy-Authorization: Basic ${Buffer.from(`${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`).toString("base64")}\r\n` : "";
      const target = host.includes(":") ? `[${host}]:${port}` : `${host}:${port}`;
      sock.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n${auth}\r\n`);
      let head = Buffer.alloc(0);
      const onData = (chunk) => {
        head = Buffer.concat([head, chunk]);
        const end = head.indexOf("\r\n\r\n");
        if (end < 0) {
          if (head.length > 16384) fail(new Error("the proxy's answer to CONNECT is too long"));
          return;
        }
        sock.off("data", onData);
        const status = Number(/^HTTP\/1\.[01] (\d{3})/.exec(head.subarray(0, end).toString("latin1"))?.[1]);
        if (status !== 200) return fail(Object.assign(new Error(`the proxy refused the CONNECT request (HTTP ${status || "?"})`), { code: `EPROXY${status || ""}` }));
        sock.setTimeout(0);
        sock.off("error", fail);
        if (head.length > end + 4) sock.unshift(head.subarray(end + 4));
        resolve(sock);
      };
      sock.on("data", onData);
    };
    sock.once(proxy.protocol === "https:" ? "secureConnect" : "connect", onConnect);
    signal?.addEventListener("abort", () => fail(signal.reason instanceof Error ? signal.reason : new Error("aborted")), { once: true });
  });
}

// An https.Agent whose connections are tunnelled through `proxy`.
class TunnelAgent extends https.Agent {
  constructor(options, proxy) {
    super(options);
    this.tunnel = proxy;
    this.tlsOptions = options;
  }
  createConnection(options, cb) {
    const host = options.host || options.hostname;
    connectThroughProxy(this.tunnel, host, options.port || 443).then(
      (socket) => {
        const secure = tls.connect({ ...this.tlsOptions, socket, servername: options.servername || (net.isIP(host) ? undefined : host) });
        cb(null, secure);
      },
      (e) => cb(e)
    );
  }
}

export function tlsFetch({ ca, cert, key }, { env = process.env, execArgv = process.execArgv } = {}) {
  const options = { ca, cert, key, keepAlive: true, minVersion: "TLSv1.2" };
  const direct = new https.Agent(options);
  const tunnels = new Map(); // proxy URL -> agent
  const agentFor = (url) => {
    const proxy = proxyFor(url, env, execArgv);
    if (!proxy) return direct;
    if (!tunnels.has(proxy.href)) tunnels.set(proxy.href, new TunnelAgent(options, proxy));
    return tunnels.get(proxy.href);
  };
  return (url, { method = "GET", headers = {}, body, signal } = {}) =>
    new Promise((resolve, reject) => {
      const req = https.request(url, { method, headers, agent: agentFor(url), signal }, (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("error", (e) => reject(Object.assign(new Error(e.message), { cause: e })));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          resolve({ status: res.statusCode, ok: res.statusCode >= 200 && res.statusCode < 300, text: async () => text });
        });
      });
      req.on("error", (e) => reject(Object.assign(new Error(e.message), { cause: e })));
      req.end(body);
    });
}

const TLS_VARS = ["RELAY_TLS_CA", "RELAY_TLS_CLIENT_CERT", "RELAY_TLS_CLIENT_KEY"];

// The contents of the file named by one of the RELAY_TLS_* variables: "~" is the home directory (managed-config
// writes ~/... for per-user files, R3-17), and a failure names the variable and the file (never its contents).
export function readTlsFile(name, value, readFile = readFileSync) {
  const path = expandHome(String(value).trim());
  try {
    return readFile(path);
  } catch (e) {
    throw new BridgeError(`Can't read ${name} ${path}: ${e.code || e.message}`);
  }
}

// Reads RELAY_TLS_CA (extra CA to trust), RELAY_TLS_CLIENT_CERT and RELAY_TLS_CLIENT_KEY (this agent's
// certificate, for relays started with RELAY_TLS_CA). Returns undefined when none is set.
export function tlsFetchFromEnv(env, readFile = readFileSync, { execArgv } = {}) {
  const [ca, cert, key] = TLS_VARS.map((k) => (env[k] && env[k].trim() ? readTlsFile(k, env[k], readFile) : undefined));
  if (!ca && !cert && !key) return undefined;
  return tlsFetch({ ca, cert, key }, { env, ...(execArgv ? { execArgv } : {}) });
}
