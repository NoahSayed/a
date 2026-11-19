// A minimal fetch() for the relay backend over (mutual) TLS. Node's built-in fetch can't be given a
// client certificate without an extra dependency, so this speaks https directly. It implements only
// what stores/supabase.js uses: status, ok, text(), the abort signal, and no redirect following.

import https from "node:https";
import { readFileSync } from "node:fs";

export function tlsFetch({ ca, cert, key }) {
  const agent = new https.Agent({ ca, cert, key, keepAlive: true, minVersion: "TLSv1.2" });
  return (url, { method = "GET", headers = {}, body, signal } = {}) =>
    new Promise((resolve, reject) => {
      const req = https.request(url, { method, headers, agent, signal }, (res) => {
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

// Reads RELAY_TLS_CA (extra CA to trust), RELAY_TLS_CLIENT_CERT and RELAY_TLS_CLIENT_KEY (this agent's
// certificate, for relays started with RELAY_TLS_CA). Returns undefined when none is set.
export function tlsFetchFromEnv(env, readFile = readFileSync) {
  const { RELAY_TLS_CA: ca, RELAY_TLS_CLIENT_CERT: cert, RELAY_TLS_CLIENT_KEY: key } = env;
  if (!ca && !cert && !key) return undefined;
  return tlsFetch({
    ca: ca ? readFile(ca) : undefined,
    cert: cert ? readFile(cert) : undefined,
    key: key ? readFile(key) : undefined,
  });
}
