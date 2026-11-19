// A real forward proxy for tests: it speaks absolute-URI HTTP and CONNECT, resolves ".test" names itself
// (so success proves the traffic went through it) and can terminate TLS like a TLS-inspecting corporate
// proxy. Shared by test/proxy.js and test/regressions-r2-client.js.
import http from "node:http";
import net from "node:net";
import tls from "node:tls";

// `inspect` maps a host name to the local port of the plain-HTTP stand-in behind it: for those hosts
// the proxy terminates TLS itself with its own certificate, like a TLS-inspecting corporate proxy.
export function startForwardProxy({ inspect = new Map(), key, cert } = {}) {
  const hits = []; // { kind: "http" | "connect" | "request", host, port }
  const target = (host) => (host.endsWith(".test") || host === "127.0.0.1" || host === "localhost" ? "127.0.0.1" : null);
  const server = http.createServer((req, res) => {
    // absolute-URI request: http://host:port/path
    let u;
    try {
      u = new URL(req.url);
    } catch {
      return res.writeHead(400).end();
    }
    hits.push({ kind: "http", host: u.hostname, port: Number(u.port) || 80 });
    const to = target(u.hostname);
    if (!to) return res.writeHead(502).end("proxy: unknown host");
    const out = http.request({ host: to, port: u.port || 80, path: u.pathname + u.search, method: req.method, headers: { ...req.headers, host: u.host } }, (r) => {
      res.writeHead(r.statusCode, r.headers);
      r.pipe(res);
    });
    out.on("error", () => res.writeHead(502).end());
    req.pipe(out);
  });
  server.on("connect", (req, socket, head) => {
    const [host, port] = req.url.split(":");
    hits.push({ kind: "connect", host, port: Number(port) });
    const to = target(host);
    if (!to) return socket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
    if (inspect.has(host)) {
      const inner = net.connect(inspect.get(host), "127.0.0.1", () => {
        socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        const clear = new tls.TLSSocket(socket, { isServer: true, key, cert });
        // keep-alive reuses one tunnel for many requests: count the requests inside it
        clear.on("data", (d) => {
          for (const _ of String(d).matchAll(/^(?:GET|POST|PUT|DELETE|PATCH) \S+ HTTP\/1\.1/gm)) hits.push({ kind: "request", host, port: Number(port) });
        });
        clear.pipe(inner);
        inner.pipe(clear);
        clear.on("error", () => inner.destroy());
      });
      inner.on("error", () => socket.destroy());
      socket.on("error", () => inner.destroy());
      return;
    }
    const up = net.connect(Number(port), to, () => {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head?.length) up.write(head);
      up.pipe(socket);
      socket.pipe(up);
    });
    up.on("error", () => socket.destroy());
    socket.on("error", () => up.destroy());
  });
  return new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () =>
      resolve({
        url: `http://127.0.0.1:${server.address().port}`,
        hits,
        count: (host) => hits.filter((h) => !host || h.host === host).length,
        requests: (host) => hits.filter((h) => h.kind === "request" && h.host === host).length,
        reset: () => (hits.length = 0),
        close: () => new Promise((r) => (server.closeAllConnections?.(), server.close(r))),
      })
    )
  );
}
