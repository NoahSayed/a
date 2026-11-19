// Test-only stand-in for Supabase's REST layer (PostgREST), backed by a real Postgres.
// It reproduces the PostgREST behaviour agent-bridge relies on:
//   * apikey header -> database role (publishable -> anon, secret -> service_role), 401 otherwise
//   * a new-style key in "Authorization: Bearer" is rejected ("Invalid JWT"), like Supabase
//   * POST /rest/v1/rpc/<fn> with named JSON args, run as that role in a transaction
//   * void functions -> 204, others -> the JSON-encoded return value
//   * SQLSTATE -> HTTP status mapping and {code,message,details,hint} error bodies
//   * PGRST202 (404) when no function matches the name + argument names
//   * GET/POST/PATCH/DELETE /rest/v1/<table> so tests can attempt direct table access
import http from "node:http";
import pg from "pg";

export const KEYS = { publishable: "sb_publishable_test", secret: "sb_secret_test" };
const ROLE_FOR_KEY = { [KEYS.publishable]: "anon", [KEYS.secret]: "service_role" };
const IDENT = /^[a-z_][a-z0-9_]*$/;

function statusFor(code, role) {
  if (!code) return 500;
  if (code === "42501") return role === "anon" ? 401 : 403;
  if (code.startsWith("28")) return 403;
  if (code === "P0001") return 400;
  if (code === "42883") return 404;
  if (code === "42P01") return 404;
  if (code === "23503" || code === "23505") return 409;
  if (code.startsWith("22") || code.startsWith("23")) return 400;
  return 500;
}

export async function startFakePostgrest({ connectionString }) {
  const pool = new pg.Pool({ connectionString, max: 20 });
  // Teardown drops the database WITH (FORCE), which terminates idle pooled connections (57P01).
  // pg emits that on the pool; unhandled, it crashed the test process after all tests had passed.
  pool.on("error", () => {});
  const stats = { requests: 0 };

  const send = (res, status, body) => {
    if (status === 204) {
      res.writeHead(204).end();
      return;
    }
    res.writeHead(status, { "Content-Type": "application/json" }).end(JSON.stringify(body));
  };

  async function asRole(role, fn) {
    const c = await pool.connect();
    try {
      await c.query("begin");
      await c.query(`set local role ${role}`);
      await c.query("set local statement_timeout = '15s'");
      const out = await fn(c);
      await c.query("commit");
      return out;
    } catch (e) {
      await c.query("rollback").catch(() => {});
      throw e;
    } finally {
      c.release();
    }
  }

  const server = http.createServer(async (req, res) => {
    stats.requests++;
    // Decode once: concatenating chunks as strings splits multi-byte characters at chunk edges.
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString("utf8");
    const role = ROLE_FOR_KEY[req.headers.apikey];
    if (!role) return send(res, 401, { message: "Invalid API key", hint: "Double check your Supabase `anon` or `service_role` API key." });
    const auth = req.headers.authorization;
    if (auth && !/^Bearer eyJ/.test(auth)) return send(res, 401, { code: "PGRST301", message: "Invalid JWT" });

    const url = new URL(req.url, "http://x");
    let body = {};
    try {
      body = raw ? JSON.parse(raw) : {};
    } catch {
      return send(res, 400, { code: "PGRST102", message: "Empty or invalid json" });
    }

    try {
      const rpc = url.pathname.match(/^\/rest\/v1\/rpc\/([^/]+)$/);
      if (rpc && req.method === "POST") {
        const fn = rpc[1];
        const keys = Object.keys(body);
        if (!IDENT.test(fn) || !keys.every((k) => IDENT.test(k))) {
          return send(res, 404, { code: "PGRST202", message: `Could not find the function public.${fn}` });
        }
        // Resolve like PostgREST's schema cache: same name, every given arg is a parameter,
        // every parameter without a default is given.
        const { rows: procs } = await pool.query(
          `select p.proargnames as names, p.pronargs as n, p.pronargdefaults as ndef,
                  p.prorettype = 'void'::regtype as is_void
             from pg_proc p join pg_namespace ns on ns.oid = p.pronamespace
            where ns.nspname = 'public' and p.proname = $1`,
          [fn]
        );
        const match = procs.find((p) => {
          const names = (p.names || []).slice(0, p.n);
          const required = names.slice(0, p.n - p.ndef);
          return keys.every((k) => names.includes(k)) && required.every((r) => keys.includes(r));
        });
        if (!match) {
          return send(res, 404, {
            code: "PGRST202",
            message: `Could not find the function public.${fn}(${keys.join(", ")}) in the schema cache`,
          });
        }
        const params = keys.map((k) => {
          const v = body[k];
          return v !== null && typeof v === "object" ? JSON.stringify(v) : v;
        });
        const call = `public.${fn}(${keys.map((k, i) => `${k} := $${i + 1}`).join(", ")})`;
        const out = await asRole(role, (c) =>
          c.query(match.is_void ? `select ${call}` : `select to_json(${call}) as r`, params)
        );
        if (match.is_void) return send(res, 204);
        return send(res, 200, out.rows[0].r);
      }

      const table = url.pathname.match(/^\/rest\/v1\/([a-z_][a-z0-9_]*)$/);
      if (table) {
        const t = `public.${table[1]}`;
        if (req.method === "GET") {
          const out = await asRole(role, (c) => c.query(`select coalesce(json_agg(x), '[]') as r from (select * from ${t} limit 100) x`));
          return send(res, 200, out.rows[0].r);
        }
        if (req.method === "POST") {
          const cols = Object.keys(body).filter((k) => IDENT.test(k));
          await asRole(role, (c) =>
            c.query(
              `insert into ${t} (${cols.join(",")}) values (${cols.map((_, i) => `$${i + 1}`).join(",")})`,
              cols.map((k) => body[k])
            )
          );
          return send(res, 201, null);
        }
        if (req.method === "PATCH") {
          const cols = Object.keys(body).filter((k) => IDENT.test(k));
          await asRole(role, (c) =>
            c.query(`update ${t} set ${cols.map((k, i) => `${k} = $${i + 1}`).join(",")}`, cols.map((k) => body[k]))
          );
          return send(res, 204);
        }
        if (req.method === "DELETE") {
          await asRole(role, (c) => c.query(`delete from ${t}`));
          return send(res, 204);
        }
      }
      return send(res, 404, { message: "not found" });
    } catch (e) {
      return send(res, statusFor(e.code, role), {
        code: e.code ?? null,
        message: e.message,
        details: e.detail ?? null,
        hint: e.hint ?? null,
      });
    }
  });

  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    pool,
    stats,
    close: async () => {
      await new Promise((r) => server.close(r));
      await pool.end();
    },
  };
}
