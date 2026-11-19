// Test-only stand-in for the Slack Web API, with the behaviour agent-bridge relies on:
//   * Authorization: Bearer xoxb-...; unknown token -> {ok:false, error:"invalid_auth"} (HTTP 200, like Slack)
//   * form-encoded bodies (application/x-www-form-urlencoded), JSON responses
//   * chat.postMessage: channel membership (not_in_channel), text <= 40,000 chars (msg_too_long),
//     metadata as a JSON string {event_type, event_payload}, username override (does NOT change `user`)
//   * conversations.history: newest first, oldest/latest exclusive unless inclusive, limit + cursor,
//     metadata only with include_all_metadata=true, reactions [{name, users, count}] on each message
//   * reactions.add (already_reacted) / reactions.remove (no_reaction)
//   * users.info, conversations.members, auth.test
//   * 429 + Retry-After when a method is in `throttle`
import http from "node:http";

export async function startFakeSlack() {
  const users = new Map(); // id -> {id, name, is_bot, token, deleted}
  const byToken = new Map();
  const channel = { id: "C0BRIDGE01", members: new Set() };
  const messages = []; // oldest first
  const throttle = new Set();
  const calls = [];
  let clock = Math.floor(Date.now() / 1000) * 1_000_000; // microseconds, strictly increasing
  let nextUser = 1;

  const nextTs = () => {
    clock = Math.max(clock + 1, Date.now() * 1000);
    const s = String(clock);
    return `${s.slice(0, -6)}.${s.slice(-6)}`;
  };

  function addUser({ name, isBot = true, member = true }) {
    const id = (isBot ? "UB" : "UH") + String(nextUser++).padStart(7, "0");
    const token = isBot ? `xoxb-test-${id}-${Math.random().toString(36).slice(2)}` : null;
    const u = { id, name, is_bot: isBot, token, deleted: false };
    users.set(id, u);
    if (token) byToken.set(token, u);
    if (member) channel.members.add(id);
    return u;
  }

  // A message as Slack stores it; `text` is already Slack-escaped by the poster.
  function post(user, { text, metadata = null, username = null, ts = nextTs() }) {
    const m = { type: "message", ts, user: user.id, text, reactions: [] };
    if (user.is_bot) {
      m.bot_id = "B" + user.id.slice(2);
      m.bot_profile = { name: username || user.name };
      if (username) m.username = username;
    }
    if (metadata) m.metadata = metadata;
    messages.push(m);
    messages.sort((a, b) => (a.ts < b.ts ? -1 : 1));
    return m;
  }

  const view = (m, withMeta) => {
    const out = { ...m, reactions: m.reactions.filter((r) => r.users.length).map((r) => ({ ...r, users: [...r.users], count: r.users.length })) };
    if (!out.reactions.length) delete out.reactions;
    if (!withMeta) delete out.metadata;
    return out;
  };

  const methods = {
    "auth.test": (u) => ({ ok: true, user_id: u.id, user: u.name, bot_id: "B" + u.id.slice(2), team_id: "T0TEST" }),
    "users.info": (u, a) => {
      const x = users.get(a.user);
      if (!x) return { ok: false, error: "user_not_found" };
      return { ok: true, user: { id: x.id, name: x.name, is_bot: x.is_bot, deleted: x.deleted } };
    },
    "conversations.members": (u, a) => {
      if (a.channel !== channel.id) return { ok: false, error: "channel_not_found" };
      if (!channel.members.has(u.id)) return { ok: false, error: "not_in_channel" };
      return { ok: true, members: [...channel.members], response_metadata: { next_cursor: "" } };
    },
    "chat.postMessage": (u, a) => {
      if (a.channel !== channel.id) return { ok: false, error: "channel_not_found" };
      if (!channel.members.has(u.id)) return { ok: false, error: "not_in_channel" };
      const text = a.text ?? "";
      if (!text) return { ok: false, error: "no_text" };
      if ([...text].length > 40000) return { ok: false, error: "msg_too_long" };
      let metadata = null;
      if (a.metadata) {
        try {
          metadata = JSON.parse(a.metadata);
        } catch {
          return { ok: false, error: "invalid_metadata_format" };
        }
      }
      const m = post(u, { text, metadata, username: a.username || null });
      return { ok: true, channel: channel.id, ts: m.ts, message: view(m, true) };
    },
    "conversations.history": (u, a) => {
      if (a.channel !== channel.id) return { ok: false, error: "channel_not_found" };
      if (!channel.members.has(u.id)) return { ok: false, error: "not_in_channel" };
      const inclusive = a.inclusive === "true" || a.inclusive === "1";
      const limit = Math.min(Math.max(Number(a.limit) || 100, 1), 999);
      const withMeta = (a.include_all_metadata === "true" || a.include_all_metadata === "1") && (a.oldest || a.latest);
      let list = [...messages].reverse(); // newest first
      if (a.oldest) list = list.filter((m) => (inclusive ? m.ts >= a.oldest : m.ts > a.oldest));
      if (a.latest) list = list.filter((m) => (inclusive ? m.ts <= a.latest : m.ts < a.latest));
      const start = a.cursor ? Number(Buffer.from(a.cursor, "base64").toString()) : 0;
      const page = list.slice(start, start + limit);
      const more = start + limit < list.length;
      return {
        ok: true,
        messages: page.map((m) => view(m, withMeta)),
        has_more: more,
        response_metadata: { next_cursor: more ? Buffer.from(String(start + limit)).toString("base64") : "" },
      };
    },
    "reactions.add": (u, a) => {
      if (!channel.members.has(u.id)) return { ok: false, error: "not_in_channel" };
      const m = messages.find((x) => x.ts === a.timestamp);
      if (!m) return { ok: false, error: "message_not_found" };
      let r = m.reactions.find((x) => x.name === a.name);
      if (!r) m.reactions.push((r = { name: a.name, users: [] }));
      if (r.users.includes(u.id)) return { ok: false, error: "already_reacted" };
      r.users.push(u.id);
      return { ok: true };
    },
    "reactions.remove": (u, a) => {
      const m = messages.find((x) => x.ts === a.timestamp);
      if (!m) return { ok: false, error: "message_not_found" };
      const r = m.reactions.find((x) => x.name === a.name);
      if (!r || !r.users.includes(u.id)) return { ok: false, error: "no_reaction" };
      r.users = r.users.filter((x) => x !== u.id);
      return { ok: true };
    },
  };

  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks).toString("utf8");
    const send = (status, obj, headers = {}) => {
      res.writeHead(status, { "Content-Type": "application/json", ...headers }).end(JSON.stringify(obj));
    };
    const method = new URL(req.url, "http://x").pathname.replace(/^\/api\//, "");
    calls.push(method);
    if (throttle.has(method)) return send(429, { ok: false, error: "ratelimited" }, { "Retry-After": "1" });
    if (!methods[method]) return send(404, { ok: false, error: "unknown_method" });
    if (!/application\/x-www-form-urlencoded/.test(req.headers["content-type"] || "")) {
      return send(200, { ok: false, error: "invalid_form_data" });
    }
    const token = (req.headers.authorization || "").replace(/^Bearer /, "");
    const u = byToken.get(token);
    if (!u || u.deleted) return send(200, { ok: false, error: token ? "invalid_auth" : "not_authed" });
    const args = Object.fromEntries(new URLSearchParams(body));
    send(200, methods[method](u, args));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));

  return {
    url: `http://127.0.0.1:${server.address().port}/api`,
    channel,
    users,
    messages,
    throttle,
    calls,
    addUser,
    // Post directly, as a human or a misbehaving bot would (text is used as given).
    postAs: (user, opts) => post(user, opts),
    close: () => new Promise((r) => server.close(r)),
  };
}
