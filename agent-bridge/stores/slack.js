// Slack backend: agents talk in one Slack channel. Each agent is its own Slack app (bot user),
// so Slack decides who sent a message: the sender is the bot user that posted it, never a field
// in the message. People in the channel can watch, and can address an agent ("@frontend ...").
//
// Messages are ordinary top-level posts: readable text for people, plus Slack message metadata
// (event_type "agent_bridge_msg") for agents. A message is claimed by adding a ✅ reaction from
// the receiving bot; Slack answers "already_reacted" to a second claim, which makes the claim
// atomic and shows people in the channel what has been picked up. Polling is stateless: every
// read scans the channel history over a lookback window (default 72 h).
//
// Trust model: everyone in the channel can read everything; keep the channel private and invite
// only the agents' bots and the people who should see the traffic. Hop caps and thread rules are
// applied by every agent-bridge client (sender and receiver), not by a server.

import { BridgeError, NetworkError, AGENT_NAME_RE, LIMITS, assertSecureUrl, validateOutgoing } from "./common.js";

const TIMEOUT_MS = 15000;
const EVENT_TYPE = "agent_bridge_msg";
const CLAIM = "white_check_mark";
const SLACK_TEXT_MAX = 40000;
export const SLACK_BODY_MAX = 30000; // leaves room for the header and Slack's &amp; escaping
const HUMAN_RE = /^human:[a-z0-9][a-z0-9._-]{0,79}$/;
export const isSlackTs = (s) => typeof s === "string" && /^\d{9,11}\.\d{6}$/.test(s);

// Slack's three escapes. Escaping & first keeps an escaped body round-trippable.
const escape = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const unescape = (s) => s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
const tsToIso = (ts) => new Date(Math.floor(parseFloat(ts) * 1000)).toISOString();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const AUTH_ERRORS = new Set(["invalid_auth", "not_authed", "account_inactive", "token_revoked", "token_expired"]);

export class SlackStore {
  constructor({ apiUrl = "https://slack.com/api", token, channel, lookbackHours = 72, fetchImpl = globalThis.fetch }) {
    if (!token) throw new BridgeError("No agent token: set SLACK_BOT_TOKEN or SLACK_BOT_TOKEN_FILE.");
    if (!channel) throw new BridgeError("SLACK_CHANNEL_ID is not set (the bridge channel's ID, like C0123ABCDEF).");
    assertSecureUrl(apiUrl, "SLACK_API_URL");
    this.apiUrl = apiUrl.replace(/\/+$/, "");
    this.token = token;
    this.channel = channel;
    this.lookbackSec = Math.max(1, Number(lookbackHours) || 72) * 3600;
    this.fetch = fetchImpl;
    this.pollIntervalMs = 3000;
    this.me = null; // { id, name }
    this.dir = null; // { at, byId: Map(id -> {name, is_bot}), botsByName: Map(name -> [ids]) }
  }

  describe() {
    return `slack:${this.channel}`;
  }

  isThreadId(id) {
    return isSlackTs(id);
  }

  // ------------------------------------------------------------------ Slack Web API

  async api(method, params = {}, { retries = 0 } = {}) {
    const form = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v == null) continue;
      form.set(k, typeof v === "object" ? JSON.stringify(v) : String(v));
    }
    for (let attempt = 0; ; attempt++) {
      let res;
      try {
        res = await this.fetch(`${this.apiUrl}/${method}`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${this.token}`,
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
          },
          body: form.toString(),
          signal: AbortSignal.timeout(TIMEOUT_MS),
          redirect: "error", // never send the bot token anywhere else
        });
      } catch (e) {
        if (attempt < retries) {
          await sleep(500 * 2 ** attempt);
          continue;
        }
        throw new NetworkError(
          `Can't reach Slack (${this.apiUrl}): ${e.cause?.code || e.cause?.message || e.name || e.message}`,
          e.cause?.code || e.code || null
        );
      }
      if (res.status === 429 || res.status >= 500) {
        const wait = Math.min(Number(res.headers.get("retry-after")) || 1, 10) * 1000;
        if (attempt < retries) {
          await sleep(wait);
          continue;
        }
        throw new NetworkError(res.status === 429 ? `Slack rate limit on ${method}; try again shortly.` : `Slack HTTP ${res.status}`);
      }
      let data;
      try {
        data = await res.json();
      } catch {
        throw new NetworkError(`Slack returned a non-JSON answer (HTTP ${res.status}).`);
      }
      if (!data.ok) {
        const err = data.error || "unknown_error";
        if (AUTH_ERRORS.has(err)) throw new BridgeError(`invalid agent token (Slack: ${err})`);
        if (err === "not_in_channel" || err === "channel_not_found") {
          throw new BridgeError(`This agent's Slack bot can't use channel ${this.channel} (${err}). Invite the bot to the channel.`);
        }
        const e = new BridgeError(`Slack error on ${method}: ${err}`);
        e.slackError = err;
        throw e;
      }
      return data;
    }
  }

  // ------------------------------------------------------------------ identity

  async identify() {
    const a = await this.api("auth.test", {}, { retries: 2 });
    if (!AGENT_NAME_RE.test(a.user || "")) {
      throw new BridgeError(
        `This bot's Slack username "${a.user}" isn't a valid agent name. Rename the bot user to lowercase letters, digits, - or _.`
      );
    }
    this.me = { id: a.user_id, name: a.user };
    const dir = await this.directory(true);
    if (!dir.byId.has(this.me.id)) {
      throw new BridgeError(`This agent's Slack bot isn't a member of channel ${this.channel}. Invite it to the channel.`);
    }
    if ((dir.botsByName.get(this.me.name) || []).length > 1) {
      throw new BridgeError(`Another bot in the channel is also named "${this.me.name}". Bot names must be unique.`);
    }
    return this.me.name;
  }

  async ensureMe() {
    if (!this.me) await this.identify();
    return this.me;
  }

  // Channel members -> names. Bots are agents; people can be addressed as "human:<username>".
  async directory(force = false) {
    if (!force && this.dir && Date.now() - this.dir.at < 30000) return this.dir;
    const ids = [];
    let cursor;
    do {
      const r = await this.api("conversations.members", { channel: this.channel, limit: 200, cursor }, { retries: 2 });
      ids.push(...r.members);
      cursor = r.response_metadata?.next_cursor || undefined;
    } while (cursor);
    const byId = new Map();
    const old = this.dir?.byId || new Map();
    for (const id of ids) {
      let u = old.get(id);
      if (!u) {
        const r = await this.api("users.info", { user: id }, { retries: 2 });
        u = { name: r.user.name, is_bot: !!r.user.is_bot, deleted: !!r.user.deleted };
      }
      if (!u.deleted) byId.set(id, u);
    }
    const botsByName = new Map();
    const humansByName = new Map();
    for (const [id, u] of byId) {
      const m = u.is_bot ? botsByName : humansByName;
      m.set(u.name, [...(m.get(u.name) || []), id]);
    }
    this.dir = { at: Date.now(), byId, botsByName, humansByName };
    return this.dir;
  }

  // The agent name for a bot user id, or null if it isn't a valid, unambiguous agent.
  agentNameOf(dir, userId) {
    const u = dir.byId.get(userId);
    if (!u || !u.is_bot || !AGENT_NAME_RE.test(u.name)) return null;
    return (dir.botsByName.get(u.name) || []).length === 1 ? u.name : null;
  }

  // ------------------------------------------------------------------ reading the channel

  // Every bridge message in the lookback window, oldest first. Anything malformed is ignored.
  async scan() {
    const me = await this.ensureMe();
    const dir = await this.directory();
    const oldest = (Date.now() / 1000 - this.lookbackSec).toFixed(6);
    const raw = [];
    let cursor;
    for (let page = 0; page < 20; page++) {
      const r = await this.api(
        "conversations.history",
        { channel: this.channel, oldest, limit: 200, include_all_metadata: true, cursor },
        { retries: 2 }
      );
      raw.push(...r.messages);
      cursor = r.response_metadata?.next_cursor;
      if (!r.has_more || !cursor) break;
    }
    raw.sort((a, b) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : 0));
    const out = [];
    const threads = new Map(); // thread id -> { cap, members, lastHop }
    for (const m of raw) {
      const parsed = m.metadata?.event_type === EVENT_TYPE ? this.parseAgentMessage(m, dir) : this.parseHumanMessage(m, dir);
      if (!parsed) continue;
      // Nothing in Slack stops a bot posting whatever metadata it likes, so every reader applies the
      // thread rules itself: a reply needs a known thread start, stays between that thread's two
      // participants, and can't go past the cap the thread started with.
      if (parsed.hop === 1) {
        if (threads.has(parsed.thread_id)) continue;
        threads.set(parsed.thread_id, {
          cap: parsed.max_hops,
          members: new Set([parsed.from_agent, parsed.to_agent]),
          count: 1,
        });
      } else {
        const t = threads.get(parsed.thread_id);
        if (!t) continue; // start not seen (outside the lookback window, or never existed)
        if (!t.members.has(parsed.from_agent) || !t.members.has(parsed.to_agent)) continue;
        // Count messages rather than trusting hop numbers: without a lock, two replies sent at
        // the same moment can carry the same hop, and both must still arrive.
        t.count += 1;
        if (t.count > t.cap) continue;
        parsed.hop = t.count;
        parsed.max_hops = t.cap;
      }
      const claim = (m.reactions || []).find((r) => r.name === CLAIM);
      parsed.read_at = parsed.to_agent === me.name && claim?.users?.includes(me.id) ? "claimed" : null;
      out.push(parsed);
    }
    return out;
  }

  parseAgentMessage(m, dir) {
    if (!m.bot_id || m.subtype) return null;
    const from = this.agentNameOf(dir, m.user); // who posted, according to Slack
    const p = m.metadata?.event_payload;
    if (!from || !p || p.v !== 1) return null;
    const to = String(p.to || "");
    if (!AGENT_NAME_RE.test(to) && !HUMAN_RE.test(to)) return null;
    if (to === from) return null;
    if (!["request", "response", "fyi"].includes(p.type)) return null;
    const hop = Number(p.hop);
    const max = Number(p.max_hops);
    if (!Number.isInteger(hop) || !Number.isInteger(max) || hop < 1 || max < 1 || max > LIMITS.maxHopsCap || hop > max) {
      return null;
    }
    const thread = hop === 1 ? m.ts : String(p.thread_id || "");
    if (!isSlackTs(thread) || thread > m.ts) return null;
    const nl = (m.text || "").indexOf("\n");
    if (nl < 0) return null;
    const subject = typeof p.subject === "string" && !/[\r\n]/.test(p.subject) ? p.subject.slice(0, LIMITS.subject) : null;
    return {
      id: m.ts,
      thread_id: thread,
      from_agent: from,
      to_agent: to,
      type: p.type,
      subject,
      body: unescape(m.text.slice(nl + 1)),
      hop,
      max_hops: max,
      created_at: tsToIso(m.ts),
    };
  }

  // A person in the channel addressing an agent: "<@BOTID> ...", "@name ..." or "name: ...".
  parseHumanMessage(m, dir) {
    if (m.bot_id || m.subtype || !m.user) return null;
    const u = dir.byId.get(m.user);
    if (!u || u.is_bot || !/^[a-z0-9][a-z0-9._-]{0,79}$/.test(u.name)) return null;
    const text = (m.text || "").trim();
    let to = null;
    let rest = null;
    const mention = text.match(/^<@([A-Z0-9]+)(?:\|[^>]*)?>[\s:,]*([\s\S]*)$/);
    if (mention) {
      to = this.agentNameOf(dir, mention[1]);
      rest = mention[2];
    } else {
      const named = text.match(/^@?([a-z0-9][a-z0-9_-]{0,39})(?::|\s)\s*([\s\S]*)$/i);
      if (named && (text.startsWith("@") || /^[^\s]+:/.test(text))) {
        const name = named[1].toLowerCase();
        if ((dir.botsByName.get(name) || []).length === 1) {
          to = name;
          rest = named[2];
        }
      }
    }
    if (!to || !rest || !rest.trim()) return null;
    return {
      id: m.ts,
      thread_id: m.ts,
      from_agent: `human:${u.name}`,
      to_agent: to,
      type: "request",
      subject: null,
      body: unescape(rest.trim()),
      hop: 1,
      max_hops: 20,
      created_at: tsToIso(m.ts),
    };
  }

  // ------------------------------------------------------------------ store interface

  async heartbeat() {}

  async whoami() {
    const me = await this.ensureMe();
    const unread = (await this.scan()).filter((x) => x.to_agent === me.name && !x.read_at).length;
    return { agent: me.name, description: null, project_dir: null, unread };
  }

  async listAgents() {
    const dir = await this.directory(true);
    const out = [];
    for (const [name, ids] of dir.botsByName) {
      if (!AGENT_NAME_RE.test(name)) continue;
      out.push({ name, description: ids.length > 1 ? "ambiguous: several bots share this name" : null, project_dir: null, last_seen: null });
    }
    return out.sort((a, b) => (a.name < b.name ? -1 : 1));
  }

  async send({ to, body, type = "request", subject = null, threadId = null, maxHops = 20 }) {
    const me = await this.ensureMe();
    const checked = validateOutgoing(
      { from: me.name, to, body, type, subject, threadId },
      {
        isThreadId: isSlackTs,
        maxBody: SLACK_BODY_MAX,
        validateRecipient: (t) => {
          if (!AGENT_NAME_RE.test(t) && !HUMAN_RE.test(t)) {
            throw new BridgeError(`Invalid agent name ${JSON.stringify(t)}: use an agent name or human:<slack-username>.`);
          }
        },
      }
    );
    ({ body, subject } = checked); // DLP may have redacted them
    const dir = await this.directory(true);
    let mention = "";
    if (HUMAN_RE.test(to)) {
      const ids = dir.humansByName.get(to.slice(6)) || [];
      if (ids.length !== 1) throw new BridgeError(`Unknown person "${to}" in the bridge channel.`);
      mention = `<@${ids[0]}> `;
    } else if ((dir.botsByName.get(to) || []).length !== 1) {
      throw new BridgeError(`Unknown agent "${to}". Use list_agents to see who is in the channel.`);
    }

    let hop = 1;
    let max = Math.min(Math.max(Number(maxHops) || 20, 1), LIMITS.maxHopsCap);
    if (threadId) {
      const msgs = (await this.scan()).filter((x) => x.thread_id === threadId);
      const inThread = (who) => msgs.some((x) => x.from_agent === who || x.to_agent === who);
      if (!inThread(me.name)) throw new BridgeError(`Unknown thread_id ${threadId}. Omit it to start a new thread.`);
      if (!inThread(to)) throw new BridgeError(`"${to}" is not part of this thread. Start a new thread to include them.`);
      const last = msgs.reduce((a, b) => (b.hop > a.hop ? b : a));
      hop = last.hop + 1;
      max = msgs[0].max_hops; // the cap the thread started with
      if (hop > max) {
        throw new BridgeError(
          `Thread ${threadId} hit the ${max}-message limit (loop protection). Ask a human before continuing, or start a new thread with a summary.`
        );
      }
    }

    const header =
      `*${me.name} → ${mention || to}* · ${type}` +
      (subject ? ` · ${escape(subject)}` : "") +
      (threadId ? ` · re ${threadId}` : "");
    const text = `${header}\n${escape(body)}`;
    if ([...text].length > SLACK_TEXT_MAX) {
      throw new BridgeError(`body is too long for Slack after escaping (max ${SLACK_TEXT_MAX} characters in total).`);
    }
    const payload = { v: 1, to, type, hop, max_hops: max };
    if (subject) payload.subject = subject;
    if (threadId) payload.thread_id = threadId;
    // Not retried: a retry after a lost response could post the message twice.
    const r = await this.api("chat.postMessage", {
      channel: this.channel,
      text,
      metadata: { event_type: EVENT_TYPE, event_payload: payload },
      unfurl_links: false,
      unfurl_media: false,
    });
    return {
      id: r.ts,
      thread_id: threadId || r.ts,
      from_agent: me.name,
      to_agent: to,
      type,
      subject,
      body,
      hop,
      max_hops: max,
      created_at: tsToIso(r.ts),
      read_at: null,
      dlp: checked.dlp,
    };
  }

  async inbox({ limit = 20, markRead = true, threadId = null, fromAgent = null } = {}) {
    const me = await this.ensureMe();
    if (threadId != null && !isSlackTs(threadId)) throw new BridgeError(`Unknown thread_id ${threadId}.`);
    if (fromAgent != null && !AGENT_NAME_RE.test(fromAgent) && !HUMAN_RE.test(fromAgent)) {
      throw new BridgeError(`Invalid agent name ${JSON.stringify(fromAgent)}.`);
    }
    const lim = Math.min(Math.max(Number(limit) || 20, 1), 100);
    const unread = (await this.scan()).filter(
      (x) =>
        x.to_agent === me.name &&
        !x.read_at &&
        (threadId == null || x.thread_id === threadId) &&
        (fromAgent == null || x.from_agent === fromAgent)
    );
    if (!markRead) return unread.slice(0, lim);
    const claimed = [];
    for (const m of unread) {
      if (claimed.length >= lim) break;
      try {
        await this.api("reactions.add", { channel: this.channel, timestamp: m.id, name: CLAIM });
      } catch (e) {
        if (e.slackError === "already_reacted") continue; // another session of this agent took it
        if (claimed.length) break; // hand over what we already hold
        throw e;
      }
      claimed.push({ ...m, read_at: new Date().toISOString() });
    }
    return claimed;
  }

  async unmark(ids) {
    let n = 0;
    for (const id of ids || []) {
      try {
        await this.api("reactions.remove", { channel: this.channel, timestamp: id, name: CLAIM }, { retries: 2 });
        n++;
      } catch (e) {
        if (e.slackError !== "no_reaction") throw e;
      }
    }
    return n;
  }

  async unreadSummary() {
    const me = await this.ensureMe();
    const counts = new Map();
    for (const x of await this.scan()) {
      if (x.to_agent === me.name && !x.read_at) counts.set(x.from_agent, (counts.get(x.from_agent) || 0) + 1);
    }
    return [...counts].sort().map(([from_agent, n]) => ({ from_agent, n }));
  }

  async thread(threadId) {
    const me = await this.ensureMe();
    if (!isSlackTs(threadId)) throw new BridgeError(`Unknown thread_id ${threadId}.`);
    const msgs = (await this.scan()).filter((x) => x.thread_id === threadId);
    if (!msgs.some((x) => x.from_agent === me.name || x.to_agent === me.name)) {
      throw new BridgeError(`Unknown thread_id ${threadId}.`);
    }
    return msgs;
  }

  async recent({ limit = 20, afterId = 0 } = {}) {
    const me = await this.ensureMe();
    const lim = Math.min(Math.max(Number(limit) || 20, 1), 200);
    const mine = (await this.scan()).filter((x) => x.from_agent === me.name || x.to_agent === me.name);
    if (afterId && afterId !== "0") return mine.filter((x) => x.id > String(afterId)).slice(0, lim);
    return mine.slice(-lim);
  }

  async close() {}
}
