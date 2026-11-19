// Remote backend: Supabase (PostgREST RPC). Agents on different machines share one project.
// Identity comes from the per-agent token; the database decides who the sender is.
// See supabase/migration.sql for the functions called here.

import { BridgeError, isUuid, validateOutgoing } from "./common.js";

const TIMEOUT_MS = 15000;

export class SupabaseStore {
  constructor({ url, key, token, fetchImpl = globalThis.fetch }) {
    if (!url) throw new BridgeError("SUPABASE_URL is not set.");
    if (!key) throw new BridgeError("SUPABASE_PUBLISHABLE_KEY is not set.");
    if (!token) throw new BridgeError("No agent token: set AGENT_BRIDGE_TOKEN or AGENT_BRIDGE_TOKEN_FILE.");
    this.url = url.replace(/\/+$/, "");
    this.key = key;
    this.token = token;
    this.fetch = fetchImpl;
    this.pollIntervalMs = 2000;
    this.agent = null;
  }

  describe() {
    return `supabase:${this.url}`;
  }

  // PostgREST RPC call. New Supabase keys (sb_publishable_/sb_secret_) must go ONLY in the
  // apikey header; legacy JWT keys may also be sent as a Bearer token.
  async rpc(fn, args = {}, { retries = 0, key = this.key } = {}) {
    const headers = { apikey: key, "Content-Type": "application/json", Accept: "application/json" };
    if (key.startsWith("eyJ")) headers.Authorization = `Bearer ${key}`;
    for (let attempt = 0; ; attempt++) {
      let res;
      try {
        res = await this.fetch(`${this.url}/rest/v1/rpc/${fn}`, {
          method: "POST",
          headers,
          body: JSON.stringify(args),
          signal: AbortSignal.timeout(TIMEOUT_MS),
        });
      } catch (e) {
        if (attempt < retries) {
          await new Promise((r) => setTimeout(r, 500 * 2 ** attempt));
          continue;
        }
        throw new BridgeError(`Can't reach Supabase (${this.url}): ${e.cause?.code || e.name || e.message}`);
      }
      if (res.status >= 500 && attempt < retries) {
        await new Promise((r) => setTimeout(r, 500 * 2 ** attempt));
        continue;
      }
      if (res.status === 204) return null;
      const text = await res.text();
      let data = null;
      try {
        data = text ? JSON.parse(text) : null;
      } catch {
        data = text;
      }
      if (!res.ok) {
        const msg = (data && (data.message || data.msg || data.error)) || `HTTP ${res.status}`;
        if (res.status === 404 && data?.code === "PGRST202") {
          throw new BridgeError(
            `Supabase function ${fn} not found. Run supabase/migration.sql in your project first.`
          );
        }
        throw new BridgeError(msg);
      }
      return data;
    }
  }

  async identify() {
    const me = await this.rpc("bridge_whoami", { p_token: this.token }, { retries: 2 });
    this.agent = me.agent;
    return me.agent;
  }

  async whoami() {
    const me = await this.rpc("bridge_whoami", { p_token: this.token }, { retries: 2 });
    this.agent = me.agent;
    return me;
  }

  async heartbeat({ description = null, projectDir = null } = {}) {
    await this.rpc(
      "bridge_heartbeat",
      { p_token: this.token, p_description: description, p_project_dir: projectDir },
      { retries: 2 }
    );
  }

  async listAgents() {
    return this.rpc("bridge_list_agents", { p_token: this.token }, { retries: 2 });
  }

  // Not retried: a retry after a lost response could deliver the message twice.
  async send({ to, body, type = "request", subject = null, threadId = null, maxHops = 20 }) {
    validateOutgoing({ from: this.agent, to, body, type, subject, threadId });
    return this.rpc("bridge_send", {
      p_token: this.token,
      p_to: to,
      p_body: body,
      p_type: type,
      p_subject: subject,
      p_thread_id: threadId,
      p_max_hops: maxHops,
    });
  }

  // Not retried when marking read, for the same reason as send.
  async inbox({ limit = 20, markRead = true, threadId = null } = {}) {
    if (threadId != null && !isUuid(threadId)) throw new BridgeError(`Unknown thread_id ${threadId}.`);
    return this.rpc(
      "bridge_inbox",
      { p_token: this.token, p_limit: limit, p_mark_read: markRead, p_thread_id: threadId },
      { retries: markRead ? 0 : 2 }
    );
  }

  async unreadSummary() {
    return this.rpc("bridge_unread_summary", { p_token: this.token }, { retries: 2 });
  }

  async thread(threadId) {
    if (!isUuid(threadId)) throw new BridgeError(`Unknown thread_id ${threadId}.`);
    return this.rpc("bridge_thread", { p_token: this.token, p_thread_id: threadId }, { retries: 2 });
  }

  async recent({ limit = 20, afterId = 0 } = {}) {
    return this.rpc("bridge_recent", { p_token: this.token, p_limit: limit, p_after_id: afterId }, { retries: 2 });
  }

  async close() {}
}

// Admin calls need the project's SECRET key (sb_secret_... or legacy service_role JWT).
export class SupabaseAdmin {
  constructor({ url, secretKey, fetchImpl = globalThis.fetch }) {
    if (!secretKey) throw new BridgeError("Admin commands need SUPABASE_SECRET_KEY (the project's secret key).");
    this.store = new SupabaseStore({ url, key: secretKey, token: "admin-unused-token-value", fetchImpl });
  }
  createAgent(name, description = null) {
    return this.store.rpc("bridge_admin_create_agent", { p_name: name, p_description: description });
  }
  rotateToken(name) {
    return this.store.rpc("bridge_admin_rotate_token", { p_name: name });
  }
  revokeAgent(name) {
    return this.store.rpc("bridge_admin_revoke_agent", { p_name: name });
  }
  purge(days) {
    return this.store.rpc("bridge_admin_purge", { p_older_than: `${Number(days)} days` });
  }
}
