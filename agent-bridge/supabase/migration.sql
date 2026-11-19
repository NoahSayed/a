-- agent-bridge: Supabase / Postgres backend
--
-- Security model
--   * Agents talk to PostgREST with the project's PUBLISHABLE (anon) key plus their own
--     per-agent token. The tables are not readable or writable by anon/authenticated at all.
--   * Every operation goes through a SECURITY DEFINER function that resolves the caller's
--     identity from the token (stored only as a SHA-256 hash). The sender of a message is
--     always the token's agent, so agents can't impersonate each other or read others' mail.
--   * Abuse limits per sending agent (rate, unread backlog per recipient, bytes per day) live in
--     bridge_settings; threads stay between their two participants and keep their starting cap.
--   * Admin functions (create/rotate/revoke/delete agents, limits, purge) are callable only by service_role
--     (the secret key) or from the SQL editor.
--
-- Everything is prefixed bridge_ so it can live next to other tables in an existing project.
-- Safe to re-run: functions use CREATE OR REPLACE, tables/indexes use IF NOT EXISTS.

create table if not exists public.bridge_agents (
  name         text primary key check (name ~ '^[a-z0-9][a-z0-9_-]{0,39}$'),
  description  text check (char_length(description) <= 500),
  project_dir  text check (char_length(project_dir) <= 1000),
  token_hash   bytea not null unique,
  created_at   timestamptz not null default now(),
  last_seen    timestamptz,
  revoked_at   timestamptz
);

create table if not exists public.bridge_messages (
  id          bigint generated always as identity primary key,
  thread_id   uuid not null,
  from_agent  text not null references public.bridge_agents (name) on update cascade,
  to_agent    text not null references public.bridge_agents (name) on update cascade,
  type        text not null check (type in ('request', 'response', 'fyi')),
  subject     text check (char_length(subject) <= 200),
  body        text not null check (char_length(body) between 1 and 50000),
  hop         int  not null check (hop >= 1),
  created_at  timestamptz not null default now(),
  read_at     timestamptz,
  max_hops    int  not null default 20 check (max_hops between 1 and 100),
  constraint bridge_messages_thread_hop_key unique (thread_id, hop),
  constraint bridge_messages_not_self check (from_agent <> to_agent),
  constraint bridge_messages_subject_one_line check (subject is null or subject !~ '[\r\n]')
);

-- Upgrades for databases created by an earlier version of this file.
do $$
begin
  if not exists (select 1 from information_schema.columns
                  where table_schema = 'public' and table_name = 'bridge_messages' and column_name = 'max_hops') then
    alter table public.bridge_messages add column max_hops int not null default 20 check (max_hops between 1 and 100);
  end if;
  if not exists (select 1 from pg_constraint where conname = 'bridge_messages_subject_one_line') then
    alter table public.bridge_messages add constraint bridge_messages_subject_one_line
      check (subject is null or subject !~ '[\r\n]') not valid;
  end if;
end $$;

-- Abuse limits (R1-03). One row; change it with bridge_admin_set_limits or `cli.js limits`.
create table if not exists public.bridge_settings (
  id                    int primary key default 1 check (id = 1),
  rate_per_minute       int    not null default 60       check (rate_per_minute between 1 and 10000),
  max_unread_per_sender int    not null default 200      check (max_unread_per_sender between 1 and 100000),
  max_bytes_per_day     bigint not null default 20000000 check (max_bytes_per_day between 1000 and 100000000000)
);
insert into public.bridge_settings (id) values (1) on conflict (id) do nothing;

create index if not exists bridge_messages_unread_idx on public.bridge_messages (to_agent, id) where read_at is null;
create index if not exists bridge_messages_to_idx     on public.bridge_messages (to_agent, id);
create index if not exists bridge_messages_from_idx   on public.bridge_messages (from_agent, id);
create index if not exists bridge_messages_from_time_idx on public.bridge_messages (from_agent, created_at);
create index if not exists bridge_messages_thread_idx on public.bridge_messages (thread_id, hop);

-- Lock the tables down: RLS on with no policies, and no table privileges for API roles.
alter table public.bridge_agents   enable row level security;
alter table public.bridge_messages enable row level security;
alter table public.bridge_settings enable row level security;
revoke all on table public.bridge_agents   from public, anon, authenticated;
revoke all on table public.bridge_messages from public, anon, authenticated;
revoke all on table public.bridge_settings from public, anon, authenticated;
-- Supabase's default privileges also cover sequences (R1-15).
do $$
declare v_seq text := pg_get_serial_sequence('public.bridge_messages', 'id');
begin
  execute format('revoke all on sequence %s from public', v_seq);
  if exists (select 1 from pg_roles where rolname = 'anon') then
    execute format('revoke all on sequence %s from anon, authenticated', v_seq);
  end if;
end $$;

-- ---------------------------------------------------------------- internal helpers

create or replace function public.bridge_hash_token(p_token text)
returns bytea language sql immutable set search_path = '' as $$
  select pg_catalog.sha256(pg_catalog.convert_to(p_token, 'UTF8'))
$$;

create or replace function public.bridge_new_token()
returns text language sql volatile set search_path = '' as $$
  select 'abt_' || pg_catalog.replace(pg_catalog.gen_random_uuid()::text, '-', '')
                || pg_catalog.replace(pg_catalog.gen_random_uuid()::text, '-', '')
$$;

-- Resolves a token to an agent name or raises. Touches last_seen at most every 30s.
create or replace function public.bridge_auth(p_token text)
returns text language plpgsql security definer set search_path = '' as $$
declare
  v_name text;
  v_seen timestamptz;
begin
  if p_token is null or char_length(p_token) < 20 or char_length(p_token) > 200 then
    raise exception 'invalid agent token' using errcode = '28000';
  end if;
  select a.name, a.last_seen into v_name, v_seen
    from public.bridge_agents a
   where a.token_hash = public.bridge_hash_token(p_token) and a.revoked_at is null;
  if v_name is null then
    raise exception 'invalid agent token' using errcode = '28000';
  end if;
  if v_seen is null or v_seen < now() - interval '30 seconds' then
    update public.bridge_agents set last_seen = now() where name = v_name;
  end if;
  return v_name;
end $$;

-- ---------------------------------------------------------------- agent API (anon-callable)

create or replace function public.bridge_whoami(p_token text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_me text := public.bridge_auth(p_token);
begin
  return (
    select pg_catalog.jsonb_build_object(
      'agent', a.name, 'description', a.description, 'project_dir', a.project_dir,
      'unread', (select count(*) from public.bridge_messages m where m.to_agent = v_me and m.read_at is null))
    from public.bridge_agents a where a.name = v_me);
end $$;

create or replace function public.bridge_heartbeat(p_token text, p_description text default null, p_project_dir text default null)
returns void language plpgsql security definer set search_path = '' as $$
declare v_me text := public.bridge_auth(p_token);
begin
  update public.bridge_agents
     set description = coalesce(p_description, description),
         project_dir = coalesce(p_project_dir, project_dir),
         last_seen   = now()
   where name = v_me;
end $$;

create or replace function public.bridge_list_agents(p_token text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_me text := public.bridge_auth(p_token);
begin
  return coalesce((
    select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
             'name', a.name, 'description', a.description,
             'project_dir', a.project_dir, 'last_seen', a.last_seen) order by a.name)
      from public.bridge_agents a where a.revoked_at is null), '[]'::jsonb);
end $$;

create or replace function public.bridge_send(
  p_token     text,
  p_to        text,
  p_body      text,
  p_type      text    default 'request',
  p_subject   text    default null,
  p_thread_id uuid    default null,
  p_max_hops  int     default 20
) returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  v_me     text := public.bridge_auth(p_token);
  v_cfg    public.bridge_settings;
  v_thread uuid;
  v_hop    int;
  v_max    int;
  v_n      bigint;
  v_row    public.bridge_messages;
begin
  if p_to = v_me then
    raise exception 'An agent cannot message itself.' using errcode = 'P0001';
  end if;
  if not exists (select 1 from public.bridge_agents where name = p_to and revoked_at is null) then
    raise exception 'Unknown agent "%". Use list_agents to see who is registered.', p_to using errcode = 'P0001';
  end if;
  if coalesce(p_type, 'request') not in ('request', 'response', 'fyi') then
    raise exception 'type must be one of request, response, fyi' using errcode = 'P0001';
  end if;

  -- Abuse limits (R1-03), checked under a per-sender lock so parallel sends can't overshoot.
  -- Lock order everywhere: sender, then thread.
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('bridge-sender:' || v_me, 0));
  select * into v_cfg from public.bridge_settings where id = 1;
  select count(*) into v_n from public.bridge_messages
   where from_agent = v_me and created_at > now() - interval '1 minute';
  if v_n >= v_cfg.rate_per_minute then
    raise exception 'Rate limit: at most % messages per minute per agent. Wait a moment and send fewer, longer messages.',
      v_cfg.rate_per_minute using errcode = 'P0001';
  end if;
  select count(*) into v_n from public.bridge_messages
   where from_agent = v_me and to_agent = p_to and read_at is null;
  if v_n >= v_cfg.max_unread_per_sender then
    raise exception '"%" already has % unread messages from you. Wait until they read them.', p_to, v_n using errcode = 'P0001';
  end if;
  select coalesce(sum(pg_catalog.octet_length(body)), 0) into v_n from public.bridge_messages
   where from_agent = v_me and created_at > now() - interval '1 day';
  if v_n + coalesce(pg_catalog.octet_length(p_body), 0) > v_cfg.max_bytes_per_day then
    raise exception 'Daily limit: at most % bytes of messages per agent per day.', v_cfg.max_bytes_per_day using errcode = 'P0001';
  end if;

  if p_thread_id is null then
    v_thread := pg_catalog.gen_random_uuid();
    v_hop := 1;
    v_max := least(greatest(coalesce(p_max_hops, 20), 1), 100);  -- hard server cap: 100
  else
    v_thread := p_thread_id;
    -- serialize sends within one thread so hop numbers stay unique under concurrency
    perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(v_thread::text, 0));
    if not exists (select 1 from public.bridge_messages
                    where thread_id = v_thread and (from_agent = v_me or to_agent = v_me)) then
      raise exception 'Unknown thread_id %. Omit it to start a new thread.', v_thread using errcode = 'P0001';
    end if;
    -- replies stay between the thread's participants (R1-02)
    if not exists (select 1 from public.bridge_messages
                    where thread_id = v_thread and (from_agent = p_to or to_agent = p_to)) then
      raise exception '"%" is not part of this thread. Start a new thread to include them.', p_to using errcode = 'P0001';
    end if;
    -- max(hop), not count(*): purged rows must not make a hop number repeat (R1-01);
    -- the cap is the one the thread started with, carried on every message (R1-10)
    select m.hop + 1, m.max_hops into v_hop, v_max
      from public.bridge_messages m where m.thread_id = v_thread order by m.hop desc limit 1;
  end if;

  if v_hop > v_max then
    raise exception 'Thread % hit the %-message limit (loop protection). Ask a human before continuing, or start a new thread with a summary.',
      v_thread, v_max using errcode = 'P0001';
  end if;

  insert into public.bridge_messages (thread_id, from_agent, to_agent, type, subject, body, hop, max_hops)
  values (v_thread, v_me, p_to, coalesce(p_type, 'request'), p_subject, p_body, v_hop, v_max)
  returning * into v_row;
  return pg_catalog.to_jsonb(v_row);
end $$;

-- Unread messages for the caller, oldest first, optionally only from one sender (R1-03).
-- When marking read, rows are claimed with FOR UPDATE SKIP LOCKED so two concurrent readers
-- never receive the same message.
drop function if exists public.bridge_inbox(text, int, boolean, uuid);
create or replace function public.bridge_inbox(
  p_token     text,
  p_limit     int     default 20,
  p_mark_read boolean default true,
  p_thread_id uuid    default null,
  p_from      text    default null
) returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  v_me    text := public.bridge_auth(p_token);
  v_limit int  := least(greatest(coalesce(p_limit, 20), 1), 100);
  v_out   jsonb;
begin
  if coalesce(p_mark_read, true) then
    with picked as (
      select id from public.bridge_messages
       where to_agent = v_me and read_at is null
         and (p_thread_id is null or thread_id = p_thread_id)
         and (p_from is null or from_agent = p_from)
       order by id limit v_limit
       for update skip locked
    ), upd as (
      update public.bridge_messages m set read_at = now()
        from picked where m.id = picked.id
      returning m.id, pg_catalog.to_jsonb(m) as j
    )
    select pg_catalog.jsonb_agg(upd.j order by upd.id) into v_out from upd;
  else
    select pg_catalog.jsonb_agg(pg_catalog.to_jsonb(m) order by m.id) into v_out
      from (select * from public.bridge_messages
             where to_agent = v_me and read_at is null
               and (p_thread_id is null or thread_id = p_thread_id)
               and (p_from is null or from_agent = p_from)
             order by id limit v_limit) m;
  end if;
  return coalesce(v_out, '[]'::jsonb);
end $$;

-- Puts messages back as unread when the caller couldn't deliver them (R1-05). Own mail only.
create or replace function public.bridge_unmark(p_token text, p_ids bigint[])
returns int language plpgsql security definer set search_path = '' as $$
declare
  v_me text := public.bridge_auth(p_token);
  v_n  int;
begin
  update public.bridge_messages set read_at = null
   where id = any (p_ids) and to_agent = v_me and read_at is not null;
  get diagnostics v_n = row_count;
  return v_n;
end $$;

create or replace function public.bridge_unread_summary(p_token text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_me text := public.bridge_auth(p_token);
begin
  return coalesce((
    select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('from_agent', s.from_agent, 'n', s.n) order by s.from_agent)
      from (select from_agent, count(*) as n from public.bridge_messages
             where to_agent = v_me and read_at is null group by from_agent) s), '[]'::jsonb);
end $$;

-- Full thread, only if the caller sent or received at least one message in it.
create or replace function public.bridge_thread(p_token text, p_thread_id uuid)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_me text := public.bridge_auth(p_token);
begin
  if not exists (select 1 from public.bridge_messages
                  where thread_id = p_thread_id and (from_agent = v_me or to_agent = v_me)) then
    raise exception 'Unknown thread_id %.', p_thread_id using errcode = 'P0001';
  end if;
  return (select pg_catalog.jsonb_agg(pg_catalog.to_jsonb(m) order by m.id)
            from public.bridge_messages m where m.thread_id = p_thread_id);
end $$;

-- Messages the caller sent or received. p_after_id > 0: everything newer than that id
-- (ascending, for tailing). Otherwise the latest p_limit messages.
create or replace function public.bridge_recent(p_token text, p_limit int default 20, p_after_id bigint default 0)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  v_me    text := public.bridge_auth(p_token);
  v_limit int  := least(greatest(coalesce(p_limit, 20), 1), 200);
begin
  if coalesce(p_after_id, 0) > 0 then
    return coalesce((select pg_catalog.jsonb_agg(pg_catalog.to_jsonb(m) order by m.id)
      from (select * from public.bridge_messages
             where id > p_after_id and (from_agent = v_me or to_agent = v_me)
             order by id limit v_limit) m), '[]'::jsonb);
  end if;
  return coalesce((select pg_catalog.jsonb_agg(pg_catalog.to_jsonb(m) order by m.id)
    from (select * from public.bridge_messages
           where from_agent = v_me or to_agent = v_me
           order by id desc limit v_limit) m), '[]'::jsonb);
end $$;

-- ---------------------------------------------------------------- admin API (service_role only)

create or replace function public.bridge_admin_create_agent(p_name text, p_description text default null)
returns text language plpgsql security definer set search_path = '' as $$
declare v_token text := public.bridge_new_token();
begin
  if exists (select 1 from public.bridge_agents where name = p_name) then
    raise exception 'Agent "%" already exists. Use bridge_admin_rotate_token to issue a new token.', p_name using errcode = 'P0001';
  end if;
  insert into public.bridge_agents (name, description, token_hash)
  values (p_name, p_description, public.bridge_hash_token(v_token));
  return v_token;
end $$;

-- Issues a new token (old one stops working) and un-revokes the agent.
create or replace function public.bridge_admin_rotate_token(p_name text)
returns text language plpgsql security definer set search_path = '' as $$
declare v_token text := public.bridge_new_token();
begin
  update public.bridge_agents set token_hash = public.bridge_hash_token(v_token), revoked_at = null
   where name = p_name;
  if not found then
    raise exception 'Unknown agent "%".', p_name using errcode = 'P0001';
  end if;
  return v_token;
end $$;

create or replace function public.bridge_admin_revoke_agent(p_name text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  update public.bridge_agents set revoked_at = now() where name = p_name;
  if not found then
    raise exception 'Unknown agent "%".', p_name using errcode = 'P0001';
  end if;
end $$;

-- Removes an agent and every message it sent or received.
create or replace function public.bridge_admin_delete_agent(p_name text)
returns bigint language plpgsql security definer set search_path = '' as $$
declare v_n bigint;
begin
  delete from public.bridge_messages where from_agent = p_name or to_agent = p_name;
  get diagnostics v_n = row_count;
  delete from public.bridge_agents where name = p_name;
  if not found then
    raise exception 'Unknown agent "%".', p_name using errcode = 'P0001';
  end if;
  return v_n;
end $$;

create or replace function public.bridge_admin_set_limits(
  p_rate_per_minute int default null, p_max_unread_per_sender int default null, p_max_bytes_per_day bigint default null)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_row public.bridge_settings;
begin
  update public.bridge_settings
     set rate_per_minute       = coalesce(p_rate_per_minute, rate_per_minute),
         max_unread_per_sender = coalesce(p_max_unread_per_sender, max_unread_per_sender),
         max_bytes_per_day     = coalesce(p_max_bytes_per_day, max_bytes_per_day)
   where id = 1
  returning * into v_row;
  return pg_catalog.to_jsonb(v_row) - 'id';
end $$;

create or replace function public.bridge_admin_purge(p_older_than interval default interval '30 days')
returns bigint language plpgsql security definer set search_path = '' as $$
declare v_n bigint;
begin
  delete from public.bridge_messages where created_at < now() - p_older_than;
  get diagnostics v_n = row_count;
  return v_n;
end $$;

-- ---------------------------------------------------------------- privileges
-- Postgres grants EXECUTE to PUBLIC by default and Supabase adds anon/authenticated via
-- default privileges, so revoke everything first, then grant exactly what each role needs.

do $$
declare f text;
begin
  for f in
    select p.oid::regprocedure::text
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public' and p.proname like 'bridge\_%'
  loop
    execute format('revoke all on function %s from public', f);
    if exists (select 1 from pg_roles where rolname = 'anon') then
      execute format('revoke all on function %s from anon, authenticated', f);
    end if;
  end loop;
end $$;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    grant execute on function
      public.bridge_whoami(text),
      public.bridge_heartbeat(text, text, text),
      public.bridge_list_agents(text),
      public.bridge_send(text, text, text, text, text, uuid, int),
      public.bridge_inbox(text, int, boolean, uuid, text),
      public.bridge_unmark(text, bigint[]),
      public.bridge_unread_summary(text),
      public.bridge_thread(text, uuid),
      public.bridge_recent(text, int, bigint)
    to anon, authenticated;
  end if;
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    grant execute on function
      public.bridge_whoami(text),
      public.bridge_heartbeat(text, text, text),
      public.bridge_list_agents(text),
      public.bridge_send(text, text, text, text, text, uuid, int),
      public.bridge_inbox(text, int, boolean, uuid, text),
      public.bridge_unmark(text, bigint[]),
      public.bridge_unread_summary(text),
      public.bridge_thread(text, uuid),
      public.bridge_recent(text, int, bigint),
      public.bridge_admin_set_limits(int, int, bigint),
      public.bridge_admin_create_agent(text, text),
      public.bridge_admin_rotate_token(text),
      public.bridge_admin_revoke_agent(text),
      public.bridge_admin_delete_agent(text),
      public.bridge_admin_purge(interval)
    to service_role;
  end if;
end $$;
