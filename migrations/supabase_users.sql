-- Supabase tables (manual migration; run once in Supabase SQL)
create extension if not exists "uuid-ossp";
create extension if not exists "pgcrypto";

-- Primary user store
create table if not exists public.service_users (
  id uuid primary key default gen_random_uuid(),
  su text not null unique,
  tin text not null,
  plain_sp text not null default '',
  status text not null default 'pending', -- approved | pending | denied
  blocked_until timestamptz null,
  company_name text not null default '',
  notes text null,
  last_login_at timestamptz null,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

create index if not exists service_users_su_idx on public.service_users (su);
create index if not exists service_users_status_idx on public.service_users (status);

-- Login approval queue
create table if not exists public.login_requests (
  id uuid primary key default gen_random_uuid(),
  su text not null,
  tin text not null,
  plain_sp text not null,
  status text not null default 'pending', -- pending | approved | denied
  created_at timestamptz default now(),
  decided_at timestamptz null,
  decided_by text null,
  reason text null,
  ip text null,
  user_agent text null
);

create index if not exists login_requests_status_idx on public.login_requests (status);
create index if not exists login_requests_created_idx on public.login_requests (created_at);
