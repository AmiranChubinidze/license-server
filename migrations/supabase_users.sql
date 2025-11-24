-- Supabase users table (manual migration; do NOT auto-run from the app)
create extension if not exists "uuid-ossp";
create extension if not exists "pgcrypto";

create table if not exists public.users (
  id uuid primary key default gen_random_uuid(),
  su text not null unique,
  sp text not null default '',
  company_name text not null default '',
  tin text not null,
  active boolean not null default true,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

create index if not exists users_su_idx on public.users (su);
