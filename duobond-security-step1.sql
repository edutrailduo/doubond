-- DuoBond security foundation (Step 1)
-- Additive only: does not delete or modify existing messages.
-- Run once in Supabase SQL Editor.

create table if not exists public.duo_devices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  device_label text not null default 'My device',
  public_key jsonb not null,
  key_fingerprint text not null,
  status text not null default 'pending'
    check (status in ('pending','approved','revoked')),
  created_at timestamptz not null default now(),
  approved_at timestamptz,
  last_seen_at timestamptz,
  revoked_at timestamptz
);

create index if not exists duo_devices_user_status_idx
  on public.duo_devices(user_id,status);

alter table public.duo_devices enable row level security;

drop policy if exists "Duo members can view device registry" on public.duo_devices;
create policy "Duo members can view device registry"
on public.duo_devices for select to authenticated
using (
  exists (select 1 from public.duo_members dm where dm.user_id = auth.uid())
);

drop policy if exists "Users register own devices" on public.duo_devices;
create policy "Users register own devices"
on public.duo_devices for insert to authenticated
with check (
  user_id = auth.uid()
  and status = 'pending'
  and exists (select 1 from public.duo_members dm where dm.user_id = auth.uid())
);

drop policy if exists "Users update own device heartbeat" on public.duo_devices;
create policy "Users update own device heartbeat"
on public.duo_devices for update to authenticated
using (user_id = auth.uid() and status <> 'revoked')
with check (user_id = auth.uid());

grant select, insert, update on public.duo_devices to authenticated;

alter table public.messages
  add column if not exists encrypted_payload jsonb,
  add column if not exists crypto_version integer,
  add column if not exists content_kind text not null default 'text'
    check (content_kind in ('text','photo'));

comment on table public.duo_devices is
  'DuoBond device public-key registry. Never store private keys here.';
comment on column public.messages.encrypted_payload is
  'Client-encrypted envelope only. Do not put plaintext in this column.';
