-- DuoBond security foundation — Step 1 (safe additive schema)
-- Does NOT delete messages, change current chat behaviour, or enable E2EE yet.
-- Private keys must NEVER be uploaded to Supabase.

begin;

create table if not exists public.duo_devices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  device_label text not null default 'My device',
  public_key jsonb not null,
  signing_public_key jsonb not null,
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
using (exists (
  select 1 from public.duo_members dm where dm.user_id = auth.uid()
));

drop policy if exists "Users register own devices" on public.duo_devices;
create policy "Users register own devices"
on public.duo_devices for insert to authenticated
with check (
  user_id = auth.uid()
  and status = 'pending'
  and approved_at is null
  and revoked_at is null
  and exists (select 1 from public.duo_members dm where dm.user_id = auth.uid())
);

-- Intentionally NO client UPDATE or DELETE policy.
-- Approval/revocation will be implemented with cryptographically verified
-- device-to-device authorization in a later step. A device cannot approve itself.

grant select, insert on public.duo_devices to authenticated;

alter table public.messages
  add column if not exists encrypted_payload jsonb,
  add column if not exists crypto_version integer,
  add column if not exists content_kind text not null default 'text'
    check (content_kind in ('text','photo'));

comment on table public.duo_devices is
  'Public device registry only. Private keys must remain on their device.';
comment on column public.messages.encrypted_payload is
  'Reserved for client-encrypted envelopes; do not use until E2EE client rollout.';
comment on column public.messages.content_kind is
  'Message payload type. Existing messages default to text.';

commit;
