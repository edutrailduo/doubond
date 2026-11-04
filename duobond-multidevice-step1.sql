-- DuoBond multi-device security foundation (Step 1)
-- Safe, additive migration. Does NOT change or delete existing messages.
-- Run once in Supabase SQL Editor. Client-side cryptographic approval is added in a later step.

begin;

create table if not exists public.duo_devices (
  device_id uuid primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  device_label text not null default 'My device'
    check (char_length(device_label) between 1 and 60),
  public_key jsonb not null,
  key_fingerprint text not null,
  status text not null default 'pending'
    check (status in ('pending', 'approved', 'revoked')),
  created_at timestamptz not null default now(),
  last_seen_at timestamptz,
  approved_at timestamptz,
  approved_by_device_id uuid,
  revoked_at timestamptz,
  constraint duo_devices_approval_state check (
    (status = 'pending' and approved_at is null and revoked_at is null)
    or (status = 'approved' and approved_at is not null and revoked_at is null)
    or (status = 'revoked' and revoked_at is not null)
  )
);

create index if not exists duo_devices_user_status_idx
  on public.duo_devices(user_id, status);

alter table public.duo_devices enable row level security;

drop policy if exists "Device owner and partner read approved device keys" on public.duo_devices;
create policy "Device owner and partner read approved device keys"
on public.duo_devices for select to authenticated
using (
  user_id = auth.uid()
  or (
    status = 'approved'
    and exists (select 1 from public.duo_members mine where mine.user_id = auth.uid())
    and exists (select 1 from public.duo_members partner where partner.user_id = duo_devices.user_id)
  )
);

drop policy if exists "Users register own pending devices" on public.duo_devices;
create policy "Users register own pending devices"
on public.duo_devices for insert to authenticated
with check (
  user_id = auth.uid()
  and status = 'pending'
  and approved_at is null
  and approved_by_device_id is null
  and revoked_at is null
  and exists (select 1 from public.duo_members mine where mine.user_id = auth.uid())
);

-- Intentionally no client UPDATE or DELETE policy:
-- a client must not be able to approve itself or erase audit history.
-- A later migration will add a narrowly scoped approval/revocation flow.

grant select, insert on public.duo_devices to authenticated;

create table if not exists public.duo_recovery_backups (
  user_id uuid primary key references auth.users(id) on delete cascade,
  kdf_name text not null check (kdf_name in ('PBKDF2-SHA-256')),
  kdf_iterations integer not null check (kdf_iterations >= 600000),
  salt_b64 text not null,
  encrypted_key_bundle text not null,
  updated_at timestamptz not null default now()
);

alter table public.duo_recovery_backups enable row level security;

drop policy if exists "Users manage own encrypted recovery backup" on public.duo_recovery_backups;
create policy "Users manage own encrypted recovery backup"
on public.duo_recovery_backups for all to authenticated
using (
  user_id = auth.uid()
  and exists (select 1 from public.duo_members mine where mine.user_id = auth.uid())
)
with check (
  user_id = auth.uid()
  and exists (select 1 from public.duo_members mine where mine.user_id = auth.uid())
);

grant select, insert, update, delete on public.duo_recovery_backups to authenticated;

do $$
begin
  alter publication supabase_realtime add table public.duo_devices;
exception when duplicate_object then null;
end $$;

commit;
