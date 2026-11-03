-- DuoBond E2EE + delivery/read receipts migration
-- Run once in Supabase Dashboard -> SQL Editor -> New query.
-- This preserves existing messages. Old body values remain readable plaintext.

begin;

-- Allow encrypted envelopes (base64 + metadata) in messages.body.
do $$
declare c record;
begin
  for c in
    select conname
    from pg_constraint
    where conrelid = 'public.messages'::regclass
      and contype = 'c'
      and pg_get_constraintdef(oid) ilike '%body%'
  loop
    execute format('alter table public.messages drop constraint %I', c.conname);
  end loop;
end $$;

alter table public.messages
  add constraint messages_body_length_check
  check (char_length(body) between 1 and 20000);

-- One public key per approved account. Private keys never go into this table.
create table if not exists public.duo_device_keys (
  user_id uuid primary key references auth.users(id) on delete cascade,
  public_key text not null,
  fingerprint text not null,
  updated_at timestamptz not null default now()
);

alter table public.duo_device_keys enable row level security;

drop policy if exists "Duo members can read device public keys" on public.duo_device_keys;
create policy "Duo members can read device public keys"
on public.duo_device_keys for select to authenticated
using (
  exists (select 1 from public.duo_members me where me.user_id = auth.uid())
);

drop policy if exists "Members manage own device public key" on public.duo_device_keys;
create policy "Members manage own device public key"
on public.duo_device_keys for insert to authenticated
with check (
  user_id = auth.uid()
  and exists (select 1 from public.duo_members me where me.user_id = auth.uid())
);

drop policy if exists "Members update own device public key" on public.duo_device_keys;
create policy "Members update own device public key"
on public.duo_device_keys for update to authenticated
using (user_id = auth.uid())
with check (
  user_id = auth.uid()
  and exists (select 1 from public.duo_members me where me.user_id = auth.uid())
);

drop policy if exists "Members delete own device public key" on public.duo_device_keys;
create policy "Members delete own device public key"
on public.duo_device_keys for delete to authenticated
using (user_id = auth.uid());

grant select, insert, update, delete on public.duo_device_keys to authenticated;

-- A recipient-owned receipt row for each message they receive.
create table if not exists public.message_receipts (
  message_id bigint not null references public.messages(id) on delete cascade,
  recipient_id uuid not null references auth.users(id) on delete cascade,
  delivered_at timestamptz,
  seen_at timestamptz,
  primary key (message_id, recipient_id),
  constraint seen_requires_delivery check (seen_at is null or delivered_at is not null)
);

alter table public.message_receipts enable row level security;

drop policy if exists "Participants can read relevant receipts" on public.message_receipts;
create policy "Participants can read relevant receipts"
on public.message_receipts for select to authenticated
using (
  recipient_id = auth.uid()
  or exists (
    select 1 from public.messages m
    where m.id = message_id and m.sender_id = auth.uid()
  )
);

drop policy if exists "Recipient creates own receipt" on public.message_receipts;
create policy "Recipient creates own receipt"
on public.message_receipts for insert to authenticated
with check (
  recipient_id = auth.uid()
  and exists (
    select 1 from public.messages m
    where m.id = message_id and m.sender_id <> auth.uid()
  )
  and exists (select 1 from public.duo_members me where me.user_id = auth.uid())
);

drop policy if exists "Recipient updates own receipt" on public.message_receipts;
create policy "Recipient updates own receipt"
on public.message_receipts for update to authenticated
using (recipient_id = auth.uid())
with check (
  recipient_id = auth.uid()
  and exists (
    select 1 from public.messages m
    where m.id = message_id and m.sender_id <> auth.uid()
  )
);

grant select, insert, update on public.message_receipts to authenticated;

-- Enable realtime events for new public-key and receipt rows.
do $$
begin
  alter publication supabase_realtime add table public.duo_device_keys;
exception when duplicate_object then null;
end $$;

do $$
begin
  alter publication supabase_realtime add table public.message_receipts;
exception when duplicate_object then null;
end $$;

commit;
