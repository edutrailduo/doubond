-- DuoBond communication upgrades: presence, reply threads, voice notes, and call signaling.
-- Safe additive migration: preserves existing messages and files.
begin;

create table if not exists public.duo_presence (
  user_id uuid primary key references auth.users(id) on delete cascade,
  last_seen_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.duo_presence enable row level security;
drop policy if exists "Duo members read presence" on public.duo_presence;
create policy "Duo members read presence" on public.duo_presence
for select to authenticated
using (
  exists (select 1 from public.duo_members where user_id = auth.uid())
);
drop policy if exists "Users update own presence" on public.duo_presence;
create policy "Users update own presence" on public.duo_presence
for insert to authenticated
with check (
  user_id = auth.uid()
  and exists (select 1 from public.duo_members where user_id = auth.uid())
);
drop policy if exists "Users refresh own presence" on public.duo_presence;
create policy "Users refresh own presence" on public.duo_presence
for update to authenticated
using (user_id = auth.uid())
with check (user_id = auth.uid());
grant select, insert, update on public.duo_presence to authenticated;

alter table public.messages
  add column if not exists reply_to bigint references public.messages(id) on delete set null;

-- Extend the existing private bucket to accept voice notes as well as images.
update storage.buckets
set file_size_limit = 20971520,
    allowed_mime_types = array[
      'image/jpeg','image/png','image/webp','image/gif','image/heic','image/heif',
      'audio/webm','audio/ogg','audio/mp4','audio/mpeg','audio/aac','audio/wav'
    ]
where id = 'duobond-media';

-- Ensure call signaling is available for one-to-one WebRTC audio/video calls.
create table if not exists public.call_signals (
  id bigint generated always as identity primary key,
  sender_id uuid not null references auth.users(id) on delete cascade,
  recipient_id uuid not null references auth.users(id) on delete cascade,
  payload jsonb not null,
  created_at timestamptz not null default now()
);
alter table public.call_signals enable row level security;
drop policy if exists "Call participants read signals" on public.call_signals;
create policy "Call participants read signals" on public.call_signals
for select to authenticated using (sender_id = auth.uid() or recipient_id = auth.uid());
drop policy if exists "Call sender inserts signals" on public.call_signals;
create policy "Call sender inserts signals" on public.call_signals
for insert to authenticated
with check (
  sender_id = auth.uid()
  and exists (select 1 from public.duo_members where user_id = auth.uid())
  and exists (select 1 from public.duo_members where user_id = recipient_id)
  and recipient_id <> auth.uid()
);
grant select, insert on public.call_signals to authenticated;

do $$ begin
  alter publication supabase_realtime add table public.call_signals;
exception when duplicate_object then null; when undefined_object then null; end $$;

commit;
