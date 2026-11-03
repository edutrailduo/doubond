-- DuoBond social features: nicknames, love reactions, and WebRTC call signaling
create table if not exists public.duo_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  nickname text not null default '',
  updated_at timestamptz not null default now(),
  constraint nickname_length check (char_length(nickname) between 1 and 30)
);
alter table public.duo_profiles enable row level security;
drop policy if exists "Duo members can read profiles" on public.duo_profiles;
create policy "Duo members can read profiles" on public.duo_profiles for select to authenticated
using (exists(select 1 from public.duo_members where user_id=auth.uid()) and exists(select 1 from public.duo_members where user_id=duo_profiles.user_id));
drop policy if exists "Users manage own profile" on public.duo_profiles;
create policy "Users manage own profile" on public.duo_profiles for all to authenticated
using (user_id=auth.uid()) with check (user_id=auth.uid());
grant select,insert,update,delete on public.duo_profiles to authenticated;

create table if not exists public.message_reactions (
  message_id bigint not null references public.messages(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  reaction text not null default '❤️' check (reaction='❤️'),
  created_at timestamptz not null default now(),
  primary key(message_id,user_id)
);
alter table public.message_reactions enable row level security;
drop policy if exists "Duo members read reactions" on public.message_reactions;
create policy "Duo members read reactions" on public.message_reactions for select to authenticated
using (exists(select 1 from public.duo_members where user_id=auth.uid()));
drop policy if exists "Users manage own reactions" on public.message_reactions;
create policy "Users manage own reactions" on public.message_reactions for all to authenticated
using (user_id=auth.uid() and exists(select 1 from public.duo_members where user_id=auth.uid()))
with check (user_id=auth.uid() and exists(select 1 from public.duo_members where user_id=auth.uid()));
grant select,insert,update,delete on public.message_reactions to authenticated;

create table if not exists public.call_signals (
  id bigint generated always as identity primary key,
  sender_id uuid not null references auth.users(id) on delete cascade,
  recipient_id uuid not null references auth.users(id) on delete cascade,
  payload jsonb not null,
  created_at timestamptz not null default now()
);
alter table public.call_signals enable row level security;
drop policy if exists "Call participants read signals" on public.call_signals;
create policy "Call participants read signals" on public.call_signals for select to authenticated
using (sender_id=auth.uid() or recipient_id=auth.uid());
drop policy if exists "Call sender inserts signals" on public.call_signals;
create policy "Call sender inserts signals" on public.call_signals for insert to authenticated
with check (sender_id=auth.uid() and exists(select 1 from public.duo_members where user_id=recipient_id));
grant select,insert on public.call_signals to authenticated;

do $$ begin
 alter publication supabase_realtime add table public.message_reactions;
exception when duplicate_object then null; when undefined_object then null; end $$;
do $$ begin
 alter publication supabase_realtime add table public.call_signals;
exception when duplicate_object then null; when undefined_object then null; end $$;
