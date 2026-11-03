-- DuoBond: partner nickname editing + block controls
-- Run in Supabase SQL Editor after the earlier DuoBond migrations.

-- Allow either member to edit the other member's nickname.
drop policy if exists "Duo members can edit partner profile" on public.duo_profiles;
create policy "Duo members can edit partner profile"
on public.duo_profiles for update to authenticated
using (
  exists (select 1 from public.duo_members where user_id = auth.uid())
  and exists (select 1 from public.duo_members where user_id = duo_profiles.user_id)
)
with check (
  exists (select 1 from public.duo_members where user_id = auth.uid())
  and exists (select 1 from public.duo_members where user_id = duo_profiles.user_id)
);

-- Block list: each person can independently block or unblock the other.
create table if not exists public.duo_blocks (
  blocker_id uuid not null references auth.users(id) on delete cascade,
  blocked_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (blocker_id, blocked_id),
  constraint duo_blocks_no_self check (blocker_id <> blocked_id)
);

alter table public.duo_blocks enable row level security;

drop policy if exists "Users read own blocks" on public.duo_blocks;
create policy "Users read own blocks"
on public.duo_blocks for select to authenticated
using (blocker_id = auth.uid() or blocked_id = auth.uid());

drop policy if exists "Users create own blocks" on public.duo_blocks;
create policy "Users create own blocks"
on public.duo_blocks for insert to authenticated
with check (
  blocker_id = auth.uid()
  and exists (select 1 from public.duo_members where user_id = auth.uid())
  and exists (select 1 from public.duo_members where user_id = blocked_id)
);

drop policy if exists "Users remove own blocks" on public.duo_blocks;
create policy "Users remove own blocks"
on public.duo_blocks for delete to authenticated
using (blocker_id = auth.uid());

grant select, insert, delete on public.duo_blocks to authenticated;

-- Prevent new messages in either direction while either person has blocked the other.
create or replace function public.duobond_prevent_blocked_messages()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if exists (
    select 1 from public.duo_blocks b
    where (b.blocker_id = new.sender_id and b.blocked_id <> new.sender_id)
       or (b.blocked_id = new.sender_id and b.blocker_id <> new.sender_id)
  ) then
    raise exception 'Messaging is unavailable because this conversation is blocked.';
  end if;
  return new;
end;
$$;

drop trigger if exists duobond_block_message_insert on public.messages;
create trigger duobond_block_message_insert
before insert on public.messages
for each row execute function public.duobond_prevent_blocked_messages();
