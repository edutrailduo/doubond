-- DuoBond private photo messaging
alter table public.messages
  add column if not exists media_path text,
  add column if not exists media_mime text,
  add column if not exists media_name text;

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'duobond-media',
  'duobond-media',
  false,
  10485760,
  array['image/jpeg','image/png','image/webp','image/gif','image/heic','image/heif']
)
on conflict (id) do update set
  public = false,
  file_size_limit = 10485760,
  allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "DuoBond members can view photos" on storage.objects;
create policy "DuoBond members can view photos"
on storage.objects for select to authenticated
using (
  bucket_id = 'duobond-media'
  and exists (select 1 from public.duo_members dm where dm.user_id = auth.uid())
);

drop policy if exists "DuoBond members can upload photos" on storage.objects;
create policy "DuoBond members can upload photos"
on storage.objects for insert to authenticated
with check (
  bucket_id = 'duobond-media'
  and (storage.foldername(name))[1] = auth.uid()::text
  and exists (select 1 from public.duo_members dm where dm.user_id = auth.uid())
);

drop policy if exists "DuoBond members can delete own uploaded photos" on storage.objects;
create policy "DuoBond members can delete own uploaded photos"
on storage.objects for delete to authenticated
using (
  bucket_id = 'duobond-media'
  and (storage.foldername(name))[1] = auth.uid()::text
  and exists (select 1 from public.duo_members dm where dm.user_id = auth.uid())
);
