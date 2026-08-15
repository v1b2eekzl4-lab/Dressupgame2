-- Public bucket for forum videos and other persistent uploads.
-- The server also creates this on first upload if it is missing.

insert into storage.buckets (id, name, public, file_size_limit)
values ('assets', 'assets', true, 52428800)
on conflict (id) do update
set public = excluded.public,
    file_size_limit = excluded.file_size_limit;

drop policy if exists "Public read assets" on storage.objects;
create policy "Public read assets"
on storage.objects
for select
to public
using (bucket_id = 'assets');
