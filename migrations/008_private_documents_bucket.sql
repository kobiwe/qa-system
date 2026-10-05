-- Make the `documents` bucket private and replace the permissive storage policies with tenant-aware ones.
--
-- Access rule: an authenticated user may read/write/delete an object only if the object belongs to something
-- that user can already see through table RLS (their company's finding, project, inspection order, ...).
-- The helper below is SECURITY INVOKER on purpose: the EXISTS sub-queries run under the caller's RLS,
-- so company isolation is inherited from the tables instead of being re-implemented here.
--
-- Path conventions (see index.html):
--   company-logos/<company_id>.<ext>            signatures/<user_id>.<ext>
--   checklist-docs/<company_id>/<instance>.<ext>
--   project-files/<project_id>/<folder_id>/<key>
--   findings/<finding_id>/<file>
--   inspection-orders/order_<last 6 hex of order id>.pdf
--   certificates/cert_<order>_<ts>.pdf          (uploaded anonymously by the lab; linked via inspection_orders.certificate_url)
--
-- Rows in the DB keep storing the legacy ".../object/public/documents/<path>" string as an opaque pointer; the client
-- extracts the path and asks for a signed URL.

-- NOTE: the parameter is obj_name, not name: inside the EXISTS sub-queries a bare `name` resolves to a table column
-- (projects.name) instead of the function argument.
drop function if exists public.storage_can_write(text) cascade;
drop function if exists public.storage_can_access(text) cascade;
create function public.storage_can_access(obj_name text)
returns boolean
language sql
stable
security invoker
set search_path = public
as $$
  select auth.uid() is not null and (
    is_system_admin()
    or case split_part(obj_name, '/', 1)
      when 'company-logos'    then split_part(split_part(obj_name, '/', 2), '.', 1) = get_company_id()::text
      -- a signature is stamped on records other people read, so anyone who can see the owner's profile (same company) may read it
      when 'signatures'       then exists (select 1 from public.profiles pr where pr.id::text = split_part(split_part(obj_name, '/', 2), '.', 1))
      when 'checklist-docs'   then split_part(obj_name, '/', 2) = get_company_id()::text
      when 'project-files'    then exists (select 1 from public.projects p where p.id::text = split_part(obj_name, '/', 2))
      when 'findings'         then exists (select 1 from public.findings f where f.id::text = split_part(obj_name, '/', 2))
      when 'inspection-orders' then exists (
        select 1 from public.inspection_orders o
        where upper(right(o.id::text, 6)) = upper(substring(obj_name from 'order_([0-9A-Fa-f]{6})\.pdf$')))
      when 'certificates'     then exists (
        select 1 from public.inspection_orders o
        where o.certificate_url is not null and right(o.certificate_url, length(obj_name)) = obj_name)
      else false
    end
  )
$$;
grant execute on function public.storage_can_access(text) to authenticated;

-- writing is stricter than reading in one case: signature files may only be added/replaced/deleted by their owner
-- or by an admin of the same company (admins upload signatures on behalf of users from the users screen)
create function public.storage_can_write(obj_name text)
returns boolean
language sql
stable
security invoker
set search_path = public
as $$
  select public.storage_can_access(obj_name)
     and (split_part(obj_name, '/', 1) <> 'signatures'
          or split_part(split_part(obj_name, '/', 2), '.', 1) = auth.uid()::text
          or is_system_admin()
          or exists (
            select 1
            from public.profiles me
            join public.profiles tgt on tgt.id::text = split_part(split_part(obj_name, '/', 2), '.', 1)
            where me.id = auth.uid() and me.role = 'admin' and tgt.company_id = me.company_id))
$$;
grant execute on function public.storage_can_write(text) to authenticated;

-- old permissive policies
drop policy if exists allow_public_read   on storage.objects;
drop policy if exists allow_auth_upload   on storage.objects;
drop policy if exists allow_auth_update   on storage.objects;
drop policy if exists anon_cert_read      on storage.objects;
drop policy if exists storage_logos_read  on storage.objects;
drop policy if exists storage_logos_upload on storage.objects;

-- new policies (authenticated)
drop policy if exists documents_select on storage.objects;
create policy documents_select on storage.objects for select to authenticated
  using (bucket_id = 'documents' and public.storage_can_access(name));
drop policy if exists documents_insert on storage.objects;
create policy documents_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'documents' and public.storage_can_write(name));
drop policy if exists documents_update on storage.objects;
create policy documents_update on storage.objects for update to authenticated
  using (bucket_id = 'documents' and public.storage_can_write(name))
  with check (bucket_id = 'documents' and public.storage_can_write(name));
drop policy if exists documents_delete on storage.objects;
create policy documents_delete on storage.objects for delete to authenticated
  using (bucket_id = 'documents' and public.storage_can_write(name));

-- anon_cert_upload (lab upload without login) is intentionally kept: insert-only, certificates/ prefix.

update storage.buckets set public = false where id = 'documents';
