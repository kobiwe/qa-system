-- Security hotfix from QA round 2 (2026-10-08). Each part closes a hole confirmed by the QA agent (and, for A and C, on production).
--
-- A) submit_lab_certificate (callable by anyone with the public key) accepted any certificate string for any order of any
--    company, overwrote existing certificates and stored javascript: URLs. It now validates the pointer shape, requires the
--    uploaded file to exist, refuses ambiguous order numbers and never overwrites a certificate that was already submitted.
-- B) File pointers stored in the database must be storage URLs of this kind — nothing else (no javascript:, no other host).
-- C) projects_write was a FOR ALL policy for every user of the company: any user could rename or DELETE any project
--    (with all its data). Reading stays company-wide (as before); writes require the right role.

-- ── A) lab RPC ───────────────────────────────────────────────────────────────
create or replace function public.submit_lab_certificate(p_order_short_id text, p_cert_url text)
returns json language plpgsql security definer set search_path = public as $$
declare v_short text := upper(trim(coalesce(p_order_short_id, ''))); v_ids uuid[]; v_path text;
begin
  if v_short !~ '^[0-9A-F]{6}$' then
    return json_build_object('success', false, 'error', 'invalid_order');
  end if;
  if p_cert_url is null or p_cert_url !~ ('^https://[a-z0-9]+\.supabase\.co/storage/v1/object/public/documents/certificates/cert_' || v_short || '_[0-9]{10,14}\.pdf$') then
    return json_build_object('success', false, 'error', 'invalid_file');
  end if;
  v_path := substring(p_cert_url from '/documents/(certificates/.+)$');
  if not exists (select 1 from storage.objects where bucket_id = 'documents' and name = v_path) then
    return json_build_object('success', false, 'error', 'file_not_found');
  end if;
  select array_agg(id) into v_ids from public.inspection_orders where upper(right(id::text, 6)) = v_short;
  if v_ids is null then return json_build_object('success', false, 'error', 'order_not_found'); end if;
  if array_length(v_ids, 1) > 1 then return json_build_object('success', false, 'error', 'ambiguous_order'); end if;
  update public.inspection_orders set certificate_url = p_cert_url, status = 'completed'
   where id = v_ids[1] and certificate_url is null;
  if not found then return json_build_object('success', false, 'error', 'already_submitted'); end if;
  return json_build_object('success', true, 'order_id', v_ids[1]::text);
end $$;
grant execute on function public.submit_lab_certificate(text, text) to anon, authenticated;

-- ── B) storage pointer format ────────────────────────────────────────────────
create or replace function public.is_storage_pointer(u text)
returns boolean language sql immutable as $$
  select u is null or (char_length(u) <= 600
    and u ~ '^https://[a-z0-9]+\.supabase\.co/storage/v1/object/public/documents/[A-Za-z0-9_./-]+$')
$$;

do $$
declare c record;
begin
  for c in select * from (values
    ('finding_attachments', 'url'), ('project_files', 'url'), ('inspection_orders', 'pdf_url'), ('inspection_orders', 'certificate_url'),
    ('companies', 'logo_url'), ('checklist_instances', 'document_url'), ('checklist_instances', 'signature_url'),
    ('findings', 'signature_url'), ('profiles', 'signature_url'), ('precontrol_files', 'url')) as t(tbl, col)
  loop
    if to_regclass('public.' || c.tbl) is not null
       and not exists (select 1 from pg_constraint where conname = c.tbl || '_' || c.col || '_pointer_chk') then
      execute format('alter table public.%I add constraint %I check (public.is_storage_pointer(%I))', c.tbl, c.tbl || '_' || c.col || '_pointer_chk', c.col);
    end if;
  end loop;
end $$;

-- ── C) projects: company-wide read (unchanged behaviour), role-restricted writes ─────────────────
create or replace function public.my_role()
returns text language sql stable security definer set search_path = public as $$
  select role from public.profiles where id = auth.uid()
$$;
grant execute on function public.my_role() to authenticated;

drop policy if exists projects_write on public.projects;
drop policy if exists projects_company_read on public.projects;
create policy projects_company_read on public.projects for select to authenticated
  using (company_id = get_company_id() or is_system_admin());
drop policy if exists projects_insert on public.projects;
create policy projects_insert on public.projects for insert to authenticated
  with check (is_system_admin() or (company_id = get_company_id() and public.my_role() in ('admin', 'manager')));
drop policy if exists projects_update on public.projects;
create policy projects_update on public.projects for update to authenticated
  using (is_system_admin() or (company_id = get_company_id() and public.my_role() in ('admin', 'manager')))
  with check (is_system_admin() or (company_id = get_company_id() and public.my_role() in ('admin', 'manager')));
drop policy if exists projects_delete on public.projects;
create policy projects_delete on public.projects for delete to authenticated
  using (is_system_admin() or (company_id = get_company_id() and public.my_role() = 'admin'));
