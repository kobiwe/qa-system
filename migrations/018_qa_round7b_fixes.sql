-- QA round 7b (second NO-GO on 016/017). Findings closed here:
--
-- N-01  profiles.signature_url could contain `..` (is_storage_pointer allowed dots) and so pointed, after path normalisation, at a
--       colleague's signature file; guard_profile_signature only checked that the string contained the user's folder.
-- N-02  stored XSS through names that are rendered all over the UI: the UI is escaped (index.html) AND the database now refuses
--       `<` / `>` in the structural / name fields (defence in depth — `NOT VALID`: existing rows are not re-checked).
-- N-03  findings.signature_url was client-chosen: any member could close a finding with a colleague's signature.
-- N-04  a second member could not replace a checklist document (UI showed a generic error): documents now get a unique name per upload.
-- N-05  an owner could overwrite / delete a signature file that was already stamped on records: signature files are write-once.

-- ── N-01 ─────────────────────────────────────────────────────────────────────────────────────
create or replace function public.is_storage_pointer(u text)
returns boolean language sql immutable as $$
  select u is null or (char_length(u) <= 600
    and u ~ '^https://[a-z0-9]+\.supabase\.co/storage/v1/object/public/documents/[A-Za-z0-9_./-]+$'
    and position('..' in u) = 0
    and position('//' in substring(u from 9)) = 0)
$$;

-- a signature is exactly  …/documents/signatures/<owner id>/<file>.<ext>   (no traversal, no extra segments)
create or replace function public.is_signature_pointer_of(u text, owner uuid)
returns boolean language sql immutable as $$
  select u is not null and u ~ ('^https://[a-z0-9]+\.supabase\.co/storage/v1/object/public/documents/signatures/' || owner::text || '/[A-Za-z0-9_-]+\.[A-Za-z0-9]+$')
$$;
grant execute on function public.is_signature_pointer_of(text, uuid) to authenticated, service_role;

create or replace function public.guard_profile_signature() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or new.signature_url is null then return new; end if;
  if tg_op = 'UPDATE' and new.signature_url is not distinct from old.signature_url then return new; end if;
  if not public.is_signature_pointer_of(new.signature_url, new.id) then
    raise exception 'a signature must be a file under your own signatures folder' using errcode = '42501';
  end if;
  return new;
end $$;

-- ── N-03: a finding is closed with the CLOSER's own signature ───────────────────────────────────
create or replace function public.guard_finding_row() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return new; end if;
  if tg_op = 'INSERT' then new.created_by := auth.uid(); else new.created_by := old.created_by; end if;
  if new.signature_url is not null and (tg_op = 'INSERT' or new.signature_url is distinct from old.signature_url)
     and not public.is_signature_pointer_of(new.signature_url, auth.uid()) then
    raise exception 'a finding can only be signed with your own signature' using errcode = '42501';
  end if;
  return new;
end $$;

-- ── N-04 / N-05: storage names ───────────────────────────────────────────────────────────────────
-- checklist documents: checklist-docs/<company>/<row id>[_<suffix>].<ext>  (the row id is the part before '_' / '.')
create or replace function public.storage_can_access(obj_name text)
returns boolean language sql stable set search_path = public as $$
  select auth.uid() is not null and (
    is_system_admin()
    or case split_part(obj_name, '/', 1)
      when 'company-logos'    then split_part(split_part(obj_name, '/', 2), '.', 1) = get_company_id()::text
      when 'signatures'       then exists (select 1 from public.profiles pr where pr.id::text = split_part(split_part(obj_name, '/', 2), '.', 1))
      when 'checklist-docs'   then split_part(obj_name, '/', 2) = get_company_id()::text
                                   and exists (select 1 from public.checklist_instances ci
                                               where ci.id::text = split_part(split_part(split_part(obj_name, '/', 3), '.', 1), '_', 1))
      when 'project-files'    then exists (select 1 from public.projects p where p.id::text = split_part(obj_name, '/', 2))
      when 'findings'         then exists (select 1 from public.findings f where f.id::text = split_part(obj_name, '/', 2))
      when 'precontrol'       then exists (select 1 from public.precontrol_forms f where f.id::text = split_part(obj_name, '/', 2))
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

create or replace function public.storage_can_modify(obj_name text, obj_owner text)
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce(case split_part(obj_name, '/', 1)
    when 'signatures' then false   -- write-once: a signature file that may already be stamped on records is never replaced or deleted from a client
    when 'project-files' then (
         split_part(obj_name, '/', 2) ~ '^[0-9a-fA-F-]{36}$' and split_part(obj_name, '/', 3) ~ '^[0-9a-fA-F-]{36}$'
         and (is_system_admin()
              or (obj_owner = auth.uid()::text and not public.folder_root_is_plans(split_part(obj_name, '/', 3)::uuid))
              or public.can_manage_project(split_part(obj_name, '/', 2)::uuid)
              or (public.folder_root_is_plans(split_part(obj_name, '/', 3)::uuid) and public.can_upload_plans(split_part(obj_name, '/', 2)::uuid))))
    when 'checklist-docs' then (
         is_system_admin() or obj_owner = auth.uid()::text
         or public.can_manage_work_item((select ci.work_item_id from public.checklist_instances ci
                                         where ci.id::text = split_part(split_part(split_part(obj_name, '/', 3), '.', 1), '_', 1))))
    else true end, false)
$$;

-- ── N-02: no markup characters in names ──────────────────────────────────────────────────────────
do $$
declare c record;
begin
  for c in select * from (values
    ('projects', 'name'), ('companies', 'name'), ('profiles', 'full_name'), ('folders', 'name'), ('contractors', 'name'),
    ('work_items', 'sub_project'), ('work_items', 'structure'), ('work_items', 'sub_structure'), ('work_items', 'element'),
    ('work_items', 'sub_element'), ('work_items', 'execution_type'), ('checklist_templates', 'type_name'),
    ('work_item_checklists', 'label'), ('checklist_type_config', 'type_name')) as t(tbl, col)
  loop
    if not exists (select 1 from pg_constraint where conname = c.tbl || '_' || c.col || '_nomarkup_chk') then
      execute format('alter table public.%I add constraint %I check (%I is null or %I !~ ''[<>]'') not valid',
                     c.tbl, c.tbl || '_' || c.col || '_nomarkup_chk', c.col, c.col);
    end if;
  end loop;
end $$;

notify pgrst, 'reload schema';
