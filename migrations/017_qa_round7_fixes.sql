-- QA round 7 fixes for migration 016 (report 7.11.2026). Each block names the finding it closes.
--
-- D-01  a signed-in user WITHOUT a profile (anyone can self-register through auth/v1/signup) got NULL from is_system_admin() /
--       can_access_project(), and `if not NULL` does not raise in plpgsql → the SECURITY DEFINER RPCs ran for any company.
-- D-02  a member could change work_items.execution_type (dropping the type-level signer requirement) and then sign.
-- D-03  projects.company_id could be changed by the project's manager / company admin (project moved to another company).
-- D-04  projects.created_by / created_at could be forged (creator back door).
-- D-05  project_id could be reset to NULL on findings / orders, which makes the row visible to the whole company.
-- D-06  profiles.signature_url could point at somebody else's signature file.
-- D-07  storage: a project member could delete / overwrite plans and colleagues' files directly through the Storage API.
-- D-10  findings.created_by could be forged (and then used to delete other people's findings).
-- D-11  task_name / task_order / list_no of a checklist row could be rewritten by any member.
-- D-12  user_requests.requested_by_name / created_at editable by the deciding admin.
-- D-13  sub-folders / files could be created under an archived folder.

-- ── D-01 ─────────────────────────────────────────────────────────────────────────────────────
create or replace function public.is_system_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select system_admin from public.profiles where id = auth.uid()), false)
$$;

create or replace function public.can_approve_precontrol() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(auth.uid() is not null and (
    is_system_admin()
    or exists (select 1 from public.profiles me where me.id = auth.uid() and (me.role = 'admin' or me.signer_role = 'qa_assurance'))), false)
$$;

create or replace function public.can_access_project(p uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(auth.uid() is not null and p is not null and (
    is_system_admin()
    or exists (
      select 1 from public.projects pr join public.profiles me on me.id = auth.uid()
      where pr.id = p and pr.company_id = me.company_id
        and (me.role = 'admin'
             or exists (select 1 from public.project_members m where m.project_id = pr.id and m.user_id = me.id)))), false)
$$;

create or replace function public.can_manage_project(p uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(auth.uid() is not null and p is not null and (
    is_system_admin()
    or exists (
      select 1 from public.projects pr join public.profiles me on me.id = auth.uid()
      where pr.id = p and pr.company_id = me.company_id
        and (me.role = 'admin'
             or (me.role = 'manager'
                 and exists (select 1 from public.project_members m where m.project_id = pr.id and m.user_id = me.id))))), false)
$$;

create or replace function public.can_upload_plans(p uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(auth.uid() is not null and public.can_access_project(p) and (
    is_system_admin()
    or exists (select 1 from public.profiles me where me.id = auth.uid() and (me.role in ('admin', 'manager') or me.signer_role = 'supervisor'))), false)
$$;

-- the member-level RPCs: a caller without a profile is refused outright
create or replace function public.duplicate_work_item_checklist(p_work_item uuid, p_src_no int default null)
returns int language plpgsql security definer set search_path = public as $$
declare v_pid uuid; v_company uuid; v_src int; v_no int;
begin
  if not exists (select 1 from public.profiles where id = auth.uid()) then raise exception 'not allowed' using errcode = '42501'; end if;
  select project_id, company_id into v_pid, v_company from public.work_items where id = p_work_item;
  if v_pid is null or not coalesce(public.can_access_project(v_pid), false) then
    raise exception 'not allowed' using errcode = '42501';
  end if;
  select coalesce(p_src_no, min(coalesce(list_no, 1))) into v_src from public.checklist_instances where work_item_id = p_work_item;
  if v_src is null or not exists (select 1 from public.checklist_instances where work_item_id = p_work_item and coalesce(list_no, 1) = v_src) then
    raise exception 'no checklist to duplicate';
  end if;
  select coalesce(max(n), 1) + 1 into v_no from (
    select list_no as n from public.work_item_checklists where work_item_id = p_work_item
    union all select coalesce(list_no, 1) from public.checklist_instances where work_item_id = p_work_item) s;
  insert into public.work_item_checklists (company_id, work_item_id, list_no, label, created_by)
    values (v_company, p_work_item, v_no, null, auth.uid());
  insert into public.checklist_instances (company_id, work_item_id, task_name, task_order, list_no, required_signer)
    select v_company, p_work_item, task_name, task_order, v_no, required_signer
    from public.checklist_instances where work_item_id = p_work_item and coalesce(list_no, 1) = v_src;
  return v_no;
end $$;

create or replace function public.set_checklist_label(p_work_item uuid, p_list_no int, p_label text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_pid uuid; v_company uuid; v_label text := nullif(btrim(p_label), ''); v_row jsonb;
begin
  if not exists (select 1 from public.profiles where id = auth.uid()) then raise exception 'not allowed' using errcode = '42501'; end if;
  select project_id, company_id into v_pid, v_company from public.work_items where id = p_work_item;
  if v_pid is null or not coalesce(public.can_access_project(v_pid), false) then raise exception 'not allowed' using errcode = '42501'; end if;
  if v_label is not null and char_length(v_label) > 200 then raise exception 'label too long'; end if;
  if not exists (select 1 from public.checklist_instances ci where ci.work_item_id = p_work_item and coalesce(ci.list_no, 1) = p_list_no) then
    raise exception 'no such checklist';
  end if;
  insert into public.work_item_checklists as w (company_id, work_item_id, list_no, label, created_by)
    values (v_company, p_work_item, p_list_no, v_label, auth.uid())
    on conflict on constraint work_item_checklists_work_item_id_list_no_key do update set label = excluded.label
    returning jsonb_build_object('id', w.id, 'list_no', w.list_no, 'label', w.label) into v_row;
  return v_row;
end $$;

create or replace function public.get_project_user_emails(p_project_id uuid)
returns table (user_id uuid, full_name text, role text, signer_role text, email text)
language plpgsql stable security definer set search_path = public as $$
declare proj_company uuid;
begin
  if not exists (select 1 from public.profiles where id = auth.uid()) then raise exception 'not allowed'; end if;
  select company_id into proj_company from public.projects where id = p_project_id;
  if proj_company is null then return; end if;
  if not coalesce(
    is_system_admin()
    or exists (select 1 from public.project_members pm where pm.project_id = p_project_id and pm.user_id = auth.uid())
    or exists (select 1 from public.profiles me where me.id = auth.uid() and me.role = 'admin' and me.company_id = proj_company), false)
  then
    raise exception 'not allowed';
  end if;
  return query
    select pr.id, pr.full_name, pr.role, pr.signer_role, u.email::text
    from public.profiles pr join auth.users u on u.id = pr.id
    where pr.company_id = proj_company
      and (pr.role = 'admin' or pr.id in (select pm.user_id from public.project_members pm where pm.project_id = p_project_id))
    order by pr.full_name;
end $$;

create or replace function public.get_company_user_emails()
returns table (id uuid, email text)
language plpgsql security definer set search_path = public as $$
begin
  if not coalesce(exists (select 1 from public.profiles where profiles.id = auth.uid() and profiles.role = 'admin') or is_system_admin(), false) then
    raise exception 'not authorized';
  end if;
  return query select u.id, u.email::text from auth.users u join public.profiles p on p.id = u.id
    where is_system_admin() or p.company_id = get_company_id();
end $$;

-- ── D-02 / D-03 / D-04 / D-05 / D-10: guards on the rows that scope everything else ─────────────
-- work items: the execution type (decides the signer requirement) and the project / company are structure → managers only
create or replace function public.guard_work_item_change() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or is_system_admin() then return new; end if;
  if new.company_id is distinct from old.company_id then raise exception 'company cannot be changed' using errcode = '42501'; end if;
  if new.execution_type is distinct from old.execution_type or new.project_id is distinct from old.project_id then
    if not (public.can_manage_project(old.project_id) and public.can_manage_project(new.project_id)) then
      raise exception 'only an admin or project manager may change the execution type / project of a work item' using errcode = '42501';
    end if;
  end if;
  return new;
end $$;
drop trigger if exists trg_guard_work_item_change on public.work_items;
create trigger trg_guard_work_item_change before update on public.work_items
  for each row execute function public.guard_work_item_change();

-- a row may never be moved out of its project (project_id := NULL makes it company-wide); moving needs manager rights on both projects
create or replace function public.guard_project_id_change() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or is_system_admin() or new.project_id is not distinct from old.project_id then return new; end if;
  if new.project_id is null then raise exception 'project cannot be cleared' using errcode = '42501'; end if;
  if not (public.can_manage_project(new.project_id) and (old.project_id is null or public.can_manage_project(old.project_id))) then
    raise exception 'only an admin or project manager may move a record between projects' using errcode = '42501';
  end if;
  return new;
end $$;
drop trigger if exists trg_guard_project_id_change on public.findings;
create trigger trg_guard_project_id_change before update on public.findings for each row execute function public.guard_project_id_change();
drop trigger if exists trg_guard_project_id_change on public.inspection_orders;
create trigger trg_guard_project_id_change before update on public.inspection_orders for each row execute function public.guard_project_id_change();
drop trigger if exists trg_guard_project_id_change on public.contractors;
create trigger trg_guard_project_id_change before update on public.contractors for each row execute function public.guard_project_id_change();

-- findings: the author is the caller and cannot be rewritten
create or replace function public.guard_finding_row() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return new; end if;
  if tg_op = 'INSERT' then new.created_by := auth.uid(); else new.created_by := old.created_by; end if;
  return new;
end $$;
drop trigger if exists trg_guard_finding_row on public.findings;
create trigger trg_guard_finding_row before insert or update on public.findings for each row execute function public.guard_finding_row();

-- projects: company is fixed, created_by / created_at are server-set
drop policy if exists projects_update on public.projects;
create policy projects_update on public.projects for update
  using (public.can_manage_project(id))
  with check (public.can_manage_project(id) and (company_id = get_company_id() or is_system_admin()));

create or replace function public.guard_project_row() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return new; end if;
  if tg_op = 'INSERT' then
    new.created_by := auth.uid(); new.created_at := now();
  else
    new.created_by := old.created_by; new.created_at := old.created_at;
    if not is_system_admin() then new.company_id := old.company_id; end if;
  end if;
  return new;
end $$;
drop trigger if exists trg_guard_project_row on public.projects;
create trigger trg_guard_project_row before insert or update on public.projects
  for each row execute function public.guard_project_row();

-- ── D-06: a signature file belongs to its owner ──────────────────────────────────────────────
create or replace function public.guard_profile_signature() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or new.signature_url is null then return new; end if;
  if tg_op = 'UPDATE' and new.signature_url is not distinct from old.signature_url then return new; end if;
  if position('/documents/signatures/' || new.id::text || '/' in new.signature_url) = 0 then
    raise exception 'a signature must be a file under your own signatures folder' using errcode = '42501';
  end if;
  return new;
end $$;
drop trigger if exists trg_guard_profile_signature on public.profiles;
create trigger trg_guard_profile_signature before insert or update on public.profiles
  for each row execute function public.guard_profile_signature();

-- ── D-11 (+ the move of a row between work items): checklist row identity is structure ────────────
create or replace function public.stamp_checklist_signer()
returns trigger language plpgsql security definer set search_path = public as $$
declare p record; stamp_now boolean; v_req text; v_exec text; v_pid uuid; v_manage boolean;
begin
  if auth.uid() is null then return new; end if;   -- service role / SQL console
  select project_id, execution_type into v_pid, v_exec from public.work_items
    where id = case when tg_op = 'UPDATE' then old.work_item_id else new.work_item_id end;
  v_manage := public.can_manage_project(v_pid);

  if tg_op = 'UPDATE' and not v_manage then
    if new.task_name is distinct from old.task_name or new.task_order is distinct from old.task_order
       or new.list_no is distinct from old.list_no or new.work_item_id is distinct from old.work_item_id
       or new.company_id is distinct from old.company_id then
      raise exception 'only an admin or project manager may change the checklist structure' using errcode = '42501';
    end if;
    if new.required_signer is distinct from old.required_signer then
      raise exception 'only an admin or project manager may change the required signer' using errcode = '42501';
    end if;
  end if;

  if new.is_checked is true then
    stamp_now := (tg_op = 'INSERT');
    if tg_op = 'UPDATE' then stamp_now := old.is_checked is distinct from true; end if;
    if stamp_now then
      select full_name, signer_role, signature_url into p from public.profiles where id = auth.uid();
      v_req := coalesce(new.required_signer,
                        (select c.required_signer from public.checklist_type_config c where c.company_id = new.company_id and c.type_name = v_exec));
      if not public.can_sign_as(p.signer_role, v_req) then
        raise exception 'not authorized to sign: this item requires role %', v_req using errcode = '42501';
      end if;
      new.checked_by := auth.uid(); new.signer_name := p.full_name; new.signer_role := p.signer_role; new.signature_url := p.signature_url;
    else
      if new.checked_at is distinct from old.checked_at and old.checked_by is distinct from auth.uid() and not v_manage then
        raise exception 'only the signer or a manager may change the sign date' using errcode = '42501';
      end if;
      new.checked_by := old.checked_by; new.signer_name := old.signer_name; new.signer_role := old.signer_role; new.signature_url := old.signature_url;
    end if;
  else
    if tg_op = 'UPDATE' and old.is_checked is true and old.checked_by is distinct from auth.uid() and not v_manage then
      raise exception 'only the signer or a manager may undo a signature' using errcode = '42501';
    end if;
    new.checked_by := null; new.signer_name := null; new.signer_role := null; new.signature_url := null;
  end if;
  return new;
end $$;

-- ── D-13: nothing is added under an archived folder (the folder itself or any ancestor) ────────────
create or replace function public.folder_chain_archived(f uuid) returns boolean
language sql stable security definer set search_path = public as $$
  with recursive up as (
    select id, parent_id, archived_at from public.folders where id = f
    union all
    select x.id, x.parent_id, x.archived_at from public.folders x join up on x.id = up.parent_id)
  select exists (select 1 from up where archived_at is not null)
$$;
grant execute on function public.folder_chain_archived(uuid) to authenticated, service_role;

create or replace function public.guard_folder_change() returns trigger
language plpgsql security definer set search_path = public as $$
declare v_manage boolean; v_owner boolean;
begin
  if auth.uid() is null or pg_trigger_depth() > 1 then   -- service role, or a nested change (seed trigger, FK cascade)
    if tg_op = 'DELETE' then return old; end if;
    return new;
  end if;
  if tg_op = 'INSERT' then
    new.created_by := auth.uid();
    if not is_system_admin() then new.is_default := false; end if;   -- only the seeding trigger creates protected folders
    new.archived_at := null; new.archived_by := null;
    if new.parent_id is not null then
      if not exists (select 1 from public.folders f where f.id = new.parent_id and f.project_id = new.project_id and f.company_id = new.company_id) then
        raise exception 'parent folder is not in this project';
      end if;
      if public.folder_chain_archived(new.parent_id) then raise exception 'the parent folder is archived' using errcode = '42501'; end if;
    end if;
    return new;
  elsif tg_op = 'UPDATE' then
    if not is_system_admin() and (new.project_id is distinct from old.project_id or new.company_id is distinct from old.company_id
        or new.parent_id is distinct from old.parent_id or new.is_default is distinct from old.is_default
        or new.created_by is distinct from old.created_by) then
      raise exception 'folder structure fields cannot be changed' using errcode = '42501';
    end if;
    v_manage := public.can_manage_project(old.project_id);
    v_owner := old.created_by = auth.uid();
    if (new.name is distinct from old.name or new.archived_at is distinct from old.archived_at)
       and not (is_system_admin() or v_manage or (not old.is_default and v_owner)) then
      raise exception 'only the folder owner or a manager may rename / archive a folder (default folders: managers only)' using errcode = '42501';
    end if;
    if new.archived_at is distinct from old.archived_at then
      new.archived_by := case when new.archived_at is null then null else auth.uid() end;
    else
      new.archived_by := old.archived_by;
    end if;
    return new;
  else   -- DELETE
    if old.is_default then raise exception 'default folders cannot be deleted — archive them' using errcode = '42501'; end if;
    if exists (select 1 from public.folders c where c.parent_id = old.id) or exists (select 1 from public.project_files f where f.folder_id = old.id) then
      raise exception 'folder is not empty — archive it instead' using errcode = '23503';
    end if;
    return old;
  end if;
end $$;

create or replace function public.guard_project_file() returns trigger
language plpgsql security definer set search_path = public as $$
declare v_name text;
begin
  if auth.uid() is null or pg_trigger_depth() > 1 then return new; end if;
  if not exists (select 1 from public.folders f
                 where f.id = new.folder_id and f.project_id = new.project_id and f.company_id = new.company_id)
     or public.folder_chain_archived(new.folder_id) then
    raise exception 'folder is not an open folder of this project' using errcode = '42501';
  end if;
  if public.folder_root_is_plans(new.folder_id) and not public.can_upload_plans(new.project_id) then
    raise exception 'plans may only be uploaded by a supervisor or a project manager' using errcode = '42501';
  end if;
  select full_name into v_name from public.profiles where id = auth.uid();
  new.uploaded_by := auth.uid(); new.uploaded_by_name := v_name;
  return new;
end $$;

-- ── D-12: the deciding admin cannot rewrite who asked or when ────────────────────────────────────
create or replace function public.guard_user_request() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    new.status := 'pending'; new.decided_by := null; new.decided_at := null; new.decision_note := null;
    if auth.uid() is not null then
      new.requested_by := auth.uid();
      new.created_at := now();
      select full_name into new.requested_by_name from public.profiles where id = auth.uid();
    end if;
    return new;
  end if;
  if auth.uid() is not null then
    if old.status <> 'pending' then raise exception 'request already decided' using errcode = '42501'; end if;
    if new.company_id is distinct from old.company_id or new.project_id is distinct from old.project_id
       or new.full_name is distinct from old.full_name or new.email is distinct from old.email or new.requested_by is distinct from old.requested_by
       or new.signer_role is distinct from old.signer_role or new.phone is distinct from old.phone or new.note is distinct from old.note
       or new.requested_by_name is distinct from old.requested_by_name or new.created_at is distinct from old.created_at then
      raise exception 'only the decision may change' using errcode = '42501';
    end if;
    if new.status <> 'pending' then new.decided_by := auth.uid(); new.decided_at := now(); end if;
  end if;
  return new;
end $$;

-- ── D-07: storage enforces the same rules as the tables ──────────────────────────────────────────
-- project-files/<project>/<folder>/<key>: the folder must be an open folder of that project; the plans tree needs plan-upload rights.
-- Overwriting / deleting an EXISTING object additionally needs the uploader, a manager (or, in the plans tree, a plan uploader).
create or replace function public.storage_can_write(obj_name text)
returns boolean language sql stable set search_path = public as $$
  select public.storage_can_access(obj_name)
     and case split_part(obj_name, '/', 1)
       when 'signatures' then (
            split_part(split_part(obj_name, '/', 2), '.', 1) = auth.uid()::text
            or is_system_admin()
            or exists (
              select 1 from public.profiles me
              join public.profiles tgt on tgt.id::text = split_part(split_part(obj_name, '/', 2), '.', 1)
              where me.id = auth.uid() and me.role = 'admin' and tgt.company_id = me.company_id))
       when 'company-logos' then (is_system_admin() or my_role() = 'admin')
       when 'project-files' then (
            split_part(obj_name, '/', 3) ~ '^[0-9a-fA-F-]{36}$'
            and exists (select 1 from public.folders f
                        where f.id::text = split_part(obj_name, '/', 3) and f.project_id::text = split_part(obj_name, '/', 2))
            and not public.folder_chain_archived(split_part(obj_name, '/', 3)::uuid)
            and (not public.folder_root_is_plans(split_part(obj_name, '/', 3)::uuid)
                 or public.can_upload_plans(split_part(obj_name, '/', 2)::uuid)))
       else true
     end
$$;

create or replace function public.storage_can_modify(obj_name text, obj_owner text)
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce(case split_part(obj_name, '/', 1)
    when 'project-files' then (
         split_part(obj_name, '/', 2) ~ '^[0-9a-fA-F-]{36}$' and split_part(obj_name, '/', 3) ~ '^[0-9a-fA-F-]{36}$'
         and (is_system_admin()
              or (obj_owner = auth.uid()::text and not public.folder_root_is_plans(split_part(obj_name, '/', 3)::uuid))
              or public.can_manage_project(split_part(obj_name, '/', 2)::uuid)
              or (public.folder_root_is_plans(split_part(obj_name, '/', 3)::uuid) and public.can_upload_plans(split_part(obj_name, '/', 2)::uuid))))
    when 'checklist-docs' then (
         is_system_admin() or obj_owner = auth.uid()::text
         or public.can_manage_work_item((select ci.work_item_id from public.checklist_instances ci
                                         where ci.id::text = split_part(split_part(obj_name, '/', 3), '.', 1))))
    else true end, false)
$$;
grant execute on function public.storage_can_modify(text, text) to authenticated, service_role;

drop policy if exists documents_update on storage.objects;
create policy documents_update on storage.objects for update
  using (bucket_id = 'documents' and public.storage_can_write(name) and public.storage_can_modify(name, owner_id))
  with check (bucket_id = 'documents' and public.storage_can_write(name));
drop policy if exists documents_delete on storage.objects;
create policy documents_delete on storage.objects for delete
  using (bucket_id = 'documents' and public.storage_can_write(name) and public.storage_can_modify(name, owner_id));

notify pgrst, 'reload schema';
