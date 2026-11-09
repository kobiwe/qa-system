-- Meeting 5.11.2026 (Kobi, Imran, Netanel): role-based permissions.
--
--  A) professional roles: + execution engineer, supervisor, electrical inspector; a professional role is granted by an admin only
--  B) per-row "required signer" on checklist templates/instances + SERVER-SIDE enforcement of who may sign / undo a signature
--  C) project scoping (S2): a user sees and writes only the projects they are a member of; company admins see all projects
--  D) structure writes (work items, checklist rows/lists, project members, contractors, templates) limited to admin / project manager
--  E) folders: the default tree is protected (no delete, archive only, by managers), user folders are archived/deleted by their owner;
--     plans folder ("תוכניות לביצוע") accepts uploads from a supervisor or project manager only
--  F) user requests: a project manager asks for a new user, a company admin approves
--  G) storage: checklist documents follow checklist visibility (project) instead of company-wide
--
-- Existing users keep their effective access: every current company user is added to every project of the company (backfill at the
-- end); admins then remove the people who should not see a project.

-- ── helpers ──────────────────────────────────────────────────────────────────────────────────
create or replace function public.is_signer_role(r text) returns boolean language sql immutable as $$
  select r is null or r in ('qa_inspector', 'site_manager', 'execution_engineer', 'surveyor', 'supervisor', 'electrical_inspector', 'qa_assurance')
$$;

-- who may sign a row that requires p_required:
--   no requirement → anyone; site manager ⇄ execution engineer are interchangeable; a QA inspector signs for the electrician / external parties;
--   a surveyor row only by a surveyor; a supervisor row only by a supervisor
create or replace function public.can_sign_as(p_signer text, p_required text) returns boolean language sql immutable as $$
  select case
    when p_required is null then true
    when p_signer is null then false
    when p_required in ('site_manager', 'execution_engineer') then p_signer in ('site_manager', 'execution_engineer')
    when p_required = 'electrical_inspector' then p_signer in ('electrical_inspector', 'qa_inspector')
    else p_signer = p_required
  end
$$;

create or replace function public.can_access_project(p uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select auth.uid() is not null and p is not null and (
    is_system_admin()
    or exists (
      select 1 from public.projects pr join public.profiles me on me.id = auth.uid()
      where pr.id = p and pr.company_id = me.company_id
        and (me.role = 'admin'
             or exists (select 1 from public.project_members m where m.project_id = pr.id and m.user_id = me.id))))
$$;

-- manage = company admin (any project of the company) or project manager who is a member of the project
create or replace function public.can_manage_project(p uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select auth.uid() is not null and p is not null and (
    is_system_admin()
    or exists (
      select 1 from public.projects pr join public.profiles me on me.id = auth.uid()
      where pr.id = p and pr.company_id = me.company_id
        and (me.role = 'admin'
             or (me.role = 'manager'
                 and exists (select 1 from public.project_members m where m.project_id = pr.id and m.user_id = me.id)))))
$$;

create or replace function public.can_manage_work_item(w uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select public.can_manage_project((select project_id from public.work_items where id = w))
$$;

-- plans may be uploaded by a project manager / company admin, or by a supervisor — and only in projects they can access
create or replace function public.can_upload_plans(p uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select auth.uid() is not null and public.can_access_project(p) and (
    is_system_admin()
    or exists (select 1 from public.profiles me where me.id = auth.uid() and (me.role in ('admin', 'manager') or me.signer_role = 'supervisor')))
$$;

create or replace function public.folder_root_is_plans(f uuid) returns boolean
language sql stable security definer set search_path = public as $$
  with recursive up as (
    select id, parent_id, name, is_default from public.folders where id = f
    union all
    select x.id, x.parent_id, x.name, x.is_default from public.folders x join up on x.id = up.parent_id)
  select exists (select 1 from up where parent_id is null and is_default and name = 'תוכניות לביצוע')
$$;

grant execute on function public.is_signer_role(text), public.can_sign_as(text, text), public.can_access_project(uuid),
  public.can_manage_project(uuid), public.can_manage_work_item(uuid), public.can_upload_plans(uuid), public.folder_root_is_plans(uuid)
  to authenticated, service_role;

-- ── A) professional roles ────────────────────────────────────────────────────────────────────
alter table public.profiles drop constraint if exists profiles_signer_role_chk;
alter table public.profiles add constraint profiles_signer_role_chk check (public.is_signer_role(signer_role));
alter table public.profiles add column if not exists phone text;
do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'profiles_phone_chk') then
    alter table public.profiles add constraint profiles_phone_chk check (phone is null or char_length(phone) <= 40);
  end if;
end $$;

-- the professional role decides who may sign what, so a user must not pick it for themselves (it was editable in the profile screen)
create or replace function public.guard_profile_privileged()
returns trigger language plpgsql security definer set search_path = public as $$
declare caller_admin boolean;
begin
  if auth.uid() is null or is_system_admin() then return new; end if;
  select exists (select 1 from public.profiles me
                 where me.id = auth.uid() and me.role = 'admin' and me.company_id = new.company_id) into caller_admin;
  if tg_op = 'INSERT' then
    if new.system_admin is true then raise exception 'only a system admin may create a system admin'; end if;
    if new.role = 'admin' and not caller_admin then raise exception 'only an admin may create an admin'; end if;
    if new.signer_role is not null and not caller_admin then raise exception 'only an admin may set a professional role'; end if;
    return new;
  end if;
  if old.system_admin is true then raise exception 'a system admin profile may only be edited by a system admin or the owner'; end if;
  if new.system_admin is distinct from old.system_admin then raise exception 'system_admin may only be changed by a system admin'; end if;
  if new.company_id   is distinct from old.company_id   then raise exception 'the company may only be changed by a system admin'; end if;
  if new.role         is distinct from old.role and not caller_admin then raise exception 'only an admin may change roles'; end if;
  if new.signer_role  is distinct from old.signer_role and not caller_admin then raise exception 'only an admin may change a professional role'; end if;
  return new;
end $$;

-- ── B) required signer per row + enforced signing ────────────────────────────────────────────
alter table public.checklist_templates add column if not exists required_signer text;
alter table public.checklist_instances add column if not exists required_signer text;
alter table public.checklist_templates drop constraint if exists checklist_templates_required_signer_chk;
alter table public.checklist_templates add constraint checklist_templates_required_signer_chk check (public.is_signer_role(required_signer));
alter table public.checklist_instances drop constraint if exists checklist_instances_required_signer_chk;
alter table public.checklist_instances add constraint checklist_instances_required_signer_chk check (public.is_signer_role(required_signer));
alter table public.checklist_type_config drop constraint if exists checklist_type_config_required_signer_chk;
alter table public.checklist_type_config add constraint checklist_type_config_required_signer_chk check (public.is_signer_role(required_signer));

create or replace function public.stamp_checklist_signer()
returns trigger language plpgsql security definer set search_path = public as $$
declare p record; stamp_now boolean; v_req text; v_exec text; v_pid uuid; v_manage boolean;
begin
  if auth.uid() is null then return new; end if;   -- service role / SQL console
  select project_id, execution_type into v_pid, v_exec from public.work_items where id = new.work_item_id;
  v_manage := public.can_manage_project(v_pid);

  -- the required signer of a row is configuration: managers only
  if tg_op = 'UPDATE' and new.required_signer is distinct from old.required_signer and not v_manage then
    raise exception 'only an admin or project manager may change the required signer' using errcode = '42501';
  end if;

  if new.is_checked is true then
    stamp_now := (tg_op = 'INSERT');
    if tg_op = 'UPDATE' then stamp_now := old.is_checked is distinct from true; end if;
    if stamp_now then
      select full_name, signer_role, signature_url into p from public.profiles where id = auth.uid();
      -- row requirement wins; otherwise the requirement configured for the execution type
      v_req := coalesce(new.required_signer,
                        (select c.required_signer from public.checklist_type_config c where c.company_id = new.company_id and c.type_name = v_exec));
      if not public.can_sign_as(p.signer_role, v_req) then
        raise exception 'not authorized to sign: this item requires role %', v_req using errcode = '42501';
      end if;
      new.checked_by := auth.uid(); new.signer_name := p.full_name; new.signer_role := p.signer_role; new.signature_url := p.signature_url;
    else
      -- still ticked: the signature is immutable; the sign date may be corrected by the signer or a manager only
      if new.checked_at is distinct from old.checked_at and old.checked_by is distinct from auth.uid() and not v_manage then
        raise exception 'only the signer or a manager may change the sign date' using errcode = '42501';
      end if;
      new.checked_by := old.checked_by; new.signer_name := old.signer_name; new.signer_role := old.signer_role; new.signature_url := old.signature_url;
    end if;
  else
    -- undoing a signature: the signer, or an admin / project manager
    if tg_op = 'UPDATE' and old.is_checked is true and old.checked_by is distinct from auth.uid() and not v_manage then
      raise exception 'only the signer or a manager may undo a signature' using errcode = '42501';
    end if;
    new.checked_by := null; new.signer_name := null; new.signer_role := null; new.signature_url := null;
  end if;
  return new;
end $$;

-- duplicate a checklist (same tasks and required signers, nothing ticked). Plain members may not insert checklist rows directly
-- (that would let them invent a row without a requirement and sign it), so duplication is the only member-level way to add rows.
create or replace function public.duplicate_work_item_checklist(p_work_item uuid, p_src_no int default null)
returns int language plpgsql security definer set search_path = public as $$
declare v_pid uuid; v_company uuid; v_src int; v_no int;
begin
  select project_id, company_id into v_pid, v_company from public.work_items where id = p_work_item;
  if v_pid is null or not public.can_access_project(v_pid) then
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
grant execute on function public.duplicate_work_item_checklist(uuid, int) to authenticated;
revoke execute on function public.duplicate_work_item_checklist(uuid, int) from anon, public;

-- naming a checklist ("description" of a list) is allowed to every member, but creating the list row is a structure write: RPC
create or replace function public.set_checklist_label(p_work_item uuid, p_list_no int, p_label text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_pid uuid; v_company uuid; v_label text := nullif(btrim(p_label), ''); v_row jsonb;
begin
  select project_id, company_id into v_pid, v_company from public.work_items where id = p_work_item;
  if v_pid is null or not public.can_access_project(v_pid) then raise exception 'not allowed' using errcode = '42501'; end if;
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
grant execute on function public.set_checklist_label(uuid, int, text) to authenticated;
revoke execute on function public.set_checklist_label(uuid, int, text) from anon, public;

-- ── C) projects: scoped visibility ───────────────────────────────────────────────────────────
alter table public.projects add column if not exists created_by uuid default auth.uid();

drop policy if exists projects_company_read on public.projects;   -- company-wide read (the S2 hole)
drop policy if exists projects_select on public.projects;
create policy projects_select on public.projects for select using (
  public.can_access_project(id)
  -- the creator: needed only for INSERT … RETURNING (the membership row is added by an AFTER trigger); expires at once so that
  -- removing the creator from the project really removes their access
  or (created_by = auth.uid() and company_id = get_company_id() and created_at > now() - interval '2 minutes'));
drop policy if exists projects_update on public.projects;
create policy projects_update on public.projects for update
  using (public.can_manage_project(id))
  with check (public.can_manage_project(id));

-- the creator (a project manager) becomes a member, otherwise they would lose sight of their own project
create or replace function public.add_project_creator_as_member() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is not null
     and exists (select 1 from public.profiles where id = auth.uid() and company_id = new.company_id and role <> 'admin') then
    insert into public.project_members (project_id, user_id, company_id, added_by)
      values (new.id, auth.uid(), new.company_id, auth.uid()) on conflict (project_id, user_id) do nothing;
  end if;
  return new;
end $$;
drop trigger if exists trg_add_project_creator_as_member on public.projects;
create trigger trg_add_project_creator_as_member after insert on public.projects
  for each row execute function public.add_project_creator_as_member();

-- members: company admin or the project's manager manage them; nobody can add a user of another company or to another company's project
drop policy if exists pm_select on public.project_members;
create policy pm_select on public.project_members for select using (user_id = auth.uid() or public.can_access_project(project_id));
drop policy if exists pm_insert on public.project_members;
create policy pm_insert on public.project_members for insert with check (
  public.can_manage_project(project_id)
  and exists (select 1 from public.projects pr where pr.id = project_id and pr.company_id = project_members.company_id)
  and exists (select 1 from public.profiles t where t.id = user_id and t.company_id = project_members.company_id));
drop policy if exists pm_delete on public.project_members;
create policy pm_delete on public.project_members for delete using (public.can_manage_project(project_id));

-- ── D) project data ──────────────────────────────────────────────────────────────────────────
-- read/update: any member. Structure (create/delete work items, checklist rows and lists): admin / project manager.
-- `project_id in (select id from projects)` is evaluated once per statement (projects RLS = project visibility), not per row.

drop policy if exists work_items_all on public.work_items;
create policy work_items_select on public.work_items for select using (project_id in (select id from public.projects));
create policy work_items_update on public.work_items for update
  using (project_id in (select id from public.projects))
  with check (project_id in (select id from public.projects) and (company_id = get_company_id() or is_system_admin()));
create policy work_items_insert on public.work_items for insert
  with check (public.can_manage_project(project_id) and (company_id = get_company_id() or is_system_admin()));
create policy work_items_delete on public.work_items for delete using (public.can_manage_project(project_id));

drop policy if exists ci_select on public.checklist_instances;
drop policy if exists ci_insert on public.checklist_instances;
drop policy if exists ci_update on public.checklist_instances;
drop policy if exists ci_delete on public.checklist_instances;
create policy ci_select on public.checklist_instances for select using (work_item_id in (select id from public.work_items));
create policy ci_update on public.checklist_instances for update
  using (work_item_id in (select id from public.work_items))
  with check (work_item_id in (select id from public.work_items) and (company_id = get_company_id() or is_system_admin()));
create policy ci_insert on public.checklist_instances for insert
  with check (public.can_manage_work_item(work_item_id) and (company_id = get_company_id() or is_system_admin()));
create policy ci_delete on public.checklist_instances for delete using (public.can_manage_work_item(work_item_id));

drop policy if exists wic_select on public.work_item_checklists;
drop policy if exists wic_insert on public.work_item_checklists;
drop policy if exists wic_update on public.work_item_checklists;
drop policy if exists wic_delete on public.work_item_checklists;
create policy wic_select on public.work_item_checklists for select using (work_item_id in (select id from public.work_items));
create policy wic_update on public.work_item_checklists for update
  using (work_item_id in (select id from public.work_items))
  with check (work_item_id in (select id from public.work_items) and (company_id = get_company_id() or is_system_admin()));
create policy wic_insert on public.work_item_checklists for insert
  with check (public.can_manage_work_item(work_item_id) and (company_id = get_company_id() or is_system_admin()));
create policy wic_delete on public.work_item_checklists for delete using (public.can_manage_work_item(work_item_id));

-- templates: readable by the company only (the "read templates" USING(true) policy leaked every company's templates; "admin manage templates"
-- let an admin of ANY company write ANY company's templates); written by admin / project manager
drop policy if exists "read templates" on public.checklist_templates;
drop policy if exists "admin manage templates" on public.checklist_templates;
drop policy if exists ct_all on public.checklist_templates;
create policy ct_select on public.checklist_templates for select using (company_id = get_company_id() or is_system_admin());
create policy ct_write on public.checklist_templates for all
  using ((company_id = get_company_id() and my_role() in ('admin', 'manager')) or is_system_admin())
  with check ((company_id = get_company_id() and my_role() in ('admin', 'manager')) or is_system_admin());

-- findings & their children
drop policy if exists findings_all on public.findings;
create policy findings_select on public.findings for select using (
  is_system_admin() or (project_id is null and company_id = get_company_id()) or project_id in (select id from public.projects));
create policy findings_insert on public.findings for insert with check (
  is_system_admin() or (company_id = get_company_id() and (project_id is null
    or project_id in (select p.id from public.projects p where p.company_id = findings.company_id))));
create policy findings_update on public.findings for update
  using (is_system_admin() or (project_id is null and company_id = get_company_id()) or project_id in (select id from public.projects))
  with check (is_system_admin() or (company_id = get_company_id() and (project_id is null
    or project_id in (select p.id from public.projects p where p.company_id = findings.company_id))));
create policy findings_delete on public.findings for delete using (
  is_system_admin() or created_by = auth.uid()
  or (project_id is null and company_id = get_company_id() and my_role() in ('admin', 'manager'))
  or public.can_manage_project(project_id));

drop policy if exists "company members manage finding attachments" on public.finding_attachments;
create policy fa_all on public.finding_attachments for all
  using (finding_id in (select id from public.findings))
  with check (company_id = get_company_id() and finding_id in (select id from public.findings));
drop policy if exists "company members view activity" on public.finding_activity;
drop policy if exists "company members insert activity" on public.finding_activity;
create policy fact_select on public.finding_activity for select using (finding_id in (select id from public.findings));
create policy fact_insert on public.finding_activity for insert
  with check (company_id = get_company_id() and finding_id in (select id from public.findings));

-- contractors: members read, admin / project manager write
drop policy if exists contractors_select on public.contractors;
drop policy if exists contractors_insert on public.contractors;
drop policy if exists contractors_update on public.contractors;
drop policy if exists contractors_delete on public.contractors;
create policy contractors_select on public.contractors for select using (
  is_system_admin() or (project_id is null and company_id = get_company_id()) or project_id in (select id from public.projects));
create policy contractors_insert on public.contractors for insert with check (
  company_id = get_company_id() and (public.can_manage_project(project_id) or (project_id is null and my_role() in ('admin', 'manager'))));
create policy contractors_update on public.contractors for update
  using (public.can_manage_project(project_id) or (project_id is null and company_id = get_company_id() and my_role() in ('admin', 'manager')))
  with check (company_id = get_company_id());
create policy contractors_delete on public.contractors for delete using (
  public.can_manage_project(project_id) or (project_id is null and company_id = get_company_id() and my_role() in ('admin', 'manager')));

-- inspection orders
drop policy if exists insp_orders_all on public.inspection_orders;
create policy insp_orders_all on public.inspection_orders for all
  using (is_system_admin() or (project_id is null and company_id = get_company_id()) or project_id in (select id from public.projects))
  with check ((company_id = get_company_id() or is_system_admin())
              and (project_id is null or project_id in (select p.id from public.projects p where p.company_id = inspection_orders.company_id)));

-- ── E) folders and project files ─────────────────────────────────────────────────────────────
alter table public.folders add column if not exists archived_at timestamptz;
alter table public.folders add column if not exists archived_by uuid;

drop policy if exists folders_select on public.folders;
drop policy if exists folders_insert on public.folders;
drop policy if exists folders_update on public.folders;
drop policy if exists folders_delete on public.folders;
create policy folders_select on public.folders for select using (is_system_admin() or project_id in (select id from public.projects));
create policy folders_insert on public.folders for insert with check (
  company_id = get_company_id() and project_id in (select p.id from public.projects p where p.company_id = folders.company_id));
create policy folders_update on public.folders for update
  using (is_system_admin() or project_id in (select id from public.projects))
  with check (is_system_admin() or project_id in (select id from public.projects));
-- the default tree can never be deleted by a client; a user folder only by its owner or a manager (and only when empty — see the trigger)
create policy folders_delete on public.folders for delete using (
  not is_default and (is_system_admin() or created_by = auth.uid() or public.can_manage_project(project_id)));

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
    if new.parent_id is not null and not exists (
      select 1 from public.folders f where f.id = new.parent_id and f.project_id = new.project_id and f.company_id = new.company_id) then
      raise exception 'parent folder is not in this project';
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
drop trigger if exists trg_guard_folder_change on public.folders;
create trigger trg_guard_folder_change before insert or update or delete on public.folders
  for each row execute function public.guard_folder_change();

drop policy if exists project_files_select on public.project_files;
drop policy if exists project_files_insert on public.project_files;
drop policy if exists project_files_delete on public.project_files;
create policy project_files_select on public.project_files for select using (is_system_admin() or project_id in (select id from public.projects));
create policy project_files_insert on public.project_files for insert with check (
  company_id = get_company_id() and project_id in (select p.id from public.projects p where p.company_id = project_files.company_id));
-- a file may be deleted by its uploader or a manager; inside the plans tree only by those who may upload plans (a supervisor included)
create policy project_files_delete on public.project_files for delete using (
  public.can_access_project(project_id)
  and (case when public.folder_root_is_plans(folder_id)
            then public.can_upload_plans(project_id)
            else uploaded_by = auth.uid() or public.can_manage_project(project_id) end));

create or replace function public.guard_project_file() returns trigger
language plpgsql security definer set search_path = public as $$
declare v_name text;
begin
  if auth.uid() is null or pg_trigger_depth() > 1 then return new; end if;
  if not exists (select 1 from public.folders f
                 where f.id = new.folder_id and f.project_id = new.project_id and f.company_id = new.company_id and f.archived_at is null) then
    raise exception 'folder is not an open folder of this project' using errcode = '42501';
  end if;
  if public.folder_root_is_plans(new.folder_id) and not public.can_upload_plans(new.project_id) then
    raise exception 'plans may only be uploaded by a supervisor or a project manager' using errcode = '42501';
  end if;
  select full_name into v_name from public.profiles where id = auth.uid();
  new.uploaded_by := auth.uid(); new.uploaded_by_name := v_name;
  return new;
end $$;
drop trigger if exists trg_guard_project_file on public.project_files;
create trigger trg_guard_project_file before insert on public.project_files
  for each row execute function public.guard_project_file();

-- ── F) user requests ─────────────────────────────────────────────────────────────────────────
create table if not exists public.user_requests (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id),
  project_id uuid not null references public.projects(id) on delete cascade,
  full_name text not null check (char_length(full_name) between 2 and 120),
  email text not null check (char_length(email) <= 200 and email ~* '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$'),
  phone text check (phone is null or char_length(phone) <= 40),
  signer_role text check (public.is_signer_role(signer_role)),
  note text check (note is null or char_length(note) <= 500),
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  requested_by uuid not null default auth.uid(),
  requested_by_name text,
  created_at timestamptz not null default now(),
  decided_by uuid,
  decided_at timestamptz,
  decision_note text check (decision_note is null or char_length(decision_note) <= 500)
);
create unique index if not exists user_requests_pending_uq on public.user_requests (project_id, lower(email)) where status = 'pending';
alter table public.user_requests enable row level security;
create policy ur_select on public.user_requests for select using (
  is_system_admin() or requested_by = auth.uid() or (company_id = get_company_id() and my_role() = 'admin'));
create policy ur_insert on public.user_requests for insert with check (
  company_id = get_company_id() and requested_by = auth.uid() and status = 'pending'
  and public.can_manage_project(project_id)
  and exists (select 1 from public.projects pr where pr.id = project_id and pr.company_id = user_requests.company_id));
create policy ur_update on public.user_requests for update
  using (is_system_admin() or (company_id = get_company_id() and my_role() = 'admin'))
  with check (is_system_admin() or (company_id = get_company_id() and my_role() = 'admin'));

create or replace function public.guard_user_request() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    new.status := 'pending'; new.decided_by := null; new.decided_at := null; new.decision_note := null;
    if auth.uid() is not null then
      new.requested_by := auth.uid();
      select full_name into new.requested_by_name from public.profiles where id = auth.uid();
    end if;
    return new;
  end if;
  if auth.uid() is not null then
    if old.status <> 'pending' then raise exception 'request already decided' using errcode = '42501'; end if;
    if new.company_id is distinct from old.company_id or new.project_id is distinct from old.project_id
       or new.full_name is distinct from old.full_name or new.email is distinct from old.email or new.requested_by is distinct from old.requested_by
       or new.signer_role is distinct from old.signer_role or new.phone is distinct from old.phone or new.note is distinct from old.note then
      raise exception 'only the decision may change' using errcode = '42501';
    end if;
    if new.status <> 'pending' then new.decided_by := auth.uid(); new.decided_at := now(); end if;
  end if;
  return new;
end $$;
drop trigger if exists trg_guard_user_request on public.user_requests;
create trigger trg_guard_user_request before insert or update on public.user_requests
  for each row execute function public.guard_user_request();

grant select, insert, update on public.user_requests to authenticated;
grant select, insert, update, delete on public.user_requests to service_role;

-- ── G) storage: checklist documents follow the checklist row's visibility (project), not the whole company ───────────
create or replace function public.storage_can_access(obj_name text)
returns boolean language sql stable set search_path = public as $$
  select auth.uid() is not null and (
    is_system_admin()
    or case split_part(obj_name, '/', 1)
      when 'company-logos'    then split_part(split_part(obj_name, '/', 2), '.', 1) = get_company_id()::text
      -- a signature is stamped on records other people read, so anyone who can see the owner's profile (same company) may read it
      when 'signatures'       then exists (select 1 from public.profiles pr where pr.id::text = split_part(split_part(obj_name, '/', 2), '.', 1))
      when 'checklist-docs'   then split_part(obj_name, '/', 2) = get_company_id()::text
                                   and exists (select 1 from public.checklist_instances ci where ci.id::text = split_part(split_part(obj_name, '/', 3), '.', 1))
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

-- ── backfill: nobody loses the access they have today ────────────────────────────────────────
insert into public.project_members (project_id, user_id, company_id, added_by)
select pr.id, pf.id, pr.company_id, null
from public.projects pr
join public.profiles pf on pf.company_id = pr.company_id and pf.role <> 'admin' and coalesce(pf.system_admin, false) = false
on conflict (project_id, user_id) do nothing;

notify pgrst, 'reload schema';
