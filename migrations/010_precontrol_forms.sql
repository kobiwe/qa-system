-- Pre-control ("בקרה מקדימה"): supplier / material / subcontractor approvals and trial sections.
-- One generic table (type-specific fields live in `data` jsonb), a file list, and a tamper-proof history written by triggers.
--
-- Rules enforced here (not only in the UI):
--   * a form is visible to whoever can see its project (table RLS on projects), inside the same company
--   * only quality assurance (profiles.signer_role = 'qa_assurance'), a company admin or a system admin may change `status`
--   * only an admin may grant the 'qa_assurance' signer role (otherwise users could promote themselves)

-- ── who may approve ───────────────────────────────────────────────────────────
create or replace function public.can_approve_precontrol()
returns boolean language sql stable security definer set search_path = public as $$
  select auth.uid() is not null and (
    is_system_admin()
    or exists (select 1 from public.profiles me where me.id = auth.uid() and (me.role = 'admin' or me.signer_role = 'qa_assurance'))
  )
$$;
grant execute on function public.can_approve_precontrol() to authenticated;

-- ── tables ───────────────────────────────────────────────────────────────────
create table if not exists public.precontrol_forms (
  id              uuid primary key default gen_random_uuid(),
  company_id      uuid not null default get_company_id(),
  project_id      uuid not null references public.projects(id) on delete cascade,
  form_type       text not null check (form_type in ('supplier', 'material', 'subcontractor', 'trial_section')),
  serial_number   integer,
  title           text not null,
  status          text not null default 'in_progress' check (status in ('approved', 'in_progress', 'rejected')),
  supplier_name   text,
  branch          text,
  material        text,
  submitted_date  date,
  valid_from      date,
  valid_to        date,
  notes           text,
  data            jsonb not null default '{}'::jsonb,     -- check items / trial-section fields
  recipients      jsonb not null default '[]'::jsonb,     -- user ids the form is sent to
  decision_note   text,                                   -- comment given with the last status decision
  decided_by      uuid,
  decided_by_name text,
  decided_at      timestamptz,
  created_by      uuid default auth.uid(),
  created_by_name text,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  constraint precontrol_forms_shape check (
    jsonb_typeof(data) = 'object' and jsonb_typeof(recipients) = 'array'
    and char_length(title) between 1 and 300
    and coalesce(char_length(supplier_name), 0) <= 300 and coalesce(char_length(branch), 0) <= 300 and coalesce(char_length(material), 0) <= 300
    and coalesce(char_length(notes), 0) <= 5000 and coalesce(char_length(decision_note), 0) <= 2000
    and (valid_from is null or valid_to is null or valid_to >= valid_from))
);
create unique index if not exists precontrol_forms_serial_uq on public.precontrol_forms (project_id, form_type, serial_number);
create index if not exists precontrol_forms_project_idx on public.precontrol_forms (project_id, status);

create table if not exists public.precontrol_files (
  id               uuid primary key default gen_random_uuid(),
  company_id       uuid not null default get_company_id(),
  form_id          uuid not null references public.precontrol_forms(id) on delete cascade,
  name             text not null,
  url              text not null,
  size_bytes       bigint,
  uploaded_by      uuid default auth.uid(),
  uploaded_by_name text,
  created_at       timestamptz not null default now()
);
create index if not exists precontrol_files_form_idx on public.precontrol_files (form_id);

create table if not exists public.precontrol_history (
  id          uuid primary key default gen_random_uuid(),
  company_id  uuid not null,
  form_id     uuid not null references public.precontrol_forms(id) on delete cascade,
  action      text not null check (action in ('created', 'status_changed', 'updated')),   -- written by triggers only
  from_status text,
  to_status   text,
  comment     text,
  actor_id    uuid,
  actor_name  text,
  created_at  timestamptz not null default now()
);
create index if not exists precontrol_history_form_idx on public.precontrol_history (form_id, created_at);

-- privileges (RLS below decides who sees what; tables created by migrations do not get default grants)
grant select, insert, update, delete on public.precontrol_forms, public.precontrol_files to authenticated;
grant select on public.precontrol_history to authenticated;   -- no client writes: history is trigger-only
grant all on public.precontrol_forms, public.precontrol_files, public.precontrol_history to service_role;

-- ── triggers ──
create or replace function public.precontrol_file_guard()
returns trigger language plpgsql as $$
begin
  if new.url !~ ('^https://[a-z0-9]+.supabase.co/storage/v1/object/public/documents/precontrol/' || new.form_id::text || '/[A-Za-z0-9_.-]+$') or char_length(new.url) > 600 or char_length(new.name) > 300 then
    raise exception 'invalid attachment';
  end if;
  return new;
end $$;
drop trigger if exists trg_precontrol_file_guard on public.precontrol_files;
create trigger trg_precontrol_file_guard before insert or update on public.precontrol_files
  for each row execute function public.precontrol_file_guard();
create or replace function public.precontrol_before_write()
returns trigger language plpgsql security definer set search_path = public as $$
declare me_name text;
begin
  select full_name into me_name from public.profiles where id = auth.uid();
  new.updated_at := now();
  if tg_op = 'INSERT' then
    perform pg_advisory_xact_lock(hashtext(new.project_id::text || new.form_type));
    if new.serial_number is null then
      select coalesce(max(serial_number), 0) + 1 into new.serial_number
      from public.precontrol_forms where project_id = new.project_id and form_type = new.form_type;
    end if;
    if auth.uid() is not null then
      new.created_by      := auth.uid();
      new.created_by_name := me_name;
      new.decided_by := null; new.decided_by_name := null; new.decided_at := null; new.decision_note := null;
    end if;
    if new.status <> 'in_progress' and not public.can_approve_precontrol() then
      raise exception 'only quality assurance may set the status';
    end if;
  else
    if auth.uid() is not null then   -- system columns are not writable from the client
      new.company_id := old.company_id; new.project_id := old.project_id; new.form_type := old.form_type;
      new.serial_number := old.serial_number; new.created_by := old.created_by; new.created_by_name := old.created_by_name; new.created_at := old.created_at;
    end if;
    if new.status is distinct from old.status then
      if not public.can_approve_precontrol() then
        raise exception 'only quality assurance may change the status';
      end if;
      new.decided_by      := auth.uid();
      new.decided_by_name := me_name;
      new.decided_at      := now();
    elsif auth.uid() is not null then   -- no status change: the decision stamp cannot be forged
      new.decided_by := old.decided_by; new.decided_by_name := old.decided_by_name; new.decided_at := old.decided_at; new.decision_note := old.decision_note;
    end if;
  end if;
  return new;
end $$;

create or replace function public.precontrol_after_write()
returns trigger language plpgsql security definer set search_path = public as $$
declare me_name text;
begin
  select full_name into me_name from public.profiles where id = auth.uid();
  if tg_op = 'INSERT' then
    insert into public.precontrol_history (company_id, form_id, action, to_status, actor_id, actor_name)
    values (new.company_id, new.id, 'created', new.status, auth.uid(), me_name);
  elsif new.status is distinct from old.status then
    insert into public.precontrol_history (company_id, form_id, action, from_status, to_status, comment, actor_id, actor_name)
    values (new.company_id, new.id, 'status_changed', old.status, new.status, new.decision_note, auth.uid(), me_name);
  elsif (to_jsonb(new) - 'updated_at') is distinct from (to_jsonb(old) - 'updated_at') then
    insert into public.precontrol_history (company_id, form_id, action, actor_id, actor_name)
    values (new.company_id, new.id, 'updated', auth.uid(), me_name);
  end if;
  return new;
end $$;

drop trigger if exists trg_precontrol_before on public.precontrol_forms;
create trigger trg_precontrol_before before insert or update on public.precontrol_forms
  for each row execute function public.precontrol_before_write();
drop trigger if exists trg_precontrol_after on public.precontrol_forms;
create trigger trg_precontrol_after after insert or update on public.precontrol_forms
  for each row execute function public.precontrol_after_write();

-- only an admin may hand out the quality-assurance role
create or replace function public.guard_qa_assurance_role()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.signer_role = 'qa_assurance'
     and (tg_op = 'INSERT' or new.signer_role is distinct from old.signer_role)
     and auth.uid() is not null then
    if not (is_system_admin() or exists (
        select 1 from public.profiles me where me.id = auth.uid() and me.role = 'admin' and me.company_id = new.company_id)) then
      raise exception 'only an admin may grant the quality assurance role';
    end if;
  end if;
  return new;
end $$;
drop trigger if exists trg_guard_qa_role on public.profiles;
create trigger trg_guard_qa_role before insert or update of signer_role on public.profiles
  for each row execute function public.guard_qa_assurance_role();

-- ── RLS ──────────────────────────────────────────────────────────────────────
alter table public.precontrol_forms   enable row level security;
alter table public.precontrol_files   enable row level security;
alter table public.precontrol_history enable row level security;

drop policy if exists pc_forms_select on public.precontrol_forms;
create policy pc_forms_select on public.precontrol_forms for select to authenticated using (
  is_system_admin() or (company_id = get_company_id()
    and exists (select 1 from public.projects p where p.id = precontrol_forms.project_id)));
drop policy if exists pc_forms_insert on public.precontrol_forms;
create policy pc_forms_insert on public.precontrol_forms for insert to authenticated with check (
  is_system_admin() or (company_id = get_company_id()
    and exists (select 1 from public.projects p where p.id = precontrol_forms.project_id)));
drop policy if exists pc_forms_update on public.precontrol_forms;
create policy pc_forms_update on public.precontrol_forms for update to authenticated using (
  is_system_admin() or (company_id = get_company_id()
    and exists (select 1 from public.projects p where p.id = precontrol_forms.project_id)))
  with check (
  is_system_admin() or (company_id = get_company_id()
    and exists (select 1 from public.projects p where p.id = precontrol_forms.project_id)));
drop policy if exists pc_forms_delete on public.precontrol_forms;
create policy pc_forms_delete on public.precontrol_forms for delete to authenticated using (
  is_system_admin() or (company_id = get_company_id()
    and exists (select 1 from public.projects p where p.id = precontrol_forms.project_id)
    and (created_by = auth.uid() or public.can_approve_precontrol())));

drop policy if exists pc_files_all on public.precontrol_files;
create policy pc_files_all on public.precontrol_files for all to authenticated
  using (exists (select 1 from public.precontrol_forms f where f.id = precontrol_files.form_id))
  with check (exists (select 1 from public.precontrol_forms f where f.id = precontrol_files.form_id));

drop policy if exists pc_history_select on public.precontrol_history;
create policy pc_history_select on public.precontrol_history for select to authenticated
  using (exists (select 1 from public.precontrol_forms f where f.id = precontrol_history.form_id));
drop policy if exists pc_history_insert on public.precontrol_history;   -- history is written by triggers only

-- ── recipients: the users of a project (members + company admins) with their e-mail ─────────────
create or replace function public.get_project_user_emails(p_project_id uuid)
returns table (user_id uuid, full_name text, role text, signer_role text, email text)
language plpgsql stable security definer set search_path = public as $$
declare proj_company uuid;
begin
  select company_id into proj_company from public.projects where id = p_project_id;
  if proj_company is null then return; end if;
  if not (
    is_system_admin()
    or exists (select 1 from public.project_members pm where pm.project_id = p_project_id and pm.user_id = auth.uid())
    or exists (select 1 from public.profiles me where me.id = auth.uid() and me.role = 'admin' and me.company_id = proj_company)
  ) then
    raise exception 'not allowed';
  end if;
  return query
    select pr.id, pr.full_name, pr.role, pr.signer_role, u.email::text
    from public.profiles pr join auth.users u on u.id = pr.id
    where pr.company_id = proj_company
      and (pr.role = 'admin' or pr.id in (select pm.user_id from public.project_members pm where pm.project_id = p_project_id))
    order by pr.full_name;
end $$;
revoke execute on function public.get_project_user_emails(uuid) from public, anon;
grant execute on function public.get_project_user_emails(uuid) to authenticated;

-- ── storage: attachments live under precontrol/<form_id>/... and follow the form's visibility ───────
create or replace function public.storage_can_access(obj_name text)
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
