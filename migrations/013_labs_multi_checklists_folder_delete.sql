-- 013: meeting 29.10.2026 — project labs (control + assurance), several checklists per work item, restricted folder deletion

-- 1) labs per project. The existing projects.lab_email stays the CONTROL lab address; the assurance lab is new.
alter table projects add column if not exists lab_control_name text;
alter table projects add column if not exists lab_assurance_name text;
alter table projects add column if not exists lab_assurance_email text;
-- which of the project's labs an order was addressed to (the e-mail address is resolved from the project at send time)
alter table inspection_orders add column if not exists lab_kind text;
alter table inspection_orders drop constraint if exists inspection_orders_lab_kind_chk;
alter table inspection_orders add constraint inspection_orders_lab_kind_chk check (lab_kind is null or lab_kind in ('control', 'assurance'));

-- 2) several checklists per work item ("layer"): every checklist_instances row belongs to list number N of its work item;
--    list rows (label = free description to tell the lists apart, e.g. a section / cross-section) live in work_item_checklists.
--    List 1 needs no row (all existing data is list 1).
alter table checklist_instances add column if not exists list_no integer not null default 1;
create index if not exists checklist_instances_wi_list_idx on checklist_instances (work_item_id, list_no);

create table if not exists work_item_checklists (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references companies(id),
  work_item_id uuid not null references work_items(id) on delete cascade,
  list_no integer not null,
  label text,
  created_by uuid,
  created_at timestamptz default now(),
  unique (work_item_id, list_no)
);
alter table work_item_checklists enable row level security;
drop policy if exists wic_all on work_item_checklists;
create policy wic_all on work_item_checklists for all
  using (company_id = get_company_id() or is_system_admin())
  with check (company_id = get_company_id()
              and exists (select 1 from work_items w where w.id = work_item_id and w.company_id = get_company_id()));
grant select, insert, update, delete on public.work_item_checklists to authenticated;
grant select, insert, update, delete on public.work_item_checklists to service_role;

-- 3) folder deletion: any user of the company may create folders (folders_insert), only company admins / managers /
--    system admins may delete them (the UI hides the button; this is the real gate)
drop policy if exists folders_delete on folders;
create policy folders_delete on folders for delete using (
  company_id = get_company_id()
  and (is_system_admin() or exists (select 1 from profiles p where p.id = auth.uid() and p.role in ('admin', 'manager')))
);

-- 4) a checklist row can be linked to an inspection order by its number; the order's lab certificate then shows in the row.
--    The link is a pointer (the certificate is resolved live), so removing / re-uploading a certificate stays consistent.
alter table checklist_instances add column if not exists inspection_order_id uuid references inspection_orders(id) on delete set null;

notify pgrst, 'reload schema';
