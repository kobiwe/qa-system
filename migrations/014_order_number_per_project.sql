-- 014: inspection orders get a running 5-digit number per project, starting at 10000 (meeting follow-up, 29.10.2026).
-- The internal id stays the technical key (e.g. PDF storage names); order_number is what people see, type and what the lab uses
-- together with the project id (migration 015). Also: tenant-safe numbering and role-restricted deletes of checklist lists (QA round 2).

alter table projects add column if not exists next_order_number integer not null default 10000;
alter table inspection_orders add column if not exists order_number integer;

-- the guard trigger below must not undo the backfill, so it is (re)created at the end
drop trigger if exists trg_guard_next_order_number on projects;

-- backfill existing orders per project in creation order, then point the project counter past them (idempotent: only unnumbered rows)
with n as (
  select id, project_id,
         (select coalesce(max(x.order_number) + 1, 10000) from inspection_orders x where x.project_id = o.project_id and x.order_number is not null)
         + row_number() over (partition by project_id order by created_at, id) - 1 as num
  from inspection_orders o
  where order_number is null and project_id is not null
)
update inspection_orders o set order_number = n.num from n where o.id = n.id;

update projects p set next_order_number = greatest(p.next_order_number,
  coalesce((select max(o.order_number) + 1 from inspection_orders o where o.project_id = p.id), 10000));

create unique index if not exists inspection_orders_project_number_uq on inspection_orders (project_id, order_number) where order_number is not null;

-- numbering is server-side only: a client-sent value is ignored on insert, and the number never changes afterwards.
-- The counter lives on the project row, so concurrent inserts for one project are serialized by the row lock and a number is never reused.
-- The project must belong to the order's company (the function is SECURITY DEFINER, so this is checked explicitly).
create or replace function public.assign_order_number() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    if new.project_id is null then
      new.order_number := null;
    else
      update projects set next_order_number = next_order_number + 1
       where id = new.project_id and company_id = new.company_id
       returning next_order_number - 1 into new.order_number;
      if not found then raise exception 'project not found for this company' using errcode = '42501'; end if;
    end if;
  elsif new.order_number is distinct from old.order_number then
    new.order_number := old.order_number;
  end if;
  return new;
end $$;

drop trigger if exists trg_assign_order_number on inspection_orders;
create trigger trg_assign_order_number before insert or update on inspection_orders
  for each row execute function public.assign_order_number();

-- users cannot write the counter directly (only the numbering trigger, which runs one level deeper, may move it)
create or replace function public.guard_next_order_number() returns trigger
language plpgsql as $$
begin
  if new.next_order_number is distinct from old.next_order_number and pg_trigger_depth() = 1 then
    new.next_order_number := old.next_order_number;
  end if;
  return new;
end $$;
create trigger trg_guard_next_order_number before update on projects
  for each row execute function public.guard_next_order_number();

-- an order can only point at a project of the same company
drop policy if exists insp_orders_all on inspection_orders;
create policy insp_orders_all on inspection_orders for all
  using (company_id = get_company_id() or is_system_admin())
  with check ((company_id = get_company_id() or is_system_admin())
              and (project_id is null or exists (select 1 from projects p where p.id = inspection_orders.project_id and p.company_id = inspection_orders.company_id)));

-- deleting checklist rows / lists is limited to admins and managers in the database too (the UI only hides the button);
-- reading, adding and editing stay open to every user of the company
drop policy if exists ci_all on checklist_instances;
drop policy if exists ci_select on checklist_instances;
drop policy if exists ci_insert on checklist_instances;
drop policy if exists ci_update on checklist_instances;
drop policy if exists ci_delete on checklist_instances;
create policy ci_select on checklist_instances for select using (company_id = get_company_id() or is_system_admin());
create policy ci_insert on checklist_instances for insert with check (company_id = get_company_id() or is_system_admin());
create policy ci_update on checklist_instances for update using (company_id = get_company_id() or is_system_admin()) with check (company_id = get_company_id() or is_system_admin());
create policy ci_delete on checklist_instances for delete using ((company_id = get_company_id() or is_system_admin()) and (is_system_admin() or my_role() in ('admin', 'manager')));

drop policy if exists wic_all on work_item_checklists;
drop policy if exists wic_select on work_item_checklists;
drop policy if exists wic_insert on work_item_checklists;
drop policy if exists wic_update on work_item_checklists;
drop policy if exists wic_delete on work_item_checklists;
create policy wic_select on work_item_checklists for select using (company_id = get_company_id() or is_system_admin());
create policy wic_insert on work_item_checklists for insert
  with check (company_id = get_company_id() and exists (select 1 from work_items w where w.id = work_item_id and w.company_id = get_company_id()));
create policy wic_update on work_item_checklists for update using (company_id = get_company_id() or is_system_admin())
  with check (company_id = get_company_id() and exists (select 1 from work_items w where w.id = work_item_id and w.company_id = get_company_id()));
create policy wic_delete on work_item_checklists for delete using ((company_id = get_company_id() or is_system_admin()) and (is_system_admin() or my_role() in ('admin', 'manager')));

-- trigger functions are not meant to be called by anyone
revoke execute on function public.assign_order_number() from public, anon, authenticated;
revoke execute on function public.guard_next_order_number() from public, anon, authenticated;

notify pgrst, 'reload schema';
