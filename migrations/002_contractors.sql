-- per-project contractor list (main contractor still lives in projects.contractor)
create table if not exists contractors (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null,
  project_id uuid not null references projects(id) on delete cascade,
  name text not null,
  is_main boolean default false,
  created_at timestamptz default now()
);
alter table contractors enable row level security;
drop policy if exists contractors_select on contractors;
create policy contractors_select on contractors for select using (company_id = get_company_id() or is_system_admin());
drop policy if exists contractors_insert on contractors;
create policy contractors_insert on contractors for insert with check (company_id = get_company_id());
drop policy if exists contractors_update on contractors;
create policy contractors_update on contractors for update using (company_id = get_company_id());
drop policy if exists contractors_delete on contractors;
create policy contractors_delete on contractors for delete using (company_id = get_company_id());
