-- documents module: folder tree + files; default tree seeded by a trigger on every new project
create table if not exists folders (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null,
  project_id uuid not null references projects(id) on delete cascade,
  parent_id uuid references folders(id) on delete cascade,
  name text not null,
  is_default boolean default false,
  row_order integer default 0,
  created_by uuid,
  created_at timestamptz default now()
);
alter table folders enable row level security;
drop policy if exists folders_select on folders;
create policy folders_select on folders for select using (company_id = get_company_id() or is_system_admin());
drop policy if exists folders_insert on folders;
create policy folders_insert on folders for insert with check (company_id = get_company_id());
drop policy if exists folders_update on folders;
create policy folders_update on folders for update using (company_id = get_company_id());
drop policy if exists folders_delete on folders;
create policy folders_delete on folders for delete using (company_id = get_company_id());

create table if not exists project_files (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null,
  project_id uuid not null references projects(id) on delete cascade,
  folder_id uuid not null references folders(id) on delete cascade,
  name text not null,
  url text not null,
  size_bytes bigint,
  uploaded_by uuid,
  uploaded_by_name text,
  created_at timestamptz default now()
);
alter table project_files enable row level security;
drop policy if exists project_files_select on project_files;
create policy project_files_select on project_files for select using (company_id = get_company_id() or is_system_admin());
drop policy if exists project_files_insert on project_files;
create policy project_files_insert on project_files for insert with check (company_id = get_company_id());
drop policy if exists project_files_delete on project_files;
create policy project_files_delete on project_files for delete using (company_id = get_company_id());

create or replace function seed_default_folders() returns trigger security definer set search_path = public as $$
declare plans_id uuid;
begin
  insert into folders (company_id, project_id, parent_id, name, is_default, row_order)
  select new.company_id, new.id, null, t.name, true, t.ord
  from unnest(array['איכות','איכות סביבה','בטיחות','חוזה','יומני עבודה','לוחות זמנים','סיורי פתע','סיכומי ישיבות','פיקוח עליון','צו התחלת עבודה','תוכניות לביצוע']) with ordinality as t(name, ord);
  select id into plans_id from folders where project_id = new.id and name = 'תוכניות לביצוע' and parent_id is null;
  insert into folders (company_id, project_id, parent_id, name, is_default, row_order)
  select new.company_id, new.id, plans_id, s.name, true, s.ord
  from unnest(array['אדריכל מבנים','אדריכלות מעטפת ופנים','אדריכלות נוף','איטום','אינסטלציה','אלומיניום','בזק','בטיחות','בטיחות אש','ביסוס וקרקע','בניה ירוקה','גיאולוג','חשמל ותאורה','מיזוג אוויר','מים וביוב','מעליות']) with ordinality as s(name, ord);
  return new;
end; $$ language plpgsql;

drop trigger if exists trg_seed_default_folders on projects;
create trigger trg_seed_default_folders after insert on projects
  for each row execute function seed_default_folders();

-- one-off backfill for projects that existed before the trigger (idempotent)
insert into folders (company_id, project_id, parent_id, name, is_default, row_order)
select p.company_id, p.id, null, f.name, true, f.ord from projects p
cross join (select * from unnest(array['איכות','איכות סביבה','בטיחות','חוזה','יומני עבודה','לוחות זמנים','סיורי פתע','סיכומי ישיבות','פיקוח עליון','צו התחלת עבודה','תוכניות לביצוע']) with ordinality as t(name, ord)) f
where not exists (select 1 from folders ff where ff.project_id = p.id and ff.is_default);
insert into folders (company_id, project_id, parent_id, name, is_default, row_order)
select parent.company_id, parent.project_id, parent.id, sub.name, true, sub.ord from folders parent
cross join (select * from unnest(array['אדריכל מבנים','אדריכלות מעטפת ופנים','אדריכלות נוף','איטום','אינסטלציה','אלומיניום','בזק','בטיחות','בטיחות אש','ביסוס וקרקע','בניה ירוקה','גיאולוג','חשמל ותאורה','מיזוג אוויר','מים וביוב','מעליות']) with ordinality as t(name, ord)) sub
where parent.name = 'תוכניות לביצוע' and parent.parent_id is null
  and not exists (select 1 from folders c where c.parent_id = parent.id);
