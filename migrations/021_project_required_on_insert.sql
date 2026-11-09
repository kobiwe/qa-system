-- Decision 8.11.2026: every finding / inspection order belongs to the project being worked on.
-- The UI fills the project in by itself (active project; locked while editing), so users never have to pick it each time.
-- The database enforces it for NEW rows only: a signed-in caller cannot insert a finding / order without a project
-- (an admin could previously create a company-wide row). Existing rows without a project stay untouched, and
-- UPDATEs of them keep working (clearing a project on update is already refused by guard_project_id_change, migration 017).
-- Server-side callers (auth.uid() is null: migrations, seeds, service role) are not affected.
create or replace function public.require_project_on_insert() returns trigger
language plpgsql security invoker set search_path = public, pg_temp as $$
begin
  if auth.uid() is not null and new.project_id is null then
    raise exception 'project is required' using errcode = '23502';
  end if;
  return new;
end $$;

drop trigger if exists trg_require_project on public.findings;
create trigger trg_require_project before insert on public.findings for each row execute function public.require_project_on_insert();
drop trigger if exists trg_require_project on public.inspection_orders;
create trigger trg_require_project before insert on public.inspection_orders for each row execute function public.require_project_on_insert();

notify pgrst, 'reload schema';
