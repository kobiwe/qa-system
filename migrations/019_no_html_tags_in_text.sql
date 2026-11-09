-- QA round 7c: stored XSS keeps appearing in a new column every round (findings.status, work_items.stop_release_notes, type names …).
-- The UI escapes what it renders, and from now on the database also refuses HTML TAGS in every text column of the public schema:
-- a value may not contain `<` followed by a letter, `/`, `!` or `?` (so "<5%", "> 2", "ס"מ" and quotes stay legal, `<img`, `</b>`, `<!--` do not).
-- NOT VALID: rows that already exist are not re-checked (validate after reviewing them: select * from public._notag_violations()).
-- This replaces the stricter `*_nomarkup_chk` constraints of migration 018, which also forbade a plain `>` (an Excel import with "גובה > 2" failed).

do $$
declare c record; ccount int := 0;
begin
  -- remove the 018 constraints
  for c in select conrelid::regclass::text as t, conname from pg_constraint where conname like '%\_nomarkup\_chk' escape '\' loop
    execute format('alter table %s drop constraint %I', c.t, c.conname);
  end loop;

  for c in
    select table_name, column_name, data_type
    from information_schema.columns
    where table_schema = 'public'
      and table_name in (select tablename from pg_tables where schemaname = 'public')
      and table_name not in ('_migrations', 'client_errors')
      and data_type in ('text', 'character varying', 'jsonb')
  loop
    if not exists (select 1 from pg_constraint where conname = left(c.table_name || '_' || c.column_name || '_notag_chk', 63)) then
      execute format('alter table public.%I add constraint %I check (%s) not valid',
        c.table_name, left(c.table_name || '_' || c.column_name || '_notag_chk', 63),
        case when c.data_type = 'jsonb' then format('%I is null or %I::text !~ ''<[A-Za-z/!?]''', c.column_name, c.column_name)
             else format('%I is null or %I !~ ''<[A-Za-z/!?]''', c.column_name, c.column_name) end);
      ccount := ccount + 1;
    end if;
  end loop;
  raise notice 'added % notag constraints', ccount;
end $$;

-- review helper: rows that already contain a tag (to clean up before VALIDATE CONSTRAINT)
create or replace function public._notag_violations()
returns table (tbl text, col text, n bigint) language plpgsql security definer set search_path = public as $$
declare c record; cnt bigint;
begin
  for c in select conrelid::regclass::text as t, replace(conname, '_notag_chk', '') as nm, pg_get_constraintdef(oid) as d
           from pg_constraint where conname like '%\_notag\_chk' escape '\' loop
    execute format('select count(*) from %s where not (%s)', c.t, regexp_replace(c.d, '^CHECK \((.*)\)( NOT VALID)?$', '\1')) into cnt;
    if cnt > 0 then tbl := c.t; col := c.nm; n := cnt; return next; end if;
  end loop;
end $$;
revoke execute on function public._notag_violations() from anon, authenticated, public;

notify pgrst, 'reload schema';
