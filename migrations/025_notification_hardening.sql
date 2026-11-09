-- QA round 9 follow-up: (D-4) one live certificate notification per order, enforced by the database instead of a read-then-insert check;
-- (D-6) tries to remove API roles' EXECUTE on pg_net's HTTP functions. NOTE: on Supabase those functions are owned by supabase_admin with PUBLIC
-- execute, so this revoke is a silent no-op for the postgres role; the `net` schema is not exposed through the REST API, so it is not reachable
-- from the browser (QA round 9 confirmed). Kept so that it takes effect if the platform ever allows it.

create unique index if not exists email_log_one_certificate_notice_idx on public.email_log (ref_id)
  where kind = 'lab_certificate' and status in ('pending', 'sent', 'dry_run');

do $$
declare f record;
begin
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace
           where n.nspname = 'net' and p.proname in ('http_post', 'http_get', 'http_delete') loop
    execute format('revoke execute on function %s from public, anon, authenticated', f.sig);
  end loop;
exception when others then
  raise notice 'could not revoke pg_net execute: %', sqlerrm;
end $$;

notify pgrst, 'reload schema';
