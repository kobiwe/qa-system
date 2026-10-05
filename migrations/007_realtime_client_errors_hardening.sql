-- 1) realtime: the publication was empty, so the app's subscription to inspection_orders (lab-certificate toast) never fired.
--    REPLICA IDENTITY FULL so payload.old carries certificate_url (the client compares old vs new).
do $$ begin
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'inspection_orders') then
    alter publication supabase_realtime add table public.inspection_orders;
  end if;
end $$;
alter table public.inspection_orders replica identity full;

-- 2) client-side error log (authenticated users insert their own rows; only system admins read)
create table if not exists public.client_errors (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  user_id uuid default auth.uid(),
  company_id uuid default get_company_id(),
  env text,
  message text not null,
  context jsonb,
  url text,
  user_agent text
);
alter table public.client_errors enable row level security;
drop policy if exists client_errors_insert on public.client_errors;
create policy client_errors_insert on public.client_errors for insert to authenticated with check (user_id = auth.uid());
drop policy if exists client_errors_select on public.client_errors;
create policy client_errors_select on public.client_errors for select to authenticated using (is_system_admin());

-- 3) the admin-only email RPC has no business being callable anonymously
revoke execute on function public.get_company_user_emails() from public, anon;
grant execute on function public.get_company_user_emails() to authenticated;
