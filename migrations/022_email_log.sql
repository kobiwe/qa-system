-- Server-side e-mail (Edge Function `send-email`): log of every send attempt. Used for rate limits (per user / per company) and as an audit trail.
-- Rows are written ONLY by the Edge Function (service role). Users never insert, update or delete; company admins and system admins can read.

create table if not exists public.email_log (
  id          uuid primary key default gen_random_uuid(),
  company_id  uuid not null references public.companies(id) on delete cascade,
  project_id  uuid,
  user_id     uuid,
  kind        text not null check (kind in ('lab_order', 'ncr', 'precontrol')),
  ref_id      uuid,
  to_list     text[] not null default '{}',
  subject     text,
  attachment  text,
  status      text not null check (status in ('sent', 'failed', 'dry_run')),
  error       text,
  provider_id text,
  created_at  timestamptz not null default now()
);
create index if not exists email_log_user_time_idx    on public.email_log (user_id, created_at desc);
create index if not exists email_log_company_time_idx on public.email_log (company_id, created_at desc);
create index if not exists email_log_ref_idx          on public.email_log (kind, ref_id, created_at desc);

alter table public.email_log enable row level security;
drop policy if exists email_log_select on public.email_log;
create policy email_log_select on public.email_log for select to authenticated
  using (coalesce(public.is_system_admin(), false)
         or (company_id = public.get_company_id() and exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin')));

grant select on public.email_log to authenticated;
grant select, insert, update, delete on public.email_log to service_role;

-- same rule as every other text column (migration 019): no HTML tags
do $$
declare c text;
begin
  foreach c in array array['kind', 'subject', 'attachment', 'status', 'error', 'provider_id'] loop
    if not exists (select 1 from pg_constraint where conname = left('email_log_' || c || '_notag_chk', 63)) then
      execute format('alter table public.email_log add constraint %I check (%I is null or %I !~ ''<[A-Za-z/!?]'') not valid',
                     left('email_log_' || c || '_notag_chk', 63), c, c);
    end if;
  end loop;
end $$;

notify pgrst, 'reload schema';
