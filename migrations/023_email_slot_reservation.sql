-- QA round 8 (server-side e-mail): the rate limit was "count, then insert" without a lock, so 100 parallel requests all passed (M1).
-- reserve_email_slot() does the count and the insert atomically (advisory lock per user and per company) and returns the new row id,
-- or the name of the limit that was hit. The Edge Function (service role only) reserves BEFORE it downloads the attachment and
-- fails closed when the reservation cannot be written; it then updates the row to sent / failed / dry_run.

alter table public.email_log drop constraint if exists email_log_status_check;
alter table public.email_log add constraint email_log_status_check check (status in ('pending', 'sent', 'failed', 'dry_run'));

create or replace function public.reserve_email_slot(
  p_company uuid, p_project uuid, p_user uuid, p_kind text, p_ref uuid, p_to text[], p_subject text,
  p_user_hour int, p_company_day int, p_project_day int)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_id uuid;
begin
  -- one transaction at a time per user / company / project: the counts below cannot be raced
  perform pg_advisory_xact_lock(hashtextextended('email-user:' || p_user::text, 0));
  perform pg_advisory_xact_lock(hashtextextended('email-company:' || p_company::text, 0));
  if p_project is not null then perform pg_advisory_xact_lock(hashtextextended('email-project:' || p_project::text, 0)); end if;

  if (select count(*) from public.email_log where user_id = p_user and status in ('pending', 'sent', 'dry_run') and created_at > now() - interval '1 hour') >= p_user_hour then
    return jsonb_build_object('limited', 'user');
  end if;
  if (select count(*) from public.email_log where company_id = p_company and status in ('pending', 'sent', 'dry_run') and created_at > now() - interval '1 day') >= p_company_day then
    return jsonb_build_object('limited', 'company');
  end if;
  if p_project is not null and (select count(*) from public.email_log where project_id = p_project and status in ('pending', 'sent', 'dry_run') and created_at > now() - interval '1 day') >= p_project_day then
    return jsonb_build_object('limited', 'project');
  end if;

  insert into public.email_log (company_id, project_id, user_id, kind, ref_id, to_list, subject, status)
    values (p_company, p_project, p_user, p_kind, p_ref, p_to, p_subject, 'pending') returning id into v_id;
  return jsonb_build_object('id', v_id);
end $$;
revoke execute on function public.reserve_email_slot(uuid, uuid, uuid, text, uuid, text[], text, int, int, int) from public, anon, authenticated;
grant execute on function public.reserve_email_slot(uuid, uuid, uuid, text, uuid, text[], text, int, int, int) to service_role;

notify pgrst, 'reload schema';
