-- SECURITY: a user could update their own `profiles` row (policy profiles_update allows id = auth.uid() with no
-- WITH CHECK and no column protection) and set role = 'admin', system_admin = true or company_id = <another company>.
-- Found by the QA agent on 2026-10-08. This trigger closes it for every client request.
--   * system_admin and company_id: only a system admin may change them (or create a system admin)
--   * role: only an admin of the same company (or a system admin); nobody can promote themselves
-- Requests without a user JWT (service role, migrations, SQL console) are not restricted.

create or replace function public.guard_profile_privileged()
returns trigger language plpgsql security definer set search_path = public as $$
declare caller_admin boolean;
begin
  if auth.uid() is null or is_system_admin() then return new; end if;
  select exists (select 1 from public.profiles me
                 where me.id = auth.uid() and me.role = 'admin' and me.company_id = new.company_id) into caller_admin;
  if tg_op = 'INSERT' then
    if new.system_admin is true then raise exception 'only a system admin may create a system admin'; end if;
    if new.role = 'admin' and not caller_admin then raise exception 'only an admin may create an admin'; end if;
    return new;
  end if;
  if old.system_admin is true then raise exception 'a system admin profile may only be edited by a system admin or the owner'; end if;
  if new.system_admin is distinct from old.system_admin then raise exception 'system_admin may only be changed by a system admin'; end if;
  if new.company_id   is distinct from old.company_id   then raise exception 'the company may only be changed by a system admin'; end if;
  if new.role         is distinct from old.role and not caller_admin then raise exception 'only an admin may change roles'; end if;
  return new;
end $$;

drop trigger if exists trg_guard_profile_privileged on public.profiles;
create trigger trg_guard_profile_privileged before insert or update on public.profiles
  for each row execute function public.guard_profile_privileged();

-- closed lists (the signer_role was free text and is rendered in the users screen)
do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'profiles_role_chk') then
    alter table public.profiles add constraint profiles_role_chk check (role in ('user', 'inspector', 'manager', 'admin'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'profiles_signer_role_chk') then
    alter table public.profiles add constraint profiles_signer_role_chk
      check (signer_role is null or signer_role in ('qa_inspector', 'site_manager', 'surveyor', 'qa_assurance'));
  end if;
end $$;

-- A checklist tick is a signed action: the signer name/role/signature always come from the caller's own profile,
-- and once ticked they cannot be rewritten (previously the client chose them, so a colleague's name was possible).
create or replace function public.stamp_checklist_signer()
returns trigger language plpgsql security definer set search_path = public as $$
declare p record; stamp_now boolean;
begin
  if auth.uid() is null then return new; end if;
  if new.is_checked is true then
    -- OLD does not exist on INSERT, so it is only read in the UPDATE branch
    stamp_now := (tg_op = 'INSERT');
    if tg_op = 'UPDATE' then stamp_now := old.is_checked is distinct from true; end if;
    if stamp_now then
      select full_name, signer_role, signature_url into p from public.profiles where id = auth.uid();
      new.checked_by := auth.uid(); new.signer_name := p.full_name; new.signer_role := p.signer_role; new.signature_url := p.signature_url;
    else
      new.checked_by := old.checked_by; new.signer_name := old.signer_name; new.signer_role := old.signer_role; new.signature_url := old.signature_url;
    end if;
  else
    new.checked_by := null; new.signer_name := null; new.signer_role := null; new.signature_url := null;
  end if;
  return new;
end $$;
drop trigger if exists trg_stamp_checklist_signer on public.checklist_instances;
create trigger trg_stamp_checklist_signer before insert or update on public.checklist_instances
  for each row execute function public.stamp_checklist_signer();
