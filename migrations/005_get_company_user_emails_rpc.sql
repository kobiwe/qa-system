-- profiles has no email column (it lives in auth.users); admins need emails for the users screen / password reset
create or replace function get_company_user_emails() returns table(id uuid, email text) security definer set search_path = public as $$
begin
  if not (exists (select 1 from profiles where profiles.id = auth.uid() and profiles.role = 'admin') or is_system_admin()) then
    raise exception 'not authorized';
  end if;
  return query select u.id, u.email::text from auth.users u join profiles p on p.id = u.id
    where is_system_admin() or p.company_id = get_company_id();
end; $$ language plpgsql;
grant execute on function get_company_user_emails() to authenticated;
