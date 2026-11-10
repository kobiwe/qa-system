-- Owner decision 10.11.2026: a company admin (profiles.role = 'admin') may release / re-open stop points without holding a quality role.
-- Everything else from migration 026 stays: a project manager or an ordinary member still cannot, the releaser is stamped by the server,
-- the record is immutable until re-opened, a released stop point cannot be deleted, access to the project is still required.
-- system_admin is covered through can_access_project (platform operator); a company admin of ANOTHER company has no project access.

create or replace function public.can_release_stop_point(p uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(auth.uid() is not null and public.can_access_project(p) and exists (
    select 1 from public.profiles me where me.id = auth.uid()
      and (me.signer_role in ('qa_inspector', 'qa_assurance') or me.role = 'admin' or coalesce(me.system_admin, false))), false)
$$;
revoke all on function public.can_release_stop_point(uuid) from public, anon;
grant execute on function public.can_release_stop_point(uuid) to authenticated, service_role;

notify pgrst, 'reload schema';
