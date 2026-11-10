-- Stop points (נקודות עצירה): only a quality inspector (qa_inspector) or quality assurance (qa_assurance) who can access the project
-- may release one. Decided 9.11.2026 (meeting follow-up). Same principle as signing: no bypass for company admins or system admins.
--   release (stop_released false -> true): releasers only; the releaser is stamped by the server
--   a release record is immutable: to change it, re-open it first. Re-open / remove / DELETE of a RELEASED stop point: releasers only
--   removing an OPEN stop point (no record yet): releasers, or an admin / project manager
--   release fields on a row that is not released are always cleared by the server (no forged "approved" rows)
--   marking a stop point (false -> true): unchanged, any project member (adding a safeguard is always allowed)
-- The service role / SQL console (auth.uid() is null) is not restricted.
-- QA round 10 (D-01..D-03): NULL is treated as false (an `is_stop_point := null` patch used to skip the check), the record cannot be rewritten
-- in place, forged release values are normalised away; both flags become NOT NULL (no NULL rows existed in staging or production).

update public.work_items set is_stop_point = false where is_stop_point is null;
update public.work_items set stop_released = false where stop_released is null;
alter table public.work_items alter column is_stop_point set default false, alter column is_stop_point set not null,
                              alter column stop_released set default false, alter column stop_released set not null;

create or replace function public.can_release_stop_point(p uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(auth.uid() is not null and public.can_access_project(p) and exists (
    select 1 from public.profiles me where me.id = auth.uid() and me.signer_role in ('qa_inspector', 'qa_assurance')), false)
$$;
revoke all on function public.can_release_stop_point(uuid) from public, anon;
grant execute on function public.can_release_stop_point(uuid) to authenticated, service_role;

create or replace function public.guard_stop_point_release() returns trigger
language plpgsql security definer set search_path = public as $$
declare v_pid uuid; v_rel boolean; v_mgr boolean;
        v_old_rel boolean; v_new_rel boolean; v_old_stop boolean; v_new_stop boolean; v_fields boolean;
begin
  if auth.uid() is null then return new; end if;   -- service role / SQL console
  v_new_rel := coalesce(new.stop_released, false);
  v_new_stop := coalesce(new.is_stop_point, false);
  v_pid := case when tg_op = 'INSERT' then new.project_id else old.project_id end;
  v_rel := public.can_release_stop_point(v_pid);
  v_mgr := public.can_manage_project(v_pid);

  if tg_op = 'INSERT' then
    if (v_new_rel or new.stop_released_at is not null or new.stop_released_by is not null
        or new.stop_release_result is not null or new.stop_release_notes is not null) and not v_rel then
      raise exception 'only a quality inspector or quality assurance may release a stop point' using errcode = '42501';
    end if;
    if v_new_rel then new.stop_released_by := auth.uid();
    else new.stop_released_at := null; new.stop_released_by := null; new.stop_release_result := null; new.stop_release_notes := null; end if;
    return new;
  end if;

  v_old_rel := coalesce(old.stop_released, false);
  v_old_stop := coalesce(old.is_stop_point, false);
  v_fields := new.stop_released_at is distinct from old.stop_released_at
           or new.stop_released_by is distinct from old.stop_released_by
           or new.stop_release_result is distinct from old.stop_release_result
           or new.stop_release_notes is distinct from old.stop_release_notes;

  -- a release record is immutable while it stands: re-open it first
  if v_old_rel and v_new_rel and v_fields then
    raise exception 'a release record cannot be edited; re-open the stop point first' using errcode = '42501';
  end if;
  -- release
  if v_new_rel and not v_old_rel and not v_rel then
    raise exception 'only a quality inspector or quality assurance may release a stop point' using errcode = '42501';
  end if;
  -- re-open / un-mark (NULL counts as false, so is_stop_point := null is an un-mark)
  -- a RELEASED stop point carries the approval record: only a releaser may re-open or remove it (a manager can no longer wipe the record)
  if v_old_rel and ((not v_new_rel) or (v_old_stop and not v_new_stop)) and not v_rel then
    raise exception 'only a quality inspector or quality assurance may re-open or remove a released stop point' using errcode = '42501';
  end if;
  -- an OPEN stop point (no record yet) may also be removed by an admin / project manager
  if not v_old_rel and v_old_stop and not v_new_stop and not (v_rel or v_mgr) then
    raise exception 'only a quality inspector, quality assurance, admin or project manager may remove a stop point' using errcode = '42501';
  end if;

  -- (D-08) a row that is not a stop point, or has just become one, is never "released": no stale release carries over to a new stop point
  if not v_new_stop or not v_old_stop then v_new_rel := false; new.stop_released := false; end if;

  if v_new_rel and not v_old_rel then new.stop_released_by := auth.uid();
  elsif not v_new_rel then new.stop_released_at := null; new.stop_released_by := null; new.stop_release_result := null; new.stop_release_notes := null; end if;
  return new;
end $$;

-- a released stop point cannot be deleted (it is the approval record). The release must be re-opened first, by a releaser.
-- Deleting the whole project (FK cascade) is still possible: the project row is already gone when the cascade reaches the work items.
-- This also stops the Excel tree import while the project holds released stop points (a single DELETE statement: all or nothing).
create or replace function public.guard_stop_point_delete() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return old; end if;
  if coalesce(old.stop_released, false) and exists (select 1 from public.projects where id = old.project_id) then
    raise exception 'a released stop point cannot be deleted; a quality inspector or quality assurance must re-open it first' using errcode = '42501';
  end if;
  return old;
end $$;
drop trigger if exists trg_guard_stop_point_delete on public.work_items;
create trigger trg_guard_stop_point_delete before delete on public.work_items
  for each row execute function public.guard_stop_point_delete();

drop trigger if exists trg_guard_stop_point_release on public.work_items;
create trigger trg_guard_stop_point_release before insert or update on public.work_items
  for each row execute function public.guard_stop_point_release();

notify pgrst, 'reload schema';
