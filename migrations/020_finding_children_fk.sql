-- QA round 7d, N-06: finding_activity / finding_attachments had no foreign key to findings, so deleting a finding (or its project)
-- left orphan rows (and permissions_test / smoke runs left rows behind). NOT VALID: orphans that already exist are not checked;
-- new rows must reference a finding and are removed together with it.
do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'finding_activity_finding_fk') then
    alter table public.finding_activity add constraint finding_activity_finding_fk
      foreign key (finding_id) references public.findings(id) on delete cascade not valid;
  end if;
  if not exists (select 1 from pg_constraint where conname = 'finding_attachments_finding_fk') then
    alter table public.finding_attachments add constraint finding_attachments_finding_fk
      foreign key (finding_id) references public.findings(id) on delete cascade not valid;
  end if;
end $$;
notify pgrst, 'reload schema';
