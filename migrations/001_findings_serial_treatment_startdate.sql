-- findings: serial number (per company, auto), required treatment, start date
alter table findings add column if not exists serial_number integer;
alter table findings add column if not exists required_treatment text;
alter table findings add column if not exists start_date date;

with ranked as (
  select id, row_number() over (partition by company_id order by created_at) rn from findings
)
update findings f set serial_number = ranked.rn from ranked where ranked.id = f.id and f.serial_number is null;

create or replace function assign_finding_serial_number() returns trigger as $$
begin
  if new.serial_number is null then
    select coalesce(max(serial_number), 0) + 1 into new.serial_number from findings where company_id = new.company_id;
  end if;
  return new;
end; $$ language plpgsql security definer;

drop trigger if exists trg_finding_serial_number on findings;
create trigger trg_finding_serial_number before insert on findings
  for each row execute function assign_finding_serial_number();
