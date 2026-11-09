-- "A lab certificate arrived" notification: when the lab uploads a certificate (inspection_orders.certificate_url NULL -> value) a trigger calls the
-- Edge Function `notify-certificate` through pg_net (asynchronous HTTP). The function mails the person who created the order, with the PDF attached.
-- The URL of the function and a shared secret are kept in Supabase Vault (names `notify_url`, `notify_secret`; set per environment by
-- scripts/setup_notifications.js). Without them the trigger does nothing, and a failure of the notification can never block the lab's upload.

create extension if not exists pg_net;

alter table public.email_log drop constraint if exists email_log_kind_check;
alter table public.email_log add constraint email_log_kind_check check (kind in ('lab_order', 'ncr', 'precontrol', 'lab_certificate'));

create or replace function public.notify_certificate_uploaded() returns trigger
language plpgsql security definer set search_path = public as $$
declare v_url text; v_secret text;
begin
  select decrypted_secret into v_url    from vault.decrypted_secrets where name = 'notify_url'    limit 1;
  select decrypted_secret into v_secret from vault.decrypted_secrets where name = 'notify_secret' limit 1;
  if v_url is null or v_secret is null then return new; end if;
  begin
    perform net.http_post(url := v_url,
      headers := jsonb_build_object('Content-Type', 'application/json', 'x-notify-secret', v_secret),
      body := jsonb_build_object('order_id', new.id),
      timeout_milliseconds := 8000);
  exception when others then
    null;   -- never let a notification problem roll back the certificate upload
  end;
  return new;
end $$;
revoke execute on function public.notify_certificate_uploaded() from public, anon, authenticated;

drop trigger if exists trg_notify_certificate on public.inspection_orders;
create trigger trg_notify_certificate after update of certificate_url on public.inspection_orders
  for each row when (old.certificate_url is null and new.certificate_url is not null)
  execute function public.notify_certificate_uploaded();

notify pgrst, 'reload schema';
