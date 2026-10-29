-- 015: the lab identifies an order by (project id, running order number) instead of the 6-character id code.
-- No real customers yet (owner decision 29.10.2026), so the old code-based function and the links built on it are dropped.
-- The project id travels inside the e-mailed link and is unguessable; the order number is only unique per project, so both are needed.
-- Certificate files are named certificates/cert_<project id>_<order number>_<ts>.pdf and the function checks that exact shape.

drop function if exists public.submit_lab_certificate(text, text);

create or replace function public.submit_lab_certificate(p_project_id uuid, p_order_number integer, p_cert_url text)
returns json language plpgsql security definer set search_path = public as $$
declare v_id uuid; v_path text;
begin
  if p_project_id is null or p_order_number is null or p_order_number < 1 then
    return json_build_object('success', false, 'error', 'invalid_order');
  end if;
  if p_cert_url is null or p_cert_url !~ ('^https://[a-z0-9]+\.supabase\.co/storage/v1/object/public/documents/certificates/cert_'
       || p_project_id::text || '_' || p_order_number::text || '_[0-9]{10,14}\.pdf$') then
    return json_build_object('success', false, 'error', 'invalid_file');
  end if;
  v_path := substring(p_cert_url from '/documents/(certificates/.+)$');
  if not exists (select 1 from storage.objects where bucket_id = 'documents' and name = v_path) then
    return json_build_object('success', false, 'error', 'file_not_found');
  end if;
  select id into v_id from public.inspection_orders where project_id = p_project_id and order_number = p_order_number;
  if v_id is null then return json_build_object('success', false, 'error', 'order_not_found'); end if;
  update public.inspection_orders set certificate_url = p_cert_url, status = 'completed'
   where id = v_id and certificate_url is null;
  if not found then return json_build_object('success', false, 'error', 'already_submitted'); end if;
  return json_build_object('success', true, 'order_id', v_id::text);
end $$;
grant execute on function public.submit_lab_certificate(uuid, integer, text) to anon, authenticated;

-- lets the lab page check the link BEFORE uploading a file (no orphan files for unknown / already answered orders).
-- Reveals only open / submitted / not_found, and only to someone who holds the project id.
create or replace function public.lab_order_status(p_project_id uuid, p_order_number integer)
returns json language sql stable security definer set search_path = public as $$
  select coalesce(
    (select json_build_object('status', case when o.certificate_url is null then 'open' else 'submitted' end)
       from public.inspection_orders o where o.project_id = p_project_id and o.order_number = p_order_number),
    json_build_object('status', 'not_found'))
$$;
grant execute on function public.lab_order_status(uuid, integer) to anon, authenticated;

notify pgrst, 'reload schema';
