-- security fix: legacy USING(true) policies defeated the company-scoped ones (permissive policies are OR'd)
drop policy if exists "authenticated read findings" on findings;
drop policy if exists "authenticated write findings" on findings;
drop policy if exists "authenticated can insert profiles" on profiles;
drop policy if exists "authenticated can update profiles" on profiles;
drop policy if exists "authenticated read all profiles" on profiles;
drop policy if exists "auth_inspection_orders" on inspection_orders;
drop policy if exists "manage checklist_instances" on checklist_instances;
drop policy if exists "manage work_items" on work_items;
