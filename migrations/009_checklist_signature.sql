-- Checklist ticks carry the signer's profile signature (auto-stamped, no manual signing per action).
-- Stores the same opaque pointer string as other file columns (see 008); NULL for ticks made before this change.
alter table public.checklist_instances add column if not exists signature_url text;
