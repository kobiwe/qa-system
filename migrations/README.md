# Database migrations

Every schema / policy / storage change goes here as a numbered, **idempotent** `.sql` file
(`create ... if not exists`, `drop ... if exists`, `create or replace`).

Applied via `scripts/migrate.js` (local-only, holds the Supabase PAT), which records what ran in `public._migrations`:

```
node scripts/migrate.js staging     # apply pending files to staging
node scripts/migrate.js prod        # apply the same files to production (only after staging is verified)
node scripts/migrate.js prod --baseline   # only record files as applied (change already exists there)
```

Order of a release with a DB change: staging migration -> test -> **prod migration** -> merge the code to `main`.
Keep changes backward compatible (add columns/tables first; remove things in a later release), because
the old code stays live in production until the merge.

001-006 are the changes made Sept-Oct 2026 (baseline recorded on prod; actually applied on staging).
The pre-existing base schema itself (tables like projects/findings/work_items) is not captured here — to rebuild an
environment from scratch use `scripts/clone_schema.js <targetRef>` from a live source project.
