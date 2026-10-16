#!/usr/bin/env bash
# Runs check.sql against a throwaway database twice: with Supabase's old defaults, and after
# the 30 Oct 2026 change (defaults removed). Needs a local Postgres you can reach as postgres.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
db=grants_check_test
psql -q -U postgres -c "drop database if exists $db" -c "create database $db"
psql -q -U postgres -c "drop role if exists anon" -c "drop role if exists authenticated" -c "drop role if exists service_role" -c "drop role if exists supabase_admin" 2>/dev/null || true
psql -q -U postgres -d $db -f "$here/fixture.sql"
echo "== before 30 Oct 2026 =="
psql -U postgres -d $db -P pager=off -f "$here/../check.sql"
# What Supabase's change does: new tables no longer go to the API roles.
psql -q -U postgres -d $db -c "alter default privileges for role postgres in schema public revoke all on tables from anon, authenticated, service_role" \
  -c "alter default privileges for role postgres in schema public revoke all on sequences from anon, authenticated, service_role"
echo "== after 30 Oct 2026 =="
psql -U postgres -d $db -P pager=off -f "$here/../check.sql"
# Half the fix the check suggests for the server key (tables, not sequences), then the check again:
# the id counter default row must appear.
psql -q -U postgres -d $db -c "alter default privileges for role postgres in schema public grant select, insert, update, delete on tables to service_role"
echo "== after the table half of the suggested fix =="
psql -U postgres -d $db -P pager=off -f "$here/../check.sql"
# The same check as if today were after 30 Oct 2026 (the cut-off moved into the past).
sed "s/date '2026-10-30'/date '2000-01-01'/g" "$here/../check.sql" > /tmp/check-after.sql
echo "== after the table half of the suggested fix, read after 30 Oct 2026 =="
psql -U postgres -d $db -P pager=off -f /tmp/check-after.sql
# The other fixes the check prints, run as printed, then the check again: their rows must be gone.
psql -q -U postgres -d $db -c "revoke truncate, references, trigger, maintain on all tables in schema public from anon, authenticated" \
  -c "grant usage, select on sequence public.orders_id_seq to authenticated" \
  -c "alter view public.my_profiles set (security_invoker = true)" \
  -c "revoke all on table public.profile_count from anon, authenticated" \
  -c "grant select on table public.vault to anon, authenticated" \
  -c "alter default privileges for role postgres in schema public grant usage, select on sequences to service_role"
echo "== after the truncate, id counter, view and sequence default fixes =="
psql -U postgres -d $db -P pager=off -f "$here/../check.sql"
# With a second schema in the list: its open table must appear, named with the schema.
sed "s/values ('public')/values ('public'), ('api'), ('gone')/" "$here/../check.sql" > /tmp/check-api.sql
echo "== with the api schema in the list =="
psql -U postgres -d $db -P pager=off -f /tmp/check-api.sql
# New functions: the anon line taken away is not enough while PUBLIC keeps them.
psql -q -U postgres -d $db -c "alter default privileges for role postgres in schema public revoke execute on functions from anon, authenticated"
echo "== function default revoked for anon and authenticated, PUBLIC still has it =="
psql -U postgres -d $db -P pager=off -f "$here/../check.sql"
psql -q -U postgres -d $db -c "alter default privileges for role postgres revoke execute on functions from public"
echo "== PUBLIC function default revoked too: no new functions rows =="
psql -U postgres -d $db -P pager=off -f "$here/../check.sql"
