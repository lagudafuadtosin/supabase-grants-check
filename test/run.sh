#!/usr/bin/env bash
# Runs check.sql against a throwaway database twice: with Supabase's old defaults, and after
# the 30 Oct 2026 change (defaults removed). Needs a local Postgres you can reach as postgres.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
db=grants_check_test
psql -q -U postgres -c "drop database if exists $db" -c "create database $db"
psql -q -U postgres -c "drop role if exists anon" -c "drop role if exists authenticated" -c "drop role if exists service_role" 2>/dev/null || true
psql -q -U postgres -d $db -f "$here/fixture.sql"
echo "== before 30 Oct 2026 =="
psql -U postgres -d $db -P pager=off -f "$here/../check.sql"
# What Supabase's change does: new tables no longer go to the API roles.
psql -q -U postgres -d $db -c "alter default privileges for role postgres in schema public revoke all on tables from anon, authenticated, service_role"
echo "== after 30 Oct 2026 =="
psql -U postgres -d $db -P pager=off -f "$here/../check.sql"
# The fix the check suggests for the server key, then the check again.
psql -q -U postgres -d $db -c "alter default privileges for role postgres in schema public grant select, insert, update, delete on tables to service_role"
echo "== after the suggested fix =="
psql -U postgres -d $db -P pager=off -f "$here/../check.sql"
# The same check as if today were after 30 Oct 2026 (the cut-off moved into the past).
sed "s/date '2026-10-30'/date '2000-01-01'/g" "$here/../check.sql" > /tmp/check-after.sql
echo "== after the suggested fix, read after 30 Oct 2026 =="
psql -U postgres -d $db -P pager=off -f /tmp/check-after.sql
