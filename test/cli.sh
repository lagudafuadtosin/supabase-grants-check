#!/usr/bin/env bash
# Makes a database from fixture.sql and runs the command's tests against it.
# Needs a local Postgres you can reach as postgres (peer), and Node.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
db=grants_cli_test
sudo -u postgres psql -q -c "drop database if exists $db" -c "create database $db"
sudo -u postgres psql -q -c "drop role if exists anon" -c "drop role if exists authenticated" -c "drop role if exists service_role" -c "drop role if exists supabase_admin" 2>/dev/null || true
sudo -u postgres psql -q -d $db -f "$here/fixture.sql" >/dev/null 2>&1 || true
sudo -u postgres psql -q -c "drop role if exists sgc_test" -c "create role sgc_test login superuser password 'sgc_test'"
cd "$here/.." && TEST_DATABASE_URL="postgres://sgc_test:sgc_test@127.0.0.1:5432/$db" node --test test/cli.test.js
