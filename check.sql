-- supabase-grants-check
-- https://github.com/lagudafuadtosin/supabase-grants-check
--
-- Paste into the Supabase SQL editor and run. It only reads. It changes nothing.
--
-- From 30 Oct 2026 Supabase stops handing new tables in the public schema to the
-- API roles (anon, authenticated, service_role) on existing projects. A table made
-- after that date is closed to the Data API until you grant it. This shows, in one
-- table, who gets your new tables today, which tables and functions are open, and
-- the exact lines to paste if you want to change something.
--
-- level: 1 = look at this now, 2 = check it is what you meant, 3 = fine
-- Nothing in the "fix" column is run for you. Read it first.

with
roles(role) as (
  values ('anon'), ('authenticated'), ('service_role')
),

-- Who gets new tables in public automatically (default privileges set by postgres).
defaults as (
  select r.role,
         exists (
           select 1
           from pg_default_acl d, aclexplode(d.defaclacl) a
           where d.defaclrole = 'postgres'::regrole
             and d.defaclnamespace = 'public'::regnamespace
             and d.defaclobjtype = 'r'
             and a.grantee = r.role::regrole
             and a.privilege_type = 'SELECT'
         ) as gets_new_tables
  from roles r
),

-- Every table and view the Data API can see in public.
tables as (
  select c.oid,
         format('%I.%I', n.nspname, c.relname) as name,
         c.relkind,
         c.relrowsecurity as rls,
         (select count(*) from pg_policy p where p.polrelid = c.oid) as policies,
         has_table_privilege('anon', c.oid, 'SELECT,INSERT,UPDATE,DELETE') as anon_any,
         has_table_privilege('authenticated', c.oid, 'SELECT,INSERT,UPDATE,DELETE') as auth_any,
         has_table_privilege('service_role', c.oid, 'SELECT') as server_reads
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public'
    and c.relkind in ('r', 'p', 'v', 'm')
    and not exists (select 1 from pg_depend dep where dep.objid = c.oid and dep.deptype = 'e')
),

-- Every function in public that a signed-out visitor can call.
functions as (
  select p.oid::regprocedure::text as name,
         p.prosecdef as definer
  from pg_proc p
  where p.pronamespace = 'public'::regnamespace
    and p.prokind in ('f', 'p')
    and has_function_privilege('anon', p.oid, 'EXECUTE')
    and not exists (select 1 from pg_depend dep where dep.objid = p.oid and dep.deptype = 'e')
),

findings(level, area, object, finding, fix) as (
  -- New tables: what changes on 30 Oct 2026.
  select case when d.role = 'service_role' and not d.gets_new_tables then 1
              when d.gets_new_tables and current_date < date '2026-10-30' then 2
              else 3 end,
         'new tables',
         d.role,
         case when d.role = 'service_role' and not d.gets_new_tables
              then 'Your server key does NOT get new tables automatically. Any new table your server reads will fail with 42501 until you grant it.'
              when d.role = 'service_role' and current_date < date '2026-10-30'
              then 'Your server key gets every new table automatically today, from Supabase''s default. Supabase removes that default on 30 Oct 2026. Set it yourself now and run this check again after 30 Oct.'
              when d.role = 'service_role'
              then 'OK: your server key gets every new table automatically.'
              when d.gets_new_tables and current_date < date '2026-10-30'
              then d.role || ' gets every new table automatically today. From 30 Oct 2026 Supabase stops this. If the app needs it, grant it in each new table''s migration.'
              when d.gets_new_tables
              then d.role || ' gets every new table automatically. Make sure you meant that: every new table is open to it until row level security is on.'
              else d.role || ' does not get new tables automatically. Grant it table by table, in the migration that makes each table.' end,
         case when d.role = 'service_role' and (not d.gets_new_tables or current_date < date '2026-10-30')
              then 'alter default privileges for role postgres in schema public grant select, insert, update, delete on tables to service_role; alter default privileges for role postgres in schema public grant usage, select on sequences to service_role;'
              when d.gets_new_tables and current_date < date '2026-10-30'
              then 'grant select, insert, update, delete on table public.<new_table> to ' || d.role || ';  -- in each new table''s migration'
              else '' end
  from defaults d

  union all

  -- Tables and views.
  select case when not t.rls and t.relkind in ('r', 'p') and (t.anon_any or t.auth_any) then 1
              when not t.server_reads then 2
              when t.rls and t.policies = 0 and (t.anon_any or t.auth_any) then 2
              when t.relkind in ('v', 'm') and (t.anon_any or t.auth_any) then 2
              else 3 end,
         case when t.relkind in ('v', 'm') then 'view' else 'table' end,
         t.name,
         case when not t.rls and t.relkind in ('r', 'p') and (t.anon_any or t.auth_any)
              then 'Reachable through the API by ' || concat_ws(' and ', case when t.anon_any then 'signed-out visitors' end, case when t.auth_any then 'signed-in users' end) || ', with row level security OFF. Anyone with your public key can read or change every row they have rights to.'
              when not t.server_reads
              then 'Your server key cannot read it. Fine if nothing on the server uses it.'
              when t.rls and t.policies = 0 and (t.anon_any or t.auth_any)
              then 'Row level security is on with no policies, so API users see nothing. Fine if only the server uses it.'
              when t.relkind in ('v', 'm') and (t.anon_any or t.auth_any)
              then 'View reachable through the API. Views do not apply row level security unless made with security_invoker. Check it shows only what it should.'
              else 'OK' end,
         case when not t.rls and t.relkind in ('r', 'p') and (t.anon_any or t.auth_any)
              then 'alter table ' || t.name || ' enable row level security;  -- then add policies for what the app needs, or: revoke all on table ' || t.name || ' from anon, authenticated;'
              when not t.server_reads
              then 'grant select, insert, update, delete on table ' || t.name || ' to service_role;'
              else '' end
  from tables t

  union all

  -- Functions a signed-out visitor can call.
  select case when f.definer then 1 else 2 end,
         'function',
         f.name,
         case when f.definer
              then 'Signed-out visitors can call this SECURITY DEFINER function. It runs with its owner''s rights and skips row level security.'
              else 'Signed-out visitors can call this function.' end,
         'revoke execute on function ' || f.name || ' from public, anon;  -- only if the app does not call it signed out'
  from functions f
)

select level, area, object, finding, fix
from findings
order by level, area, object;
