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

-- Postgres 17 added a MAINTAIN right next to TRUNCATE, REFERENCES and TRIGGER.
pg as (
  select current_setting('server_version_num')::int >= 170000 as has_maintain
),

-- Rights beyond read and write that new tables still give the browser roles.
extra_defaults as (
  select a.grantee::regrole::text as role,
         string_agg(distinct lower(a.privilege_type), ', ') as rights
  from pg_default_acl d, aclexplode(d.defaclacl) a
  where d.defaclrole = 'postgres'::regrole
    and d.defaclnamespace = 'public'::regnamespace
    and d.defaclobjtype = 'r'
    and a.grantee in ('anon'::regrole, 'authenticated'::regrole)
    and a.privilege_type in ('TRUNCATE', 'REFERENCES', 'TRIGGER', 'MAINTAIN')
  group by a.grantee
),

-- Defaults set by Supabase's own admin role. A project owner cannot change these.
admin_defaults as (
  select string_agg(distinct a.grantee::regrole::text, ', ') as roles
  from pg_default_acl d, aclexplode(d.defaclacl) a
  where d.defaclrole = to_regrole('supabase_admin')
    and d.defaclnamespace = 'public'::regnamespace
    and d.defaclobjtype = 'r'
    and a.grantee in ('anon'::regrole, 'authenticated'::regrole)
  having count(*) > 0
),

-- Tables where the browser roles still hold TRUNCATE, REFERENCES or TRIGGER.
extra_tables as (
  select count(*) as n
  from tables t
  where t.relkind in ('r', 'p')
    and (has_table_privilege('anon', t.oid, 'TRUNCATE,REFERENCES,TRIGGER')
      or has_table_privilege('authenticated', t.oid, 'TRUNCATE,REFERENCES,TRIGGER'))
  having count(*) > 0
),

-- Id counters (serial columns) a role cannot use on a table it can insert into.
-- Identity columns do not need a grant, so they are left out.
sequences as (
  select format('%I.%I', sn.nspname, s.relname) as seq,
         tb.name as tbl,
         r.role
  from pg_class s
  join pg_namespace sn on sn.oid = s.relnamespace
  join pg_depend dep on dep.objid = s.oid
                    and dep.classid = 'pg_class'::regclass
                    and dep.refclassid = 'pg_class'::regclass
                    and dep.deptype = 'a'
  join tables tb on tb.oid = dep.refobjid
  cross join roles r
  where s.relkind = 'S'
    and has_table_privilege(r.role, tb.oid, 'INSERT')
    and not has_sequence_privilege(r.role, s.oid, 'USAGE')
),

-- Every function in public that a signed-out visitor can call.
functions as (
  select p.oid::regprocedure::text as name,
         p.prosecdef as definer
  from pg_proc p
  where p.pronamespace = 'public'::regnamespace
    and p.prokind in ('f', 'p')
    -- Trigger functions cannot be called through the API, so they are left out.
    and p.prorettype not in ('trigger'::regtype, 'event_trigger'::regtype)
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

  union all

  -- Rights the Data API never uses, still given to new tables.
  select 2,
         'new tables',
         e.role,
         'New tables still give ' || e.role || ' these rights: ' || e.rights || '. The Data API never uses them, but TRUNCATE skips row level security if anything runs SQL as this role.',
         'alter default privileges for role postgres in schema public revoke truncate, references, trigger'
           || case when (select has_maintain from pg) then ', maintain' else '' end
           || ' on tables from ' || e.role || ';'
  from extra_defaults e

  union all

  -- Supabase's own admin role.
  select 2,
         'new tables',
         'supabase_admin',
         'Objects Supabase''s own admin role creates in public arrive open to ' || a.roles || '. A project owner cannot change that default (permission denied). If such an object shows up in the rows here, revoke on that object directly.',
         ''
  from admin_defaults a

  union all

  -- Tables that still carry TRUNCATE, REFERENCES or TRIGGER for the browser roles.
  select 2,
         'tables (all)',
         x.n || ' tables',
         'Signed-out visitors or signed-in users hold TRUNCATE, REFERENCES or TRIGGER on these tables. The Data API never uses them, but TRUNCATE skips row level security. Revoking them does not affect the Data API.',
         'revoke truncate, references, trigger'
           || case when (select has_maintain from pg) then ', maintain' else '' end
           || ' on all tables in schema public from anon, authenticated;'
  from extra_tables x

  union all

  -- Id counters a role cannot use.
  select 1,
         'sequence',
         s.seq,
         'Inserts into ' || s.tbl || ' through the API as ' || s.role || ' will fail: it can insert into the table but cannot use this id counter (permission denied for sequence).',
         'grant usage, select on sequence ' || s.seq || ' to ' || s.role || ';'
  from sequences s
)

select level, area, object, finding, fix
from findings
order by level, area, object;
