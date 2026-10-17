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
--
-- It reads the public schema. If you added schemas to the Data API's exposed
-- list (Project Settings > Data API), add them here, the same way:
--   values ('public'), ('api')
-- Supabase keeps that list outside the database, so it cannot be read from SQL.
-- A schema in the list that does not exist is flagged, in case the name is mistyped.
-- Rows for a schema other than public say which one in the object column.

with recursive
listed(nsp) as (
  select v.nsp
  from (values ('public')) v(nsp)
),
schemas(nsp) as (
  select l.nsp
  from listed l
  where exists (select 1 from pg_namespace n where n.nspname = l.nsp)
),
roles(role) as (
  values ('anon'), ('authenticated'), ('service_role')
),

-- Who gets new tables and new id counters (sequences) in public automatically
-- (default privileges set by postgres). Supabase's change removes both.
defaults as (
  select sc.nsp,
         r.role,
         case when sc.nsp = 'public' then r.role else sc.nsp || ': ' || r.role end as label,
         exists (
           select 1
           from pg_default_acl d, aclexplode(d.defaclacl) a
           where d.defaclrole = 'postgres'::regrole
             and d.defaclnamespace = sc.nsp::regnamespace
             and d.defaclobjtype = 'r'
             and a.grantee = r.role::regrole
             and a.privilege_type = 'SELECT'
         ) as gets_new_tables,
         exists (
           select 1
           from pg_default_acl d, aclexplode(d.defaclacl) a
           where d.defaclrole = 'postgres'::regrole
             and d.defaclnamespace = sc.nsp::regnamespace
             and d.defaclobjtype = 'S'
             and a.grantee = r.role::regrole
             and a.privilege_type = 'USAGE'
         ) as gets_new_sequences,
         exists (
           select 1
           from pg_default_acl d, aclexplode(d.defaclacl) a
           where d.defaclrole = 'postgres'::regrole
             and d.defaclnamespace = sc.nsp::regnamespace
             and d.defaclobjtype = 'f'
             and a.grantee = r.role::regrole
             and a.privilege_type = 'EXECUTE'
         ) as gets_new_functions,
         -- Postgres gives new functions to PUBLIC, which every role is in, unless a
         -- database-wide default for postgres takes it away. A per-schema one cannot.
         not exists (
           select 1
           from pg_default_acl d
           where d.defaclrole = 'postgres'::regrole
             and d.defaclnamespace = 0
             and d.defaclobjtype = 'f'
             and not exists (select 1 from aclexplode(d.defaclacl) a where a.grantee = 0 and a.privilege_type = 'EXECUTE')
         ) as public_gets_new_functions
  from schemas sc
  cross join roles r
),

-- Every table and view the Data API can see in public.
tables as (
  select c.oid,
         format('%I.%I', n.nspname, c.relname) as name,
         c.relkind,
         c.relrowsecurity as rls,
         (select count(*) from pg_policy p where p.polrelid = c.oid) as policies,
         -- any-column: a grant on single columns still reaches the Data API
         (has_any_column_privilege('anon', c.oid, 'SELECT,INSERT,UPDATE') or has_table_privilege('anon', c.oid, 'DELETE')) as anon_any,
         (has_any_column_privilege('authenticated', c.oid, 'SELECT,INSERT,UPDATE') or has_table_privilege('authenticated', c.oid, 'DELETE')) as auth_any,
         has_any_column_privilege('service_role', c.oid, 'SELECT') as server_reads,
         -- a view runs as its owner unless made with security_invoker (Postgres 15+)
         (c.relkind = 'v' and exists (select 1 from unnest(c.reloptions) o
                                      where o ~* '^security_invoker=(on|true|t|yes|y|1)$')) as invoker
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname in (select nsp from schemas)
    and c.relkind in ('r', 'p', 'v', 'm')
    and not exists (select 1 from pg_depend dep where dep.objid = c.oid and dep.deptype = 'e')
),

-- Postgres 17 added a MAINTAIN right next to TRUNCATE, REFERENCES and TRIGGER.
pg as (
  select current_setting('server_version_num')::int >= 170000 as has_maintain,
         current_setting('server_version_num')::int >= 150000 as has_invoker
),

-- A role needs USAGE on a schema before any table grant in it works.
schema_usage as (
  select sc.nsp,
         r.role,
         case when sc.nsp = 'public' then r.role else sc.nsp || ': ' || r.role end as label,
         has_schema_privilege(r.role, sc.nsp, 'USAGE') as usage,
         exists (
           select 1
           from pg_class c
           join pg_namespace n on n.oid = c.relnamespace
           where n.nspname = sc.nsp
             and c.relkind in ('r', 'p', 'v', 'm')
             and (has_any_column_privilege(r.role, c.oid, 'SELECT,INSERT,UPDATE')
                  or has_table_privilege(r.role, c.oid, 'DELETE'))
         ) as has_grants
  from schemas sc
  cross join roles r
),

-- Walk from each view down to the tables it reads, through views under it.
-- skipping = a view on the way down runs as its owner, so row level security
-- on the tables below it does not apply to the caller.
view_walk(view_oid, rel_oid, skipping) as (
  select t.oid, t.oid, not t.invoker
  from tables t
  where t.relkind in ('v', 'm')
  union
  select w.view_oid,
         d.refobjid,
         w.skipping or (c.relkind in ('v', 'm')
                        and not (c.relkind = 'v' and exists (select 1 from unnest(c.reloptions) o
                                                             where o ~* '^security_invoker=(on|true|t|yes|y|1)$')))
  from view_walk w
  join pg_rewrite r on r.ev_class = w.rel_oid
  join pg_depend d on d.objid = r.oid
                  and d.classid = 'pg_rewrite'::regclass
                  and d.refclassid = 'pg_class'::regclass
                  and d.refobjid <> w.rel_oid
  join pg_class c on c.oid = d.refobjid
),

-- For each view: the tables with row level security that it reads around.
view_rls as (
  select w.view_oid,
         string_agg(format('%I.%I', n.nspname, c.relname), ', ' order by c.relname) as tables
  from view_walk w
  join pg_class c on c.oid = w.rel_oid
  join pg_namespace n on n.oid = c.relnamespace
  where w.skipping
    and c.relkind in ('r', 'p')
    and c.relrowsecurity
  group by w.view_oid
),

-- Views that run as the caller, reachable by a browser role that lacks rights
-- on something the view reads directly. Reads through the view fail for that role.
view_needs as (
  select t.name as view_name,
         r.role,
         string_agg(distinct format('%I.%I', n.nspname, c.relname), ', ') as tables
  from tables t
  join roles r on r.role in ('anon', 'authenticated')
             and ((r.role = 'anon' and t.anon_any) or (r.role = 'authenticated' and t.auth_any))
  join pg_rewrite rw on rw.ev_class = t.oid
  join pg_depend d on d.objid = rw.oid
                  and d.classid = 'pg_rewrite'::regclass
                  and d.refclassid = 'pg_class'::regclass
                  and d.refobjid <> t.oid
  join pg_class c on c.oid = d.refobjid and c.relkind in ('r', 'p', 'v', 'm')
  join pg_namespace n on n.oid = c.relnamespace
  where t.invoker
    and not has_any_column_privilege(r.role, c.oid, 'SELECT')
  group by t.name, r.role
),

-- Rights beyond read and write that new tables still give the browser roles.
extra_defaults as (
  select sc.nsp,
         a.grantee::regrole::text as role,
         string_agg(distinct lower(a.privilege_type), ', ') as rights
  from schemas sc, pg_default_acl d, aclexplode(d.defaclacl) a
  where d.defaclrole = 'postgres'::regrole
    and d.defaclnamespace = sc.nsp::regnamespace
    and d.defaclobjtype = 'r'
    and a.grantee in ('anon'::regrole, 'authenticated'::regrole)
    and a.privilege_type in ('TRUNCATE', 'REFERENCES', 'TRIGGER', 'MAINTAIN')
  group by sc.nsp, a.grantee
),

-- Defaults set by Supabase's own admin role. A project owner cannot change these.
admin_defaults as (
  select sc.nsp,
         string_agg(distinct a.grantee::regrole::text, ', ') as roles
  from schemas sc, pg_default_acl d, aclexplode(d.defaclacl) a
  where d.defaclrole = to_regrole('supabase_admin')
    and d.defaclnamespace = sc.nsp::regnamespace
    and d.defaclobjtype = 'r'
    and a.grantee in ('anon'::regrole, 'authenticated'::regrole)
  group by sc.nsp
  having count(*) > 0
),

-- Tables where the browser roles still hold TRUNCATE, REFERENCES or TRIGGER.
extra_tables as (
  select split_part(t.name, '.', 1) as nsp,
         count(*) as n
  from tables t
  where t.relkind in ('r', 'p')
    and (has_table_privilege('anon', t.oid, 'TRUNCATE,REFERENCES,TRIGGER')
      or has_table_privilege('authenticated', t.oid, 'TRUNCATE,REFERENCES,TRIGGER'))
  group by split_part(t.name, '.', 1)
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
    and has_any_column_privilege(r.role, tb.oid, 'INSERT')
    and not has_sequence_privilege(r.role, s.oid, 'USAGE')
),

-- Every function in public that a signed-out visitor can call.
functions as (
  select p.oid::regprocedure::text as name,
         p.prosecdef as definer
  from pg_proc p
  where p.pronamespace in (select nsp::regnamespace from schemas)
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
         d.label,
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
              then 'alter default privileges for role postgres in schema ' || d.nsp || ' grant select, insert, update, delete on tables to service_role; alter default privileges for role postgres in schema ' || d.nsp || ' grant usage, select on sequences to service_role;'
              when d.gets_new_tables and current_date < date '2026-10-30'
              then 'grant select, insert, update, delete on table ' || d.nsp || '.<new_table> to ' || d.role || ';  -- in each new table''s migration'
              else '' end
  from defaults d

  union all

  -- New tables yes, their id counters no. A serial column has its own sequence,
  -- and the table default does not cover it.
  select 1,
         'new tables',
         d.label,
         d.role || ' gets every new table automatically, but not its id counters. The first insert into a new table with a serial column fails with permission denied for sequence. Identity columns are not affected.',
         'alter default privileges for role postgres in schema ' || d.nsp || ' grant usage, select on sequences to ' || d.role || ';'
  from defaults d
  where d.gets_new_tables and not d.gets_new_sequences

  union all

  -- New functions. Supabase's change leaves this default alone, so every new
  -- function is callable through the API by these roles the moment it exists.
  select 2,
         'new functions',
         d.label,
         d.role || ' gets every new function automatically' || case when d.gets_new_functions then '' else ', through PUBLIC, which every role is in' end || ', and the 30 Oct 2026 change does not stop this. Every function you add is callable through the API by ' || d.role || ' until you revoke it.',
         concat_ws(' ',
           case when d.gets_new_functions then 'alter default privileges for role postgres in schema ' || d.nsp || ' revoke execute on functions from ' || d.role || ';' end,
           case when d.public_gets_new_functions then 'alter default privileges for role postgres revoke execute on functions from public;' end)
         || '  -- then grant execute in each function''s migration'
  from defaults d
  where d.role in ('anon', 'authenticated') and (d.gets_new_functions or d.public_gets_new_functions)

  union all

  -- A listed schema the role cannot enter. Its table grants do nothing until then.
  select case when u.has_grants then 1 else 2 end,
         'schema',
         u.label,
         case when u.has_grants
              then u.role || ' has grants on tables in ' || u.nsp || ' but no USAGE on the schema, so every request from it fails with permission denied for schema ' || u.nsp || '.'
              else u.role || ' has no USAGE on schema ' || u.nsp || ', so nothing in it is reachable by that role. Fine if that is what you meant.' end,
         'grant usage on schema ' || u.nsp || ' to ' || u.role || ';'
  from schema_usage u
  where not u.usage

  union all

  -- A listed schema that does not exist. Nothing in it was checked, so a typo would pass quietly.
  select 1,
         'schema',
         l.nsp,
         'Schema ' || l.nsp || ' is in the list but does not exist, so nothing in it was checked. Compare the name with Project Settings > Data API.',
         '-- correct the name in the schemas list at the top (or in --schemas)'
  from listed l
  where not exists (select 1 from pg_namespace n where n.nspname = l.nsp)

  union all

  -- Tables and views.
  select case when not t.rls and t.relkind in ('r', 'p') and (t.anon_any or t.auth_any) then 1
              when t.relkind in ('v', 'm') and (t.anon_any or t.auth_any) and v.tables is not null then 1
              when not t.server_reads then 2
              when t.rls and t.policies = 0 and (t.anon_any or t.auth_any) then 2
              when t.relkind in ('v', 'm') and (t.anon_any or t.auth_any) and not t.invoker then 2
              else 3 end,
         case when t.relkind in ('v', 'm') then 'view' else 'table' end,
         t.name,
         case when not t.rls and t.relkind in ('r', 'p') and (t.anon_any or t.auth_any)
              then 'Reachable through the API by ' || concat_ws(' and ', case when t.anon_any then 'signed-out visitors' end, case when t.auth_any then 'signed-in users' end) || ', with row level security OFF. Anyone with your public key can read or change every row they have rights to.'
              when t.relkind = 'm' and (t.anon_any or t.auth_any) and v.tables is not null
              then 'Reachable through the API by ' || concat_ws(' and ', case when t.anon_any then 'signed-out visitors' end, case when t.auth_any then 'signed-in users' end) || '. A materialized view holds a copy of the rows, taken with its owner''s rights, so row level security on ' || v.tables || ' does not apply. Every row shows.'
              when t.relkind = 'v' and (t.anon_any or t.auth_any) and v.tables is not null
              then 'Reachable through the API by ' || concat_ws(' and ', case when t.anon_any then 'signed-out visitors' end, case when t.auth_any then 'signed-in users' end) || '. It runs as its owner, not as the caller, so it skips row level security on ' || v.tables || '. Every row of those tables shows.'
              when not t.server_reads
              then 'Your server key cannot read it. Fine if nothing on the server uses it.'
              when t.rls and t.policies = 0 and (t.anon_any or t.auth_any)
              then 'Row level security is on with no policies, so API users see nothing. Fine if only the server uses it.'
              when t.relkind in ('v', 'm') and (t.anon_any or t.auth_any) and not t.invoker
              then 'Reachable through the API, running as its owner. The tables it reads have row level security off, so it shows every row of them. Fine if that is meant to be public.'
              else 'OK' end,
         case when not t.rls and t.relkind in ('r', 'p') and (t.anon_any or t.auth_any)
              then 'alter table ' || t.name || ' enable row level security;  -- then add policies for what the app needs, or: revoke all on table ' || t.name || ' from anon, authenticated;'
              when t.relkind = 'm' and (t.anon_any or t.auth_any) and v.tables is not null
              then 'revoke all on table ' || t.name || ' from anon, authenticated;  -- a materialized view cannot follow row level security'
              when t.relkind = 'v' and (t.anon_any or t.auth_any) and v.tables is not null and (select has_invoker from pg)
              then 'alter view ' || t.name || ' set (security_invoker = true);  -- then the caller needs rights on the tables it reads; views under it need the same'
              when t.relkind = 'v' and (t.anon_any or t.auth_any) and v.tables is not null
              then 'revoke all on table ' || t.name || ' from anon, authenticated;  -- security_invoker needs Postgres 15 or newer'
              when not t.server_reads
              then 'grant select, insert, update, delete on table ' || t.name || ' to service_role;'
              when t.relkind = 'v' and (t.anon_any or t.auth_any) and not t.invoker and (select has_invoker from pg)
              then 'alter view ' || t.name || ' set (security_invoker = true);  -- so it follows row level security once that is on'
              else '' end
  from tables t
  left join view_rls v on v.view_oid = t.oid

  union all

  -- Views that run as the caller, where the caller lacks rights on what the view reads.
  select 2,
         'view',
         n.view_name,
         'Reads through this view as ' || n.role || ' will fail (permission denied): it runs as the caller, and ' || n.role || ' has no rights on ' || n.tables || '.',
         'grant select on table ' || n.tables || ' to ' || n.role || ';  -- with row level security on, the policies decide the rows'
  from view_needs n

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
         case when e.nsp = 'public' then e.role else e.nsp || ': ' || e.role end,
         'New tables still give ' || e.role || ' these rights: ' || e.rights || '. The Data API never uses them, but TRUNCATE skips row level security if anything runs SQL as this role.',
         'alter default privileges for role postgres in schema ' || e.nsp || ' revoke truncate, references, trigger'
           || case when (select has_maintain from pg) then ', maintain' else '' end
           || ' on tables from ' || e.role || ';'
  from extra_defaults e

  union all

  -- Supabase's own admin role.
  select 2,
         'new tables',
         case when a.nsp = 'public' then 'supabase_admin' else a.nsp || ': supabase_admin' end,
         'Objects Supabase''s own admin role creates in ' || a.nsp || ' arrive open to ' || a.roles || '. A project owner cannot change that default (permission denied). If such an object shows up in the rows here, revoke on that object directly.',
         ''
  from admin_defaults a

  union all

  -- Tables that still carry TRUNCATE, REFERENCES or TRIGGER for the browser roles.
  select 2,
         'tables (all)',
         x.n || ' tables' || case when x.nsp = 'public' then '' else ' in ' || x.nsp end,
         'Signed-out visitors or signed-in users hold TRUNCATE, REFERENCES or TRIGGER on these tables. The Data API never uses them, but TRUNCATE skips row level security. Revoking them does not affect the Data API.',
         'revoke truncate, references, trigger'
           || case when (select has_maintain from pg) then ', maintain' else '' end
           || ' on all tables in schema ' || x.nsp || ' from anon, authenticated;'
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

-- Aliased on purpose: the Supabase SQL editor's row limit rewrite breaks the plain form.
select f.level, f.area, f.object, f.finding, f.fix
from findings f
order by f.level, f.area, f.object;
