# supabase-grants-check

One SQL file you paste into the Supabase SQL editor. It reads your project and shows, in one table, who can reach your tables and functions through the API, and what changes for you on 30 Oct 2026. It changes nothing.

## What changes on 30 Oct 2026

Until now, every new table you made in the `public` schema was handed to the three API roles automatically:

- `anon`: anyone with your public key, signed out
- `authenticated`: your signed-in users
- `service_role`: your server key

Supabase is ending that. It became the default for new projects on 30 May 2026, and on **30 Oct 2026** it applies to every existing project. After that date a new table is closed to the Data API until a migration grants it. The app gets `permission denied for table` (error `42501`).

What does not change: tables that exist on that date keep their grants, and row level security works as before. Supabase's notice: [changelog 45329](https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically).

The one most people will miss: **your server key**. If your backend, Edge Function or Worker reads tables with the service role, the next new table it touches will fail too.

## How to use it

1. Open your project in Supabase, then **SQL Editor**.
2. Paste all of [`check.sql`](check.sql) and press **Run**.
3. Read the table. Sort by `level`.

| level | meaning |
|---|---|
| 1 | Look at this now |
| 2 | Check it is what you meant |
| 3 | Fine |

The `fix` column holds the exact line to paste **if** you decide to change something. Nothing is run for you. Some fixes close things your app may rely on, so read each one first.

## What it checks

- **New tables.** Which of the three roles gets every new table automatically, today and after 30 Oct.
- **New id counters.** Supabase's change also stops handing new sequences to the three roles. A role that gets new tables but not new sequences fails on the first insert into a new table with a `serial` column. Flagged as level 1 with the one default-privileges line that fixes it.
- **Tables reachable with row level security off.** Anyone with your public key can read or change them.
- **Tables your server key cannot read.**
- **Tables with row level security on and no policies.** API users see nothing. Fine if only your server uses them.
- **Views the API can reach.** A view runs as its owner unless it was made with `security_invoker` (Postgres 15 or newer), so a view over a table with row level security shows every row. The check walks each view down to the tables it reads, through any views under it, and flags the ones that skip row level security, with the `alter view` line to fix it. A materialized view holds a copy of the rows and cannot follow row level security, so it is flagged with a revoke. It also warns when a `security_invoker` view is open to a role that has no rights on the table underneath, because reads through it then fail with `permission denied`.
- **Functions a signed-out visitor can call**, flagged hardest when they are `SECURITY DEFINER`, because those run with their owner's rights. Trigger functions are left out, because the API cannot call them.
- **Id counters that will refuse inserts.** A `serial` column has its own sequence, and a table grant does not cover it. If a role can insert into the table but cannot use the sequence, inserts through the API fail with `permission denied for sequence`. Identity columns need no grant and are left out.
- **Rights the Data API never uses.** Supabase's old defaults give `anon` and `authenticated` TRUNCATE, REFERENCES and TRIGGER (and MAINTAIN on Postgres 17) on every table. The API never uses them, but TRUNCATE skips row level security if anything runs SQL as those roles. Shown as one row with one safe revoke.
- **Supabase's own admin role.** Objects that `supabase_admin` creates in `public` arrive open to `anon` and `authenticated`, and a project owner cannot change that default. The check tells you when that default exists.

## The fix most projects need

If your server reads tables with the service role, run this once:

```sql
alter default privileges for role postgres in schema public
  grant select, insert, update, delete on tables to service_role;
alter default privileges for role postgres in schema public
  grant usage, select on sequences to service_role;
```

It changes nothing today, because Supabase already does this by default. It keeps your server working on tables you add after 30 Oct. Run the check again after 30 Oct to make sure it is still in place.

For signed-in users and signed-out visitors, the safer habit is to grant each new table in the migration that makes it, with row level security on:

```sql
create table public.notes (...);
alter table public.notes enable row level security;
create policy ... on public.notes ...;
grant select, insert, update, delete on table public.notes to authenticated;
```

## Tested

`test/run.sh` builds a small stand-in for a Supabase project in a local Postgres (the three roles, Supabase's old defaults, and one table or function for each finding), then runs the check six ways: before 30 Oct, after the change (table and sequence defaults removed), after the table half of the suggested fix (the id counter row must appear), the same read as if today were after 30 Oct, and after running the other fix lines it prints, to prove their rows go away, and once with a second schema in the list, whose open table must then appear. Tested on PostgreSQL 18, and run read-only on a live Supabase project.

## Limits

- It reads the `public` schema, the one the Data API exposes by default. If you added schemas to the exposed list (Project Settings > Data API), add them to the `schemas` list at the top of `check.sql`. The exposed list itself cannot be read from SQL, so it is typed by hand. Rows for another schema name it in the `object` column, and every fix line names its schema.
- It reads defaults set by the `postgres` role, the role the SQL editor and most migrations use, and only reports the `supabase_admin` defaults, because they cannot be changed from the SQL editor.
- It is a guide, not an audit. It cannot know what your app is meant to allow.

## Licence

MIT. By Fuad Laguda.
