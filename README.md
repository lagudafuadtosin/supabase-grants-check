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
- **Tables reachable with row level security off.** Anyone with your public key can read or change them.
- **Tables your server key cannot read.**
- **Tables with row level security on and no policies.** API users see nothing. Fine if only your server uses them.
- **Views the API can reach.** Views skip row level security unless made with `security_invoker`.
- **Functions a signed-out visitor can call**, flagged hardest when they are `SECURITY DEFINER`, because those run with their owner's rights.

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

`test/run.sh` builds a small stand-in for a Supabase project in a local Postgres (the three roles, Supabase's old defaults, and one table or function for each finding), then runs the check four ways: before 30 Oct, after the change, after the suggested fix, and the same read as if today were after 30 Oct. Tested on PostgreSQL 18.

## Limits

- It only looks at the `public` schema, the one the Data API exposes by default.
- It reads defaults set by the `postgres` role, the role the SQL editor and most migrations use.
- It is a guide, not an audit. It cannot know what your app is meant to allow.

## Licence

MIT. By Fuad Laguda.
