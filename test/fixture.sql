-- A small stand-in for a Supabase project: the three API roles, Supabase's old defaults,
-- and one table or function for each finding the check can make.
create role anon nologin;
create role authenticated nologin;
create role service_role nologin bypassrls;
create role supabase_admin nologin;

-- Supabase's defaults before 30 Oct 2026: every new public table goes to all three roles.
alter default privileges for role postgres in schema public grant all on tables to anon, authenticated, service_role;
alter default privileges for role postgres in schema public grant all on sequences to anon, authenticated, service_role;
alter default privileges for role postgres in schema public grant all on functions to anon, authenticated, service_role;
-- Supabase's own admin role keeps its own defaults, which a project owner cannot change.
alter default privileges for role supabase_admin in schema public grant all on tables to anon, authenticated, service_role;

create table public.open_notes (id serial primary key, body text);            -- row security off: level 1
create table public.profiles (id serial primary key, owner uuid);              -- row security on, one policy: fine
alter table public.profiles enable row level security;
create policy own on public.profiles for select to authenticated using (true);
create table public.server_only (id serial primary key, secret text);         -- row security on, no policy: level 2
alter table public.server_only enable row level security;
create table public.locked_from_server (id serial primary key);               -- server cannot read: level 2
alter table public.locked_from_server enable row level security;
create policy anyone on public.locked_from_server for select to authenticated using (true);
revoke all on public.locked_from_server from service_role;
create table public.orders (id serial primary key, item text);               -- signed-in users can insert but not use the id counter: level 1
alter table public.orders enable row level security;
create policy mine on public.orders for insert to authenticated with check (true);
revoke all on sequence public.orders_id_seq from authenticated;
create table public.events (id int generated always as identity, kind text);  -- identity column: needs no counter grant, never flagged
alter table public.events enable row level security;
create policy see on public.events for select to authenticated using (true);
create view public.all_notes as select * from public.open_notes;              -- view: level 3 note

create function public.add_credits(n int) returns int language sql security definer as 'select n';  -- level 1
create function public.stamp() returns trigger language plpgsql as 'begin return new; end';  -- trigger function: never flagged
create function public.hello() returns text language sql as 'select ''hi''';                         -- level 2
