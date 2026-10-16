#!/usr/bin/env node
// supabase-grants-check: runs check.sql against a database and fails on level 1.
//
//   npx supabase-grants-check --db-url postgres://...      (or DATABASE_URL)
//
// It only reads. It changes nothing.
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import pg from 'pg'

const args = process.argv.slice(2)
const valueOf = (name) => {
  const i = args.indexOf(name)
  if (i >= 0) return args[i + 1]
  const eq = args.find((a) => a.startsWith(name + '='))
  return eq ? eq.slice(name.length + 1) : undefined
}
const flag = (name) => args.includes(name)

if (flag('--help') || flag('-h')) {
  console.log(`Usage: supabase-grants-check [options]

Shows who can reach your tables and functions through the Supabase Data API,
and what changes on 30 Oct 2026. It only reads. Exit code 1 when anything is
at or below --fail-on.

  --db-url <url>      Postgres connection string. Defaults to DATABASE_URL,
                      then SUPABASE_DB_URL.
  --schemas <list>    exposed schemas, comma separated. Default: public.
  --fail-on <level>   1, 2 or 3, or none. Default: 1.
  --json              print the rows as JSON.`)
  process.exit(0)
}

const url = valueOf('--db-url') ?? process.env.DATABASE_URL ?? process.env.SUPABASE_DB_URL
if (!url) {
  console.error('No database. Pass --db-url, or set DATABASE_URL. For a local Supabase: postgres://postgres:postgres@127.0.0.1:54322/postgres')
  process.exit(2)
}

const schemas = (valueOf('--schemas') ?? 'public').split(',').map((s) => s.trim()).filter(Boolean)
if (schemas.length === 0 || !schemas.every((s) => /^[A-Za-z_][A-Za-z0-9_$]*$/.test(s))) {
  console.error('--schemas takes plain schema names, comma separated, like public,api')
  process.exit(2)
}

const failOnRaw = valueOf('--fail-on') ?? '1'
const failOn = failOnRaw === 'none' ? 0 : Number(failOnRaw)
if (![0, 1, 2, 3].includes(failOn)) {
  console.error('--fail-on takes 1, 2, 3 or none')
  process.exit(2)
}

// The same file people paste into the SQL editor, with the schema list filled in.
const marker = "from (values ('public')) v(nsp)"
let sql = readFileSync(fileURLToPath(new URL('../check.sql', import.meta.url)), 'utf8')
if (!sql.includes(marker)) {
  console.error('check.sql does not have the schema list where it is expected.')
  process.exit(2)
}
sql = sql.replace(marker, `from (values ${schemas.map((s) => `('${s}')`).join(', ')}) v(nsp)`)

const client = new pg.Client({ connectionString: url })
let rows
try {
  await client.connect()
  rows = (await client.query(sql)).rows
} catch (e) {
  console.error(`Could not run the check: ${e.message}`)
  process.exit(2)
} finally {
  await client.end().catch(() => {})
}

const failing = failOn ? rows.filter((r) => Number(r.level) <= failOn) : []

if (flag('--json')) {
  console.log(JSON.stringify(rows, null, 2))
} else {
  const names = { 1: 'Look at this now', 2: 'Check it is what you meant', 3: 'Fine' }
  for (const level of [1, 2, 3]) {
    const these = rows.filter((r) => Number(r.level) === level)
    if (these.length === 0) continue
    console.log(`\n${level}  ${names[level]} (${these.length})`)
    for (const r of these) {
      console.log(`   ${r.area}: ${r.object}`)
      console.log(`      ${r.finding}`)
      if (r.fix) console.log(`      fix: ${r.fix}`)
    }
  }
  console.log(
    !failOn
      ? `\n${rows.length} row${rows.length === 1 ? '' : 's'}. --fail-on none, so this never fails.`
      : failing.length
        ? `\n${failing.length} finding${failing.length === 1 ? '' : 's'} at level ${failOn} or below.`
        : `\nNothing at level ${failOn} or below.`,
  )
}

// In GitHub Actions each failing row is also an error on the run's summary.
if (process.env.GITHUB_ACTIONS === 'true') {
  const clean = (s) => String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A')
  for (const r of failing) console.log(`::error title=supabase-grants-check ${clean(r.area)}: ${clean(r.object)}::${clean(r.finding)}`)
}

process.exit(failing.length ? 1 : 0)
