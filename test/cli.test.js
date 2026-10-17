// The command against a real Postgres. Needs TEST_DATABASE_URL pointing at a
// database made from test/fixture.sql by test/cli.sh. Skipped without it.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const bin = fileURLToPath(new URL('../bin/supabase-grants-check.js', import.meta.url))
const url = process.env.TEST_DATABASE_URL
const run = (args, env = {}) => {
  const r = spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8', env: { ...process.env, DATABASE_URL: '', SUPABASE_DB_URL: '', GITHUB_ACTIONS: '', ...env } })
  return { code: r.status, out: r.stdout, err: r.stderr }
}
const skip = url ? false : 'TEST_DATABASE_URL not set'

test('no database given: exit 2 and says how', () => {
  const r = run([])
  assert.equal(r.code, 2)
  assert.match(r.err, /Pass --db-url, or set DATABASE_URL/)
})

test('bad options are refused before connecting', () => {
  assert.equal(run(['--db-url', 'postgres://x@127.0.0.1:1/x', '--schemas', "public'); drop table x; --"]).code, 2)
  assert.equal(run(['--db-url', 'postgres://x@127.0.0.1:1/x', '--fail-on', '7']).code, 2)
})

test('a database that cannot be reached: exit 2, not a pass', () => {
  const r = run(['--db-url', 'postgres://nobody:x@127.0.0.1:1/nothing'])
  assert.equal(r.code, 2)
  assert.match(r.err, /Could not run the check/)
})

test('the fixture has level 1 findings: exit 1, grouped output with fix lines', { skip }, () => {
  const r = run(['--db-url', url])
  assert.equal(r.code, 1, r.err)
  assert.match(r.out, /^1 {2}Look at this now \(\d+\)/m)
  assert.match(r.out, /table: public\.open_notes/)
  assert.match(r.out, /fix: /)
  assert.match(r.out, /findings? at level 1 or below\./)
})

test('DATABASE_URL works in place of --db-url', { skip }, () => {
  assert.equal(run([], { DATABASE_URL: url }).code, 1)
})

test('--json prints the rows, and --fail-on none never fails', { skip }, () => {
  const r = run(['--db-url', url, '--json', '--fail-on', 'none'])
  assert.equal(r.code, 0, r.err)
  const rows = JSON.parse(r.out)
  assert.ok(rows.length > 0)
  assert.deepEqual(Object.keys(rows[0]), ['level', 'area', 'object', 'finding', 'fix'])
})

test('--schemas reads another exposed schema', { skip }, () => {
  const plain = JSON.parse(run(['--db-url', url, '--json', '--fail-on', 'none']).out)
  assert.ok(!plain.some((r) => r.object.startsWith('api')))
  const both = JSON.parse(run(['--db-url', url, '--json', '--fail-on', 'none', '--schemas', 'public,api']).out)
  assert.ok(both.some((r) => r.object === 'api.open_api_notes' && Number(r.level) === 1))
  assert.ok(both.some((r) => r.area === 'schema' && r.object === 'api: authenticated'))
  const typo = run(['--db-url', url, '--json', '--schemas', 'public,apl'])
  assert.equal(typo.code, 1)
  assert.ok(JSON.parse(typo.out).some((r) => r.area === 'schema' && r.object === 'apl' && Number(r.level) === 1))
})

test('in GitHub Actions each failing row is an error line', { skip }, () => {
  const r = run(['--db-url', url], { GITHUB_ACTIONS: 'true' })
  assert.equal(r.code, 1)
  assert.match(r.out, /^::error title=supabase-grants-check table: public\.open_notes::/m)
})
