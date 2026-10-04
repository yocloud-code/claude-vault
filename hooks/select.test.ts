import { expect, test } from 'claude-code/testing'
import { TEMPLATES, exampleFor, namedVars, prefixOf, variantOf } from './templates'
import { namedClash, selectProfiles } from './select'
import type { VaultProfile } from '../types'

const pg = (host: string): VaultProfile => ({ type: 'postgres', host, user: 'ro', secrets: ['password'], env: { ...variantOf('postgres').env } })
const kube = (): VaultProfile => ({ type: 'kube', database: 'apps', secrets: ['kubeconfig'], env: { ...variantOf('kube').env } })
const sshPw = (): VaultProfile => ({ type: 'ssh', variant: 'password', host: 'h', user: 'u', port: 22, secrets: ['password'], env: { ...variantOf('ssh', 'password').env } })
const profiles = { 'staging-db': pg('s'), 'prod-db': pg('p'), k8s: kube(), bastion: sshPw() }

const picks = (cmd: string, granted: string[]) => {
  const r = selectProfiles(cmd, profiles, new Set(granted))
  return 'deny' in r ? { deny: r.deny } : Object.fromEntries([...r.picks].map(([n, v]) => [n, Object.keys(v).sort()]))
}

test('variables are named after the profile', () => {
  expect(Object.keys(namedVars('prod-db', profiles['prod-db']))).toEqual(['PROD_DB_HOST', 'PROD_DB_USER', 'PROD_DB_PASSWORD'])
  expect(Object.keys(namedVars('k8s', profiles.k8s))).toEqual(['K8S_NAMESPACE', 'K8S_KUBECONFIG_FILE'])
  expect(prefixOf('prod-db')).toBe('PROD_DB')
  expect(exampleFor(variantOf('kube').example, 'k8s')).toBe('kubectl -n "${K8S_NAMESPACE:-default}" get pods')
})

test('implicit use picks by the profile\'s own variables, never conflicting', () => {
  expect(picks(`pg_dump -h "$PROD_DB_HOST" | PGPASSWORD="$STAGING_DB_PASSWORD" psql`, ['staging-db', 'prod-db'])).toEqual({
    'prod-db': ['PROD_DB_HOST', 'PROD_DB_USER'],
    'staging-db': ['STAGING_DB_HOST', 'STAGING_DB_PASSWORD', 'STAGING_DB_USER'],
  })
})

test('client variables are never injected implicitly', () => {
  expect(picks(`psql "$PGPASSWORD"`, ['staging-db', 'prod-db'])).toEqual({})
})

test('#vault: brings the client variables too', () => {
  expect(picks(`#vault:prod-db\npsql -c 'select 1'`, ['staging-db', 'prod-db'])).toEqual({
    'prod-db': ['PGDATABASE', 'PGHOST', 'PGPASSWORD', 'PGPORT', 'PGUSER', 'PROD_DB_HOST', 'PROD_DB_PASSWORD', 'PROD_DB_USER'],
  })
  expect(picks(`#vault:bastion\nssh u@h uptime`, ['bastion']).bastion).toContain('SSH_ASKPASS')
})

test('#vault: with two profiles of one client is refused; different clients are fine', () => {
  const r = picks(`#vault:staging-db,prod-db\npsql`, ['staging-db', 'prod-db'])
  expect('deny' in r && String(r.deny)).toContain('PGHOST')
  expect(Object.keys(picks(`#vault:staging-db,k8s\nkubectl get pods`, ['staging-db', 'k8s'])).sort()).toEqual(['k8s', 'staging-db'])
})

test('ungranted profiles are refused when named or referenced, unrelated variables left alone', () => {
  expect('deny' in picks(`#vault:prod-db\npsql`, ['staging-db'])).toBe(true)
  expect('deny' in picks(`#vault:nope\nls`, ['staging-db'])).toBe(true)
  expect('deny' in picks(`echo $PROD_DB_PASSWORD`, ['staging-db'])).toBe(true)
  expect(picks(`echo $HOME`, [])).toEqual({})
})

test('named variable clashes are detected', () => {
  const prod: VaultProfile = { type: 'custom', secrets: ['db_password'], env: {} }
  expect(namedClash('prod', prod, profiles)?.variable).toBe('PROD_DB_PASSWORD')
  expect(namedClash('qa-db', pg('q'), profiles)).toBeUndefined()
})

test('every template has a usable first variant', () => {
  for (const t of Object.values(TEMPLATES)) expect(t.variants.length).toBeGreaterThan(0)
  expect(TEMPLATES.ssh.variants.map(v => v.key)).toEqual(['key', 'password'])
})

test('directory grants apply to the directory and everything under it, nearest wins', async () => {
  const { effectiveGrants } = await import('./select')
  const all = {
    '/w': { a: { mode: 'read' as const, at: 1 }, b: { mode: 'read' as const, at: 1 } },
    '/w/proj': { b: { mode: 'write' as const, at: 2 } },
    '/other': { c: { mode: 'read' as const, at: 3 } },
    '/': { root: { mode: 'read' as const, at: 4 } },
  }
  const here = effectiveGrants(all, '/w/proj/src')
  expect(Object.keys(here).sort()).toEqual(['a', 'b', 'root'])
  expect(here.b).toEqual({ mode: 'write', dir: '/w/proj', at: 2 })
  expect(here.a.dir).toBe('/w')
  // a sibling whose name merely starts the same is not underneath
  expect(Object.keys(effectiveGrants(all, '/w2'))).toEqual(['root'])
  expect(Object.keys(effectiveGrants(all, '/w')).sort()).toEqual(['a', 'b', 'root'])
})
