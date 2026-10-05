import { expect, test } from 'claude-code/testing'
import { TEMPLATES, exampleFor, isSecretTemplate, namedVars, secretProblem, variantOf } from './templates'
import { selectProfiles } from './select'
import type { VaultProfile } from '../types'

const b64 = (n: number) => 'QUJD'.repeat(Math.ceil(n / 4)).slice(0, n)
const kubeconfig = (user: string) => `apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: ${b64(1200)}
    server: https://10.0.0.1:6443
  name: prod
users:
- name: admin
  user:
${user}
contexts: []
`

test('a kubeconfig with a certificate but no key is refused (truncated paste)', () => {
  const truncated = kubeconfig(`    client-certificate-data: ${b64(1500)}`)
  expect(secretProblem('kube', 'kubeconfig', truncated)).toContain('client-key-data')
  const cut = kubeconfig(`    client-certificate-data: ${b64(1500)}\n    client-key-data: ${b64(40)}`)
  expect(secretProblem('kube', 'kubeconfig', cut)).toContain('截断')
  const whole = kubeconfig(`    client-certificate-data: ${b64(1500)}\n    client-key-data: ${b64(2200)}`)
  expect(secretProblem('kube', 'kubeconfig', whole)).toBeUndefined()
  const tokenUser = kubeconfig('    token: abc.def.ghi')
  expect(secretProblem('kube', 'kubeconfig', tokenUser)).toBeUndefined()
  expect(secretProblem('kube', 'kubeconfig', 'just some text')).toContain('clusters')
})

test('a private key without its end line is refused', () => {
  const key = `-----BEGIN OPENSSH PRIVATE KEY-----\n${b64(400)}\n-----END OPENSSH PRIVATE KEY-----\n`
  expect(secretProblem('ssh', 'key', key)).toBeUndefined()
  expect(secretProblem('ssh', 'key', key.slice(0, 200))).toContain('END')
  expect(secretProblem('ssh', 'password', 'anything')).toBeUndefined()
})

test('supabase: a login token per profile, injected only when referenced', () => {
  expect(TEMPLATES.supabase.variants[0].secrets.map(s => s.name)).toEqual(['password', 'anon_key'])
  const p: VaultProfile = { type: 'supabase', host: 'https://x.supabase.co', user: 'a@b.test', secrets: ['password', 'anon_key'], env: { ...variantOf('supabase').env } }
  expect(Object.keys(namedVars('ops3-accountant', p))).toEqual([
    'OPS3_ACCOUNTANT_URL', 'OPS3_ACCOUNTANT_EMAIL', 'OPS3_ACCOUNTANT_PASSWORD', 'OPS3_ACCOUNTANT_ANON_KEY', 'OPS3_ACCOUNTANT_TOKEN',
  ])
  expect(isSecretTemplate('{supabase_token}')).toBe(true)
  expect(isSecretTemplate('{host}')).toBe(false)
  // two roles in one command: each brings its own token, nothing collides
  const profiles = { 'ops3-accountant': p, 'ops3-finance': { ...p, user: 'f@b.test' } }
  const r = selectProfiles('curl -H "Authorization: Bearer $OPS3_ACCOUNTANT_TOKEN" x && curl -H "Authorization: Bearer $OPS3_FINANCE_TOKEN" y',
    profiles, new Set(Object.keys(profiles)))
  const picks = 'deny' in r ? {} : Object.fromEntries([...r.picks].map(([n, v]) => [n, Object.keys(v).sort()]))
  expect(picks).toEqual({
    'ops3-accountant': ['OPS3_ACCOUNTANT_EMAIL', 'OPS3_ACCOUNTANT_TOKEN', 'OPS3_ACCOUNTANT_URL'],
    'ops3-finance': ['OPS3_FINANCE_EMAIL', 'OPS3_FINANCE_TOKEN', 'OPS3_FINANCE_URL'],
  })
  expect(exampleFor(variantOf('supabase').example, 'ops3-finance')).toContain('Bearer $OPS3_FINANCE_TOKEN')
  expect(secretProblem('supabase', 'anon_key', 'not-a-key')).toBeDefined()
  expect(secretProblem('supabase', 'anon_key', 'eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.c2lnbmF0dXJl')).toBeUndefined()
})

test('valid kubeconfigs are accepted: quoted values and the JSON form', () => {
  const k = b64(2200)
  const quoted = kubeconfig(`    client-certificate-data: "${b64(1500)}"\n    client-key-data: "${k}"`)
  expect(secretProblem('kube', 'kubeconfig', quoted)).toBeUndefined()
  const json = JSON.stringify({ apiVersion: 'v1', clusters: [{ name: 'a' }], users: [{ name: 'u', user: { 'client-certificate-data': b64(1500), 'client-key-data': k } }] })
  expect(secretProblem('kube', 'kubeconfig', json)).toBeUndefined()
  const jsonCut = JSON.stringify({ apiVersion: 'v1', clusters: [{ name: 'a' }], users: [{ name: 'u', user: { 'client-certificate-data': b64(1500) } }] })
  expect(secretProblem('kube', 'kubeconfig', jsonCut)).toContain('client-key-data')
})
