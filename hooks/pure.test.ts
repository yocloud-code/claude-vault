import { expect, test } from 'claude-code/testing'
import { envelope, isSealed, parsePlain, sealedBody, unwrap } from './transfer'
import { hasSecrets, redact, remember } from './redact'
import { dumpReason, peekReason, writeReason } from './guard'
import { TEMPLATES, isDefaultMapping, missingFields, parseEnv } from './templates'

const pg = { type: 'postgres', secrets: [], env: {} }

test('envelope parsing', () => {
  const env = unwrap(envelope('{"version":1}', 'abc'))
  expect(env.digest).toBe('abc')
  expect(isSealed('CLAUDE-VAULT-V1\nU2Fs\n')).toBe(true)
  expect(sealedBody('CLAUDE-VAULT-V1\nU2Fs\n')).toBe('U2Fs')
  expect(parsePlain('{"profiles":{"a":{"type":"x","secrets":[],"env":{}}}}').profiles.a.type).toBe('x')
})

test('redaction masks raw, base64 and url-encoded forms', () => {
  remember('a.password', 'S3cr3t-Value!')
  const out = redact(`pw=S3cr3t-Value! b64=${btoa('S3cr3t-Value!')} url=${encodeURIComponent('S3cr3t-Value!')}`)
  expect(out).toBe('pw=«vault:a.password» b64=«vault:a.password» url=«vault:a.password»')
  expect(hasSecrets('nothing here')).toBe(false)
})

test('templates', () => {
  expect(missingFields('postgres', { host: '', port: '', user: 'u', database: '' })).toEqual(['主机'])
  expect(missingFields('kube', { host: '', port: '', user: '', database: '' })).toEqual([])
  expect(isDefaultMapping({ type: 'ssh', variant: 'key', secrets: ['key'], env: { ...TEMPLATES.ssh.variants[0].env } })).toBe(true)
  expect(isDefaultMapping({ type: 'ssh', variant: 'key', secrets: ['key'], env: { X: '1' } })).toBe(false)
  expect(isDefaultMapping({ type: 'ssh', variant: 'password', secrets: ['password'], env: { ...TEMPLATES.ssh.variants[1].env } })).toBe(true)
  expect(parseEnv('A={host}; B = {secret:x}')).toEqual({ A: '{host}', B: '{secret:x}' })
})

test('guards', () => {
  expect(peekReason('security find-generic-password -s claude-vault -w')).toBeDefined()
  expect(peekReason('cat ~/.claude/vault/profiles.json')).toBeDefined()
  expect(peekReason('psql -c "select 1"')).toBeUndefined()
  expect(peekReason('cat .claude/vault.json')).toBeUndefined()
  expect(peekReason('ls ~/.claude/vault')).toBeDefined()
  expect(peekReason('cp backup-claude-vault-1.cvault /tmp')).toBeUndefined()
  expect(writeReason(pg, 'psql -c "drop table x"')).toBeDefined()
  expect(writeReason(pg, 'psql -c "select 1"')).toBeUndefined()
  expect(dumpReason('env | grep PG')).toBeDefined()
  expect(dumpReason('psql -c "select 1"')).toBeUndefined()
})
