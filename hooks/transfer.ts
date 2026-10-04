import type { VaultProfile } from '../types'

export type Bundle = {
  version: 1
  exportedAt: string
  profiles: Record<string, VaultProfile>
  secrets?: Record<string, string>
}

// .cvault = header line + base64 of `openssl enc -aes-256-cbc -pbkdf2 -iter 600000` over an envelope
// whose embedded SHA-256 detects a wrong passphrase or a tampered file.
export const HEADER = 'CLAUDE-VAULT-V1'
export const ITER = '600000'

export const isSealed = (text: string) => text.startsWith(HEADER + '\n')

export const sealedBody = (text: string) => text.slice(HEADER.length + 1).trim()

export const envelope = (bundleJson: string, digest: string) =>
  JSON.stringify({ magic: 'claude-vault', digest, bundle: bundleJson })

export const unwrap = (plain: string) => {
  const env = JSON.parse(plain) as { magic: string; digest: string; bundle: string }
  if (env.magic !== 'claude-vault') throw new Error('bad envelope')
  return env
}

export const parsePlain = (text: string): Bundle => {
  const b = JSON.parse(text) as Bundle
  if (!b || typeof b.profiles !== 'object') throw new Error('not a vault template')
  return { version: 1, exportedAt: b.exportedAt ?? '', profiles: b.profiles }
}
