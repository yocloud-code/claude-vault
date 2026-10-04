export type VaultMode = 'read' | 'write'

export type VaultProfile = {
  type: string
  variant?: string
  description?: string
  host?: string
  port?: number
  user?: string
  database?: string
  secrets: string[]
  env: Record<string, string>
  modes?: VaultMode[]
  note?: string
}

export type VaultGrant = { mode: VaultMode; expiresAt: number; source: 'allowlist' | 'manual' }

export type VaultView = 'list' | 'edit' | 'export' | 'import' | 'audit'

export type VaultForm = {
  original?: string
  name: string
  description: string
  type: string
  variant: string
  host: string
  port: string
  user: string
  database: string
  secrets: string
  env: string
  allow: boolean
  mode: VaultMode
  advanced: boolean
}

export type VaultImportItem = {
  name: string
  status: 'new' | 'conflict' | 'same'
  action: 'add' | 'overwrite' | 'skip' | 'rename'
  secretCount: number
  clientVars: string[]
  problems: string[]
}

export type VaultProbe = { ok: boolean; at: number; ms: number; message: string }

export type VaultUsage = { count: number; last: number }

export type VaultImportPreview = {
  file: string
  encrypted: boolean
  items: VaultImportItem[]
}

declare module 'claude-code' {
  interface PluginState {
    vault: {
      profiles: Record<string, VaultProfile>
      stored: Record<string, boolean>
      allow: Record<string, { mode: VaultMode; ttlMinutes?: number }>
      grants: Record<string, VaultGrant>
      trust: 'none' | 'trusted' | 'untrusted'
      view: VaultView
      selected: string
      form: VaultForm | null
      exportSel: string[]
      exportSecrets: boolean
      importPreview: VaultImportPreview | null
      confirmDelete: string
      notice: string
      audit: string[]
      probes: Record<string, VaultProbe>
      probing: string
      usage: Record<string, VaultUsage>
    }
  }
}
