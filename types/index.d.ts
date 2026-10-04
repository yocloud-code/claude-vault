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

/** A profile granted to a directory and everything under it, until revoked. */
export type VaultGrant = { mode: VaultMode; dir: string; at: number }

/** Grants by directory (real path), then by profile name. */
export type VaultDirGrants = Record<string, Record<string, { mode: VaultMode; at: number }>>

export type VaultView = 'list' | 'edit' | 'export' | 'import' | 'audit' | 'cleanup' | 'grants'

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

export type VaultCleanupItem = { key: string; label: string; detail: string; count: number; on: boolean }

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
      grants: Record<string, VaultGrant>
      dir: string
      allGrants: VaultDirGrants
      view: VaultView
      selected: string
      form: VaultForm | null
      exportSel: string[]
      importPreview: VaultImportPreview | null
      confirmDelete: string
      notice: string
      audit: string[]
      probes: Record<string, VaultProbe>
      probing: string
      usage: Record<string, VaultUsage>
      cleanup: VaultCleanupItem[] | null
    }
  }
}
