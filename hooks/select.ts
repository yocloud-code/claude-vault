import type { VaultProfile } from '../types'
import { namedVars, prefixOf } from './templates'

export const aliasKey = prefixOf

const isSecretTpl = (tpl: string) => /\{secret/.test(tpl)

/** Everything a profile injects when chosen explicitly: its own `<NAME>_*` variables plus the client's. */
export const varsOf = (name: string, p: VaultProfile): Record<string, string> => ({ ...namedVars(name, p), ...p.env })

export type Selection = Map<string, Record<string, string>>

export type SelectResult = { picks: Selection } | { deny: string }

/** The `<NAME>_*` variables two profiles would both define (a prefix like `prod` + secret `db_password`). */
export const namedClash = (name: string, p: VaultProfile, others: Record<string, VaultProfile>) => {
  const mine = Object.keys(namedVars(name, p, true))
  for (const [o, op] of Object.entries(others)) {
    if (o === name) continue
    const theirs = new Set(Object.keys(namedVars(o, op, true)))
    const hit = mine.find(k => theirs.has(k))
    if (hit) return { other: o, variable: hit }
  }
  return undefined
}

/**
 * Decides which granted profiles a Bash command draws on, and which variables each injects.
 *
 * - `#vault:a,b` names profiles outright: each brings its `<NAME>_*` variables and its client
 *   variables (PGPASSWORD, KUBECONFIG, ...). Unknown or ungranted names are refused, and two named
 *   profiles whose client variables overlap (two postgres profiles) are refused.
 * - Otherwise a `$<NAME>_*` reference picks that profile and injects the referenced variable plus
 *   the profile's non-secret `<NAME>_*` variables. These names are unique per profile, so implicit
 *   use never conflicts; client variables are never injected implicitly. A reference to a
 *   `<NAME>_*` variable of an ungranted profile is refused; any other variable is left alone.
 */
export function selectProfiles(command: string, profiles: Record<string, VaultProfile>, granted: Set<string>): SelectResult {
  const picks: Selection = new Map()
  const header = /^\s*#\s*vault:\s*([\w,-]+)/m.exec(command)

  if (header) {
    const names = [...new Set(header[1].split(',').map(n => n.trim()).filter(Boolean))]
    const owners = new Map<string, string[]>()
    for (const n of names) {
      if (!profiles[n]) return { deny: `vault: 没有名为 ${n} 的 profile。` }
      if (!granted.has(n)) return { deny: `vault: profile ${n} 未授权给本会话。请让用户在 /vault 面板里授权。` }
      const vars = varsOf(n, profiles[n])
      for (const k of Object.keys(vars)) owners.set(k, [...(owners.get(k) ?? []), n])
      picks.set(n, vars)
    }
    for (const [k, list] of owners) {
      if (list.length > 1) {
        return {
          deny: `vault: ${list.join('、')} 都会设置 ${k}，不能在同一条命令里一起用 #vault: 指定。` +
            `请分开执行，或去掉 #vault:，直接用各自的专属变量（如 $${prefixOf(list[0])}_PASSWORD、$${prefixOf(list[1])}_PASSWORD）。`,
        }
      }
    }
    return { picks }
  }

  const refs = new Set([...command.matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]*)/g)].map(m => m[1]))
  if (!refs.size) return { picks }

  for (const ref of refs) {
    const owner = Object.keys(profiles).find(n => ref in namedVars(n, profiles[n]))
    if (!owner) continue
    if (!granted.has(owner)) return { deny: `vault: $${ref} 属于 profile ${owner}，它未授权给本会话。请让用户在 /vault 面板里授权。` }
    const named = namedVars(owner, profiles[owner])
    const sel = picks.get(owner) ?? Object.fromEntries(Object.entries(named).filter(([, t]) => !isSecretTpl(t)))
    sel[ref] = named[ref]
    picks.set(owner, sel)
  }
  return { picks }
}
