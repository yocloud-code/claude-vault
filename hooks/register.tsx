import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'
import type { VaultCleanupItem, VaultDirGrants, VaultForm, VaultGrant, VaultImportPreview, VaultMode, VaultProbe, VaultProfile, VaultUsage, VaultView } from '../types'
import { hasSecretsDeep, redact, redactDeep, remember } from './redact'
import { dumpReason, isAllowFile, isVaultPath, peekReason, writeReason } from './guard'
import { HEADER, ITER, envelope, isSealed, parsePlain, sealedBody, unwrap } from './transfer'
import type { Bundle } from './transfer'
import { renderPane } from './ui'
import { aliasKey, effectiveGrants, namedClash, selectProfiles, varsOf } from './select'
import { envProblem, envProblems, envToText, exampleFor, isDefaultMapping, missingFields, namedVars, parseEnv, templateOf, variantOf } from './templates'
import type { Actions } from './ui'

// ---------- keychain ----------

const SERVICE = 'claude-vault'
const SAFE = /^[A-Za-z0-9._-]+$/

const b64encode = (text: string) => {
  const bytes = new TextEncoder().encode(text)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin)
}

const b64decode = (b64: string) =>
  new TextDecoder().decode(Uint8Array.from(atob(b64), c => c.charCodeAt(0)))

const account = (profile: string, field: string) => {
  const acct = `${profile}.${field}`
  if (!SAFE.test(acct)) throw new Error(`invalid account name: ${acct}`)
  return acct
}

async function getSecret($: EngineInterface, acct: string): Promise<string | undefined> {
  const r = await $.process.run(['/usr/bin/security', 'find-generic-password', '-s', SERVICE, '-a', acct, '-w'])
  if (r.exitCode !== 0) return undefined
  const raw = r.stdout.replace(/\n$/, '')
  // Values the mod writes are prefixed so multi-line secrets survive `security -w`.
  return raw.startsWith('b64:') ? b64decode(raw.slice(4)) : raw
}

async function hasSecret($: EngineInterface, acct: string): Promise<boolean> {
  const r = await $.process.run(['/usr/bin/security', 'find-generic-password', '-s', SERVICE, '-a', acct])
  return r.exitCode === 0
}

// The value travels on stdin to `security -i`, never on argv, so `ps` cannot see it.
async function setSecret($: EngineInterface, acct: string, value: string): Promise<void> {
  if (!SAFE.test(acct)) throw new Error(`invalid account name: ${acct}`)
  const line = `add-generic-password -U -s ${SERVICE} -a ${acct} -l "Claude Vault ${acct}" -w b64:${b64encode(value)}\n`
  const r = await $.process.run(['/usr/bin/security', '-i'], { stdin: line })
  if (r.exitCode !== 0 || /error/i.test(r.stderr)) throw new Error('keychain write failed')
}

async function deleteSecret($: EngineInterface, acct: string): Promise<void> {
  await $.process.run(['/usr/bin/security', 'delete-generic-password', '-s', SERVICE, '-a', acct])
}

// ---------- native dialogs ----------

// Native macOS dialogs via osascript. Prompt text goes in argv, never spliced into the script.
const osa = async ($: EngineInterface, lines: string[], args: string[]) => {
  const argv = ['/usr/bin/osascript']
  for (const l of ['on run argv', ...lines, 'end run']) argv.push('-e', l)
  const r = await $.process.run([...argv, ...args], { timeoutMs: 300_000 })
  return r.exitCode === 0 ? r.stdout.replace(/\n$/, '') : undefined
}

const askHidden = ($: EngineInterface, prompt: string) =>
  osa($, [
    'return text returned of (display dialog (item 1 of argv) default answer "" with hidden answer with title "Claude Vault" with icon caution)',
  ], [prompt])

const confirm = async ($: EngineInterface, prompt: string) =>
  (await osa($, [
    'return button returned of (display dialog (item 1 of argv) buttons {"取消", "确认"} default button "确认" with title "Claude Vault")',
  ], [prompt])) === '确认'

const chooseFile = ($: EngineInterface, prompt: string) =>
  osa($, ['return POSIX path of (choose file with prompt (item 1 of argv))'], [prompt])

const chooseFileName = ($: EngineInterface, prompt: string, defaultName: string) =>
  osa($, ['return POSIX path of (choose file name with prompt (item 1 of argv) default name (item 2 of argv))'], [prompt, defaultName])

// ---------- profiles & files ----------

type Allow = Record<string, { mode: VaultMode; ttlMinutes?: number }>

const paths = async ($: EngineInterface) => {
  const home = (await $.env.get('HOME')) ?? ''
  const dir = `${home}/.claude/vault`
  return { home, dir, profiles: `${dir}/profiles.json`, grants: `${dir}/grants.json`, audit: `${dir}/audit.log`, run: `${dir}/run` }
}

const allowPath = (cwd: string) => `${cwd}/.claude/vault.json`


const NAME = /^[a-z0-9][a-z0-9_-]{0,40}$/

async function loadProfiles($: EngineInterface): Promise<Record<string, VaultProfile>> {
  const { profiles } = await paths($)
  try {
    return JSON.parse(await $.fs.read(profiles)) as Record<string, VaultProfile>
  } catch {
    return {}
  }
}

async function saveProfiles($: EngineInterface, all: Record<string, VaultProfile>) {
  const { profiles } = await paths($)
  await writePrivate($, profiles, JSON.stringify(all, null, 2) + '\n')
}

async function loadAllow($: EngineInterface, cwd: string): Promise<{ allow: Allow; raw: string | null }> {
  try {
    const raw = await $.fs.read(allowPath(cwd))
    const parsed = JSON.parse(raw) as { allow?: Allow }
    return { allow: parsed.allow ?? {}, raw }
  } catch {
    return { allow: {}, raw: null }
  }
}

// ---------- directory grants ----------
// Grants belong to a directory (and everything under it) and last until revoked. They live in
// ~/.claude/vault/grants.json, outside any repository, so a cloned project cannot grant itself.

async function loadGrantFile($: EngineInterface): Promise<VaultDirGrants> {
  const { grants } = await paths($)
  try {
    const parsed = JSON.parse(await $.fs.read(grants)) as { dirs?: VaultDirGrants }
    return parsed.dirs ?? {}
  } catch {
    return {}
  }
}

async function saveGrantFile($: EngineInterface, dirs: VaultDirGrants) {
  const { grants } = await paths($)
  const clean = Object.fromEntries(Object.entries(dirs).filter(([, e]) => Object.keys(e).length))
  await writePrivate($, grants, JSON.stringify({ version: 1, dirs: clean }, null, 2) + '\n')
}

// The session's directory as a real path, so a symlinked spelling meets the same grants.
async function currentDir($: EngineInterface) {
  const raw = (await $.session.cwd().catch(() => '')) || cwd
  const real = (await $.fs.stat(raw, { resolve: true }).catch(() => undefined))?.realPath
  return real || raw
}

let lastRawCwd = ''

async function refreshGrants($: EngineInterface) {
  lastRawCwd = (await $.session.cwd().catch(() => '')) || cwd
  const dir = await currentDir($)
  cwd = dir
  const all = await loadGrantFile($)
  await update($, dirA, () => dir)
  await update($, allGrantsA, () => all)
  await update($, grantsA, () => effectiveGrants(all, dir))
  await syncStatus($)
}

// Grants or revokes `name` for `dir` (default: the session's directory); mode 'off' revokes.
async function setGrant($: EngineInterface, name: string, mode: VaultMode | 'off', dir?: string) {
  const where = dir ?? (await currentDir($))
  const all = await loadGrantFile($)
  const entries = { ...(all[where] ?? {}) }
  if (mode === 'off') delete entries[name]
  else entries[name] = { mode, at: now() }
  all[where] = entries
  await saveGrantFile($, all)
  await audit($, { event: mode === 'off' ? 'revoke' : 'grant', profile: name, mode, dir: where })
  await refreshGrants($)
  if (mode !== 'off') await warmRedaction($)
}

// Applies `fn` to every directory's entries (rename, delete) and saves.
async function editAllGrants($: EngineInterface, fn: (entries: Record<string, { mode: VaultMode; at: number }>) => void) {
  const all = await loadGrantFile($)
  for (const entries of Object.values(all)) fn(entries)
  await saveGrantFile($, all)
  await refreshGrants($)
}

// A project's old `.claude/vault.json` allowlist becomes grants on its directory, once, and only
// when the person had trusted that exact file.
async function migrateLegacyAllowlist($: EngineInterface) {
  const { allow, raw } = await loadAllow($, cwd)
  if (raw === null) return
  const migrated = ((await $.store.get('migratedAllowlists')) ?? {}) as Record<string, boolean>
  if (migrated[cwd]) return
  const trusted = ((await $.store.get('trusted')) ?? {}) as Record<string, string>
  if (trusted[cwd] === (await sha256(raw))) {
    const all = await loadGrantFile($)
    const entries = { ...(all[cwd] ?? {}) }
    for (const [n, a] of Object.entries(allow)) if (!entries[n]) entries[n] = { mode: a.mode === 'write' ? 'write' : 'read', at: now() }
    all[cwd] = entries
    await saveGrantFile($, all)
    await audit($, { event: 'migrate-allowlist', profiles: Object.keys(allow), dir: cwd })
  }
  await $.store.set('migratedAllowlists', { ...migrated, [cwd]: true })
}

async function sha256(text: string) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('')
}

// Creates the file with mode 0600 (umask 077); the content travels on stdin.
async function writePrivate($: EngineInterface, path: string, content: string) {
  const r = await $.process.run(
    ['/bin/sh', '-c', 'umask 077; mkdir -p "$(dirname "$1")" && cat > "$1"', 'sh', path],
    { stdin: content },
  )
  if (r.exitCode !== 0) throw new Error(`write failed: ${path}`)
}

// Temp files (env files, {secretfile:} files) that belong to a command still running. They are
// removed when that command ends; the sweep only takes files nobody owns (a reload, a crash),
// and only once they are older than any command may run (vault_exec and Bash stop at 10 minutes).
const liveFiles = new Set<string>()
const ORPHAN_AGE_MS = 15 * 60_000

async function removeFiles($: EngineInterface, files: string[]) {
  if (!files.length) return
  await $.process.run(['/bin/rm', '-f', ...files])
  for (const f of files) liveFiles.delete(f)
}

async function sweepRun($: EngineInterface) {
  const { run } = await paths($)
  const entries = await $.fs.list(run).catch(() => [])
  const cutoff = now() - ORPHAN_AGE_MS
  const orphans = entries
    .filter(x => x.kind === 'file' && x.mtimeMs < cutoff)
    .map(x => `${run}/${x.name}`)
    .filter(f => !liveFiles.has(f))
  await removeFiles($, orphans)
}

const rand = () => [...crypto.getRandomValues(new Uint8Array(12))].map(b => b.toString(16).padStart(2, '0')).join('')

type Resolved = { env: Record<string, string>; files: string[]; missing: string[]; blocked: string[] }

// The SSH_ASKPASS helper: prints $SSHPASS, which only the one ssh child carries. No secret in the file.
async function askpassPath($: EngineInterface) {
  const { dir } = await paths($)
  const file = `${dir}/bin/askpass`
  if (!(await $.fs.exists(file))) {
    await writePrivate($, file, '#!/bin/sh\nprintf \'%s\\n\' "$SSHPASS"\n')
    await $.process.run(['/bin/chmod', '700', file])
  }
  return file
}

// Expands a profile's env templates; secrets come from the Keychain and are remembered for redaction.
async function resolveEnv($: EngineInterface, name: string, p: VaultProfile, only?: Set<string>): Promise<Resolved> {
  const { run } = await paths($)
  const env: Record<string, string> = {}
  const files: string[] = []
  const missing: string[] = []
  const blocked: string[] = []
  const own = new Set(Object.keys(namedVars(name, p, true)))
  const cache = new Map<string, string | undefined>()
  const secret = async (field: string) => {
    if (!cache.has(field)) {
      const v = await getSecret($, account(name, field))
      if (v !== undefined) remember(`${name}.${field}`, v)
      cache.set(field, v)
    }
    return cache.get(field)
  }

  for (const [key, tpl] of Object.entries(p.env)) {
    if (!own.has(key) && envProblem(key, tpl)) { blocked.push(key); continue }
    if (only && !only.has(key)) continue
    let out = ''
    let ok = true
    for (const part of tpl.split(/(\{[^}]+\})/)) {
      const m = /^\{(secret|secretfile):([A-Za-z0-9_-]+)\}$/.exec(part)
      if (m) {
        const v = await secret(m[2])
        if (v === undefined) { ok = false; missing.push(`${name}.${m[2]}`); break }
        if (m[1] === 'secret') out += v
        else {
          const file = `${run}/${rand()}`
          liveFiles.add(file)
          await writePrivate($, file, v.endsWith('\n') ? v : v + '\n')
          files.push(file)
          out += file
        }
        continue
      }
      if (part === '{askpass}') { out += await askpassPath($); continue }
      const f = /^\{(host|port|user|database)\}$/.exec(part)
      out += f ? String(p[f[1] as 'host'] ?? '') : part
    }
    if (ok) env[key] = out
  }
  return { env, files, missing, blocked }
}

// Loads the secrets of every granted profile into the redaction table, so output stays masked
// after a reload (the table lives in module memory) and before a profile's first use.
async function warmRedaction($: EngineInterface) {
  const profiles = (await read($, profilesA)) as Record<string, VaultProfile>
  for (const n of Object.keys(await activeGrants($))) {
    for (const f of profiles[n]?.secrets ?? []) {
      const v = await getSecret($, account(n, f))
      if (v !== undefined) remember(`${n}.${f}`, v)
    }
  }
}

// Runs a command with one profile's variables (its own and its client's). Refuses before running
// when a secret is missing or a client variable is not allowed; temp files go when it ends.
async function runWithProfile($: EngineInterface, name: string, p: VaultProfile, command: string, timeoutMs: number) {
  const r = await resolveEnv($, name, { ...p, env: varsOf(name, p) })
  try {
    if (r.blocked.length) return { deny: `vault: profile ${name} 的客户端变量 ${r.blocked.join(', ')} 不允许设置，请在 /vault 面板里修改。` }
    if (r.missing.length) return { deny: `vault: 钥匙串里缺少密文 ${r.missing.join(', ')}，请在 /vault 面板里设置。` }
    const started = now()
    const ran = await $.process.run(['/bin/bash', '-c', command], { env: r.env, timeoutMs })
    return { ...ran, ms: now() - started }
  } finally {
    await removeFiles($, r.files)
  }
}

// Keychain accounts under the vault's service, from attribute dumps only (no secret is printed).
async function vaultAccounts($: EngineInterface): Promise<string[]> {
  const r = await $.process.run(['/usr/bin/security', 'dump-keychain'], { timeoutMs: 60_000 })
  if (r.exitCode !== 0) return []
  const out: string[] = []
  for (const block of r.stdout.split(/^keychain: /m)) {
    if (!/"svce"<blob>="claude-vault"/.test(block)) continue
    const acct = /"acct"<blob>="([^"]*)"/.exec(block)?.[1]
    if (acct && SAFE.test(acct)) out.push(acct)
  }
  return [...new Set(out)]
}

// Accounts that belong to no current profile secret (deleted profiles, switched SSH auth, renames).
// Never guess: an unreadable profiles.json would make every secret look orphaned, so it yields
// `unsafe` and nothing is offered for deletion.
async function orphanAccounts($: EngineInterface): Promise<{ orphans: string[]; unsafe?: string; noProfiles?: boolean }> {
  const { profiles: file } = await paths($)
  let profiles: Record<string, VaultProfile> = {}
  if (await $.fs.exists(file)) {
    try {
      profiles = JSON.parse(await $.fs.read(file)) as Record<string, VaultProfile>
    } catch {
      return { orphans: [], unsafe: 'profiles.json 无法读取，为安全起见跳过' }
    }
  }
  const wanted = new Set(Object.entries(profiles).flatMap(([n, p]) => (p.secrets ?? []).map(f => `${n}.${f}`)))
  const orphans = (await vaultAccounts($)).filter(a => !wanted.has(a))
  return { orphans, noProfiles: Object.keys(profiles).length === 0 }
}

async function strayRunFiles($: EngineInterface) {
  const { run } = await paths($)
  const entries = await $.fs.list(run).catch(() => [])
  return entries.filter(x => x.kind === 'file').map(x => `${run}/${x.name}`).filter(f => !liveFiles.has(f))
}

// Grants naming a deleted profile, or a directory that no longer exists.
async function staleGrants($: EngineInterface, all: VaultDirGrants) {
  const profiles = await loadProfiles($)
  const out: { dir: string; name: string }[] = []
  for (const [dir, entries] of Object.entries(all)) {
    const exists = await $.fs.exists(dir).catch(() => false)
    for (const name of Object.keys(entries)) if (!exists || !profiles[name]) out.push({ dir, name })
  }
  return out
}

async function cleanupPlan($: EngineInterface): Promise<VaultCleanupItem[]> {
  const all = await loadGrantFile($)
  const here = await currentDir($)
  const grants = Object.keys(all[here] ?? {})
  const stale = await staleGrants($, all)
  const stray = await strayRunFiles($)
  const orph = await orphanAccounts($)
  const orphans = orph.orphans
  const probes = Object.keys((await read($, probesA)) as Record<string, VaultProbe>)
  const { audit: file } = await paths($)
  let lines = 0
  try { lines = (await $.fs.read(file)).split('\n').filter(Boolean).length } catch {}
  return [
    { key: 'grants', label: '撤销当前目录的全部授权', detail: grants.join('、') || '无（上级目录的授权请在「授权管理」里撤销）', count: grants.length, on: false },
    {
      key: 'orphans', label: '删除孤立的钥匙串条目',
      detail: orph.unsafe ?? (orph.noProfiles && orphans.length
        ? `⚠ 当前没有任何 profile，这些都会被删除：${orphans.join('、')}`
        : orphans.join('、') || '无（只会删除不属于任何现有 profile 的旧密文）'),
      count: orphans.length,
      // with no profile at all, deleting everything is a decision the person makes explicitly
      on: !orph.noProfiles,
    },
    { key: 'stale-grants', label: '移除失效的授权', detail: stale.map(x => `${x.name} @ ${x.dir.replace(/^\/Users\/[^/]+/, '~')}`).join('、') || '无（profile 已删除或目录已不存在）', count: stale.length, on: true },
    { key: 'stray', label: '删除残留的临时文件', detail: stray.length ? `${stray.length} 个（私钥、kubeconfig、env 文件）` : '无', count: stray.length, on: true },
    { key: 'probes', label: '清除测试连接结果', detail: probes.join('、') || '无', count: probes.length, on: true },
    { key: 'audit', label: '清空审计日志', detail: `${lines} 条记录，清空后无法恢复`, count: lines, on: false },
  ]
}

async function runCleanupPlan($: EngineInterface, keys: string[]) {
  const done: string[] = []
  for (const key of keys) {
    if (key === 'grants') {
      const here = await currentDir($)
      const all = await loadGrantFile($)
      const n = Object.keys(all[here] ?? {}).length
      delete all[here]
      await saveGrantFile($, all)
      await refreshGrants($)
      done.push(`撤销当前目录 ${n} 个授权`)
    } else if (key === 'orphans') {
      const { orphans, unsafe } = await orphanAccounts($)
      if (unsafe) { done.push(unsafe); continue }
      for (const a of orphans) await deleteSecret($, a)
      done.push(`删除 ${orphans.length} 个孤立钥匙串条目`)
    } else if (key === 'stale-grants') {
      const all = await loadGrantFile($)
      const stale = await staleGrants($, all)
      for (const x of stale) delete all[x.dir]?.[x.name]
      await saveGrantFile($, all)
      await refreshGrants($)
      done.push(`移除 ${stale.length} 个失效授权`)
    } else if (key === 'stray') {
      const stray = await strayRunFiles($)
      await removeFiles($, stray)
      done.push(`删除 ${stray.length} 个临时文件`)
    } else if (key === 'probes') {
      await update($, probesA, () => ({}))
      done.push('清除测试结果')
    } else if (key === 'audit') {
      const { audit: file } = await paths($)
      await writePrivate($, file, '')
      await update($, usageA, () => ({}))
      done.push('清空审计日志')
    }
  }
  await audit($, { event: 'cleanup', items: keys })
  await refreshProfiles($)
  return done
}

// ---------- export encryption (system openssl; the passphrase rides in the child env, never argv) ----------
async function seal($: EngineInterface, bundle: Bundle, pass: string): Promise<string> {
  const json = JSON.stringify(bundle)
  const r = await $.process.run(
    ['/usr/bin/openssl', 'enc', '-aes-256-cbc', '-pbkdf2', '-iter', ITER, '-md', 'sha256', '-salt', '-a', '-A', '-pass', 'env:VAULT_EXPORT_PASS'],
    { stdin: envelope(json, await sha256(json)), env: { VAULT_EXPORT_PASS: pass }, timeoutMs: 120_000 },
  )
  if (r.exitCode !== 0) throw new Error('openssl encrypt failed')
  return `${HEADER}\n${r.stdout.trim()}\n`
}

async function open($: EngineInterface, text: string, pass: string): Promise<Bundle> {
  const r = await $.process.run(
    ['/usr/bin/openssl', 'enc', '-d', '-aes-256-cbc', '-pbkdf2', '-iter', ITER, '-md', 'sha256', '-a', '-A', '-pass', 'env:VAULT_EXPORT_PASS'],
    { stdin: sealedBody(text) + '\n', env: { VAULT_EXPORT_PASS: pass }, timeoutMs: 120_000 },
  )
  if (r.exitCode !== 0) throw new Error('decrypt failed')
  const env = unwrap(r.stdout)
  if ((await sha256(env.bundle)) !== env.digest) throw new Error('digest mismatch')
  return JSON.parse(env.bundle) as Bundle
}

const PANE = 'vault'

const profilesA = atom({ plugin: 'vault', key: 'profiles' } as const, {})
const storedA = atom({ plugin: 'vault', key: 'stored' } as const, {})
const grantsA = atom({ plugin: 'vault', key: 'grants' } as const, {})
const dirA = atom({ plugin: 'vault', key: 'dir' } as const, '')
const allGrantsA = atom({ plugin: 'vault', key: 'allGrants' } as const, {})
const viewA = atom({ plugin: 'vault', key: 'view' } as const, 'list')
const selectedA = atom({ plugin: 'vault', key: 'selected' } as const, '')
const formA = atom({ plugin: 'vault', key: 'form' } as const, null)
const exportSelA = atom({ plugin: 'vault', key: 'exportSel' } as const, [])
const importA = atom({ plugin: 'vault', key: 'importPreview' } as const, null)
const confirmDeleteA = atom({ plugin: 'vault', key: 'confirmDelete' } as const, '')
const noticeA = atom({ plugin: 'vault', key: 'notice' } as const, '')
const auditA = atom({ plugin: 'vault', key: 'audit' } as const, [])
const probesA = atom({ plugin: 'vault', key: 'probes' } as const, {})
const probingA = atom({ plugin: 'vault', key: 'probing' } as const, '')
const usageA = atom({ plugin: 'vault', key: 'usage' } as const, {})
const cleanupA = atom({ plugin: 'vault', key: 'cleanup' } as const, null)

let cwd = ''
// decrypted import bundle: module memory only, never $.state
let pendingBundle: Bundle | null = null

const now = () => Date.now()
function notice($: EngineInterface, text: string) {
  const tagged = /^[✔✖⚠ℹ]/.test(text) ? text
    : /失败|错误|不一致|至少|只能|没有|损坏|缺少/.test(text) ? `✖ ${text}`
    : /取消/.test(text) ? `ℹ ${text}`
    : `✔ ${text}`
  if (tagged.startsWith('✔')) {
    $.clock.after(6000, () => void update($, noticeA, (n: string) => (n === tagged ? '' : n)))
  }
  return update($, noticeA, () => tagged)
}

// Appends run one after another: the log is read, extended and rewritten, so two concurrent
// appends (parallel tool calls, the expiry timer) would otherwise drop one of the lines.
let auditQueue: Promise<void> = Promise.resolve()

async function audit($: EngineInterface, entry: Record<string, unknown>) {
  const write = async () => {
    const { audit: file } = await paths($)
    let old = ''
    try { old = await $.fs.read(file) } catch {}
    const line = JSON.stringify({ t: new Date().toISOString(), cwd, ...entry })
    const lines = (old + redact(line) + '\n').split('\n').filter(Boolean).slice(-2000)
    await writePrivate($, file, lines.join('\n') + '\n')
  }
  const done = auditQueue.then(write, write)
  auditQueue = done.catch(() => {})
  await done
  const used = entry.event === 'exec' ? [entry.profile] : entry.event === 'bash' ? (entry.profiles as string[]) : []
  if (used.length) {
    const at = now()
    await update($, usageA, (u: Record<string, VaultUsage>) => {
      const next = { ...u }
      for (const n of used as string[]) next[n] = { count: (next[n]?.count ?? 0) + 1, last: at }
      return next
    })
  }
}

// Usage per profile from the audit log's exec and bash events.
async function loadUsage($: EngineInterface) {
  const { audit: file } = await paths($)
  const usage: Record<string, VaultUsage> = {}
  let text = ''
  try { text = await $.fs.read(file) } catch {}
  for (const line of text.split('\n')) {
    if (!line) continue
    try {
      const j = JSON.parse(line) as { t: string; event: string; profile?: string; profiles?: string[] }
      const names = j.event === 'exec' && j.profile ? [j.profile] : j.event === 'bash' ? (j.profiles ?? []) : []
      const at = Date.parse(j.t)
      for (const n of names) usage[n] = { count: (usage[n]?.count ?? 0) + 1, last: Math.max(usage[n]?.last ?? 0, at) }
    } catch {}
  }
  await update($, usageA, () => usage)
}

async function refreshProfiles($: EngineInterface) {
  const profiles = await loadProfiles($)
  const stored: Record<string, boolean> = {}
  for (const [n, p] of Object.entries(profiles)) {
    for (const f of p.secrets) stored[`${n}.${f}`] = await hasSecret($, account(n, f))
  }
  await update($, profilesA, () => profiles)
  await update($, storedA, () => stored)
  return profiles
}

// The grants in force here. The session's directory can change mid-session: re-read it then.
async function activeGrants($: EngineInterface) {
  const raw = (await $.session.cwd().catch(() => '')) || cwd
  if (raw !== lastRawCwd) await refreshGrants($)
  return (await read($, grantsA)) as Record<string, VaultGrant>
}

async function syncStatus($: EngineInterface) {
  const names = Object.keys((await read($, grantsA)) as Record<string, VaultGrant>)
  $.ui.status(names.length ? `🔐 vault: ${names.join(', ')}` : undefined)
  await registerTools($, names)
}

// ---------- tools the model sees ----------
async function registerTools($: EngineInterface, granted: string[]) {
  const profiles = (await read($, profilesA)) as Record<string, VaultProfile>
  const list = granted.length
    ? granted.map(n => (profiles[n]?.description ? `${n} (${profiles[n].description})` : n)).join(', ')
    : '(none)'
  await $.tool.register({
    name: 'vault_list',
    description:
      'List credential profiles managed by the vault mod (databases, servers, clusters). Returns names, types, hosts, ' +
      'env var names and grant state — never secret values. Profiles granted to the current directory: ' + list + '.',
    inputSchema: { type: 'object', properties: {} },
  })
  await $.tool.register({
    name: 'vault_exec',
    description:
      'Run a shell command with a granted credential profile injected as environment variables. You never see the secret; ' +
      'output is redacted. Use this instead of asking for passwords. Every profile has its own variables named after it ' +
      '(profile prod-db: $PROD_DB_HOST, $PROD_DB_USER, $PROD_DB_PASSWORD; file secrets as $<NAME>_<SECRET>_FILE), plus the ' +
      "client's standard variables (PGPASSWORD, KUBECONFIG, SSH askpass, ...). vault_list shows each profile's variables. " +
      'In Bash, referencing $<NAME>_* injects that profile\'s own variables; starting the command with "#vault:<profile>" also ' +
      'injects the client variables (one profile per client: two postgres profiles cannot share one #vault: line). ' +
      'Injection is refused for run_in_background Bash commands. Variables exist only for the one command and its child processes. ' +
      'Granted to the current directory: ' + list + '. If a profile is not granted, ask the user to grant it to this directory in the /vault pane.',
    inputSchema: {
      type: 'object',
      properties: {
        profile: { type: 'string', description: 'profile name' },
        command: { type: 'string', description: 'bash command; profile env vars are set' },
        cwd: { type: 'string' },
        timeoutSec: { type: 'number', description: 'default 120, max 600' },
      },
      required: ['profile', 'command'],
    },
  })
}

async function checkUse($: EngineInterface, name: string, command: string) {
  const profiles = (await read($, profilesA)) as Record<string, VaultProfile>
  const p = profiles[name]
  if (!p) return { deny: `vault: 没有名为 ${name} 的 profile。` }
  const g = (await activeGrants($))[name]
  if (!g) return { deny: `vault: profile ${name} 未授权给当前目录。请让用户在 /vault 面板里授权（授权对该目录及其子目录长期有效）。` }
  const w = g.mode === 'read' ? writeReason(p, command) : undefined
  if (w) return { deny: w }
  return { p, g }
}

// ---------- Bash: guard, transparent injection, redaction ----------
const shq = (v: string) => `'${v.replace(/'/g, `'\\''`)}'`

// ---------- UI actions ----------
const blankForm = (type = 'postgres'): VaultForm => {
  const t = templateOf(type)
  const v = t.variants[0]
  return {
    name: '', description: '', type, variant: v.key, host: '', port: t.port ? String(t.port) : '', user: '', database: '',
    secrets: v.secrets.map(x => x.name).join(','), env: envToText(v.env),
    advanced: type === 'custom',
  }
}

function actions($: EngineInterface): Actions {
  const acts: Actions = {
  probe: async n => {
    const p = ((await read($, profilesA)) as Record<string, VaultProfile>)[n]
    const v = p && variantOf(p.type, p.variant)
    if (!p || !v?.probe) return notice($, `${n} 的类型不支持测试连接`)
    await update($, probingA, () => n)
    let result: VaultProbe
    try {
      const ran = await runWithProfile($, n, p, exampleFor(v.probe, n), 30_000)
      if ('deny' in ran) result = { ok: false, at: now(), ms: 0, message: ran.deny.replace(/^vault: /, '') }
      else {
        const tool = exampleFor(v.probe, n).split(' ')[0]
        const err = (ran.stderr || ran.stdout).trim()
        result = {
          ok: ran.exitCode === 0, at: now(), ms: ran.ms,
          message: ran.exitCode === 0 ? '' : ran.exitCode === 127 ? `本机未安装 ${tool}` : redact(err).slice(0, 200) || `退出码 ${ran.exitCode}`,
        }
      }
    } catch (err) {
      result = { ok: false, at: now(), ms: 0, message: redact(String(err)).slice(0, 200) }
    }
    await update($, probesA, (ps: Record<string, VaultProbe>) => ({ ...ps, [n]: result }))
    await update($, probingA, () => '')
    await audit($, { event: 'probe', profile: n, ok: result.ok, ms: result.ms })
  },
  copy: async (text, surface) => {
    const r = await $.ui.copy({ text, surface })
    await notice($, r.isCopied ? '已复制到剪贴板' : '✖ 复制失败（当前界面不支持剪贴板）')
  },
  go: async (view: VaultView) => {
    await update($, noticeA, () => '')
    if (view === 'audit') {
      const { audit: file } = await paths($)
      let lines: string[] = []
      try { lines = (await $.fs.read(file)).split('\n').filter(Boolean).slice(-40).reverse() } catch {}
      await update($, auditA, () => lines.map(l => {
        try { const j = JSON.parse(l); return `${j.t.slice(5, 19).replace('T', ' ')} ${j.event} ${j.profile ?? (j.profiles ?? []).join(',')} ${j.command ?? ''}` } catch { return l }
      }))
    }
    if (view === 'export') {
      const names = Object.keys((await read($, profilesA)) as object)
      await update($, exportSelA, () => names)
    }
    await update($, viewA, () => view)
  },
  select: n => void update($, selectedA, () => n),
  setGrant: async (n, mode) => {
    if (mode === 'off') {
      // an inherited grant lives on the directory above: revoke it where it was given
      const g = ((await read($, grantsA)) as Record<string, VaultGrant>)[n]
      const here = await currentDir($)
      await setGrant($, n, 'off', g?.dir ?? here)
      return notice($, g && g.dir !== here
        ? `已撤销 ${n} 在 ${g.dir.replace(/^\/Users\/[^/]+/, '~')} 的授权（它的所有子目录同时失效）`
        : `已撤销 ${n} 在当前目录的授权`)
    }
    await setGrant($, n, mode)
    const p = ((await read($, profilesA)) as Record<string, VaultProfile>)[n]
    const stored = (await read($, storedA)) as Record<string, boolean>
    const unset = (p?.secrets ?? []).filter(x => !stored[`${n}.${x}`])
    const label = mode === 'write' ? '读写' : '只读'
    await notice($, unset.length ? `⚠ 已授权 ${n}（${label}），但还缺少密文：${unset.join('、')}` : `已授权 ${n}（${label}）给当前目录及其子目录`)
  },
  revokeAt: async (dir, n) => {
    await setGrant($, n, 'off', dir)
    await notice($, `已撤销 ${n} @ ${dir.replace(/^\/Users\/[^/]+/, '~')}`)
  },
  openCleanup: async () => {
    // null while the plan is computed: the view says it is checking
    await update($, cleanupA, () => null)
    await update($, viewA, () => 'cleanup')
    const items = await cleanupPlan($)
    await update($, cleanupA, () => items)
  },
  toggleCleanup: key => void update($, cleanupA, (items: VaultCleanupItem[] | null) =>
    items ? items.map(i => (i.key === key ? { ...i, on: !i.on } : i)) : items),
  runCleanup: async () => {
    const items = ((await read($, cleanupA)) as VaultCleanupItem[] | null) ?? []
    const done = await runCleanupPlan($, items.filter(i => i.on && i.count > 0).map(i => i.key))
    await update($, cleanupA, () => null)
    await update($, viewA, () => 'list')
    await notice($, done.length ? `清理完成：${done.join('；')}` : '没有需要清理的内容')
  },
  newProfile: async () => { await update($, formA, () => blankForm()); await update($, confirmDeleteA, () => ''); await update($, viewA, () => 'edit') },
  editProfile: async n => {
    const p = ((await read($, profilesA)) as Record<string, VaultProfile>)[n]
    if (!p) return
    await update($, formA, () => ({
      original: n, name: n, description: p.description ?? '', type: p.type, variant: variantOf(p.type, p.variant).key, host: p.host ?? '', port: p.port ? String(p.port) : '', user: p.user ?? '',
      database: p.database ?? '', secrets: p.secrets.join(','), env: envToText(p.env),
      advanced: !isDefaultMapping(p),
    }))
    await update($, confirmDeleteA, () => '')
    await update($, viewA, () => 'edit')
  },
  formSet: patch => void update($, formA, (f: VaultForm | null) => (f ? { ...f, ...patch } : f)),
  formType: type => void update($, formA, (f: VaultForm | null) => {
    const b = blankForm(type)
    if (!f) return b
    // keep only the values the new type still has a field for
    const keep = new Set(templateOf(type).fields.map(x => x.key))
    return {
      ...f, type, variant: b.variant, secrets: b.secrets, env: b.env, advanced: b.advanced,
      host: keep.has('host') ? f.host : '', user: keep.has('user') ? f.user : '',
      database: keep.has('database') ? f.database : '',
      port: keep.has('port') ? (f.port && f.port !== String(templateOf(f.type).port ?? '') ? f.port : b.port) : '',
    }
  }),
  saveForm: async () => {
    const f = (await read($, formA)) as VaultForm | null
    if (!f) return
    const name = f.name.trim()
    if (!NAME.test(name)) return notice($, '名称只能用小写字母、数字、- 和 _，且以字母或数字开头')
    const missing = missingFields(f.type, f)
    if (missing.length) return notice($, `请填写必填项：${missing.join('、')}`)
    if (f.port && !/^\d{1,5}$/.test(f.port.trim())) return notice($, '端口必须是数字')
    const t = templateOf(f.type)
    const v = variantOf(f.type, f.variant)
    const fields = new Set(t.fields.map(x => x.key))
    const val = (k: 'host' | 'user' | 'database') => (fields.has(k) && f[k].trim()) || undefined
    const custom = f.advanced || f.type === 'custom'
    const secrets = custom
      ? f.secrets.split(',').map(x => x.trim()).filter(x => /^[A-Za-z0-9_-]+$/.test(x))
      : v.secrets.map(x => x.name)
    if (custom && !secrets.length) return notice($, '至少需要一个密文字段')
    const problems = custom ? envProblems(parseEnv(f.env)) : []
    if (problems.length) return notice($, problems.join('；'))
    const profile: VaultProfile = {
      type: f.type, variant: t.variants.length > 1 ? v.key : undefined,
      description: f.description.trim() || undefined, host: val('host'), user: val('user'), database: val('database'),
      port: fields.has('port') && f.port.trim() ? Number(f.port) : undefined,
      secrets, env: custom ? parseEnv(f.env) : { ...v.env },
    }
    const all = await loadProfiles($)
    const others = Object.fromEntries(Object.entries(all).filter(([o]) => o !== f.original))
    const same = Object.keys(others).find(o => o !== name && aliasKey(o) === aliasKey(name))
    if (same) return notice($, `名称 ${name} 和已有的 ${same} 会生成相同的变量前缀 ${aliasKey(name)}_，请换一个名称`)
    const clash = namedClash(name, profile, others)
    if (clash) return notice($, `变量 ${clash.variable} 和已有的 ${clash.other} 重名，请换一个名称或密文字段名`)
    const renamed = f.original && f.original !== name ? f.original : ''
    if (renamed) {
      // Keychain items are keyed `<name>.<field>`: carry every secret over to the new name
      for (const field of all[renamed]?.secrets ?? []) {
        const old = await getSecret($, account(renamed, field))
        if (old === undefined) continue
        if (secrets.includes(field)) await setSecret($, account(name, field), old)
        await deleteSecret($, account(renamed, field))
      }
      delete all[renamed]
    }
    all[name] = profile
    await saveProfiles($, all)
    if (renamed) {
      await editAllGrants($, entries => {
        if (entries[renamed]) { entries[name] = entries[renamed]; delete entries[renamed] }
      })
      await update($, selectedA, (sel: string) => (sel === renamed ? name : sel))
      await audit($, { event: 'rename-profile', profile: name, from: renamed })
    }
    await audit($, { event: 'save-profile', profile: name })
    await refreshProfiles($)
    await syncStatus($)
    await update($, formA, () => ({ ...f, name, original: name }))
    const stored = (await read($, storedA)) as Record<string, boolean>
    const unset = profile.secrets.filter(x => !stored[`${name}.${x}`])
    await notice($, `已保存 ${name}${unset.length ? `，还需设置：${unset.join('、')}` : ''}`)
    // a new profile goes straight on to its first secret, saving a click
    if (!f.original && unset.length) {
      const def = v.secrets.find(d => d.name === unset[0])
      await (def?.file ? acts.setSecretFromFile(name, unset[0]) : acts.setSecret(name, unset[0]))
    }
  },
  setSecret: async (n, field) => {
    const v = await askHidden($, `请输入 ${n}.${field} 的值（只保存到 macOS 钥匙串，Claude 看不到）`)
    if (v === undefined || v === '') return notice($, '已取消')
    remember(`${n}.${field}`, v)
    await setSecret($, account(n, field), v)
    await audit($, { event: 'set-secret', profile: n, field })
    await refreshProfiles($)
    await notice($, `${n}.${field} 已写入钥匙串`)
  },
  setSecretFromFile: async (n, field) => {
    const file = await chooseFile($, `选择 ${n}.${field} 的内容文件（如私钥、kubeconfig）`)
    if (!file) return notice($, '已取消')
    const v = await $.fs.read(file)
    remember(`${n}.${field}`, v)
    await setSecret($, account(n, field), v)
    await audit($, { event: 'set-secret-file', profile: n, field })
    await refreshProfiles($)
    await notice($, `${n}.${field} 已从文件写入钥匙串（原文件请自行妥善处理）`)
  },
  askDelete: n => void update($, confirmDeleteA, () => n),
  doDelete: async n => {
    const all = await loadProfiles($)
    for (const f of all[n]?.secrets ?? []) await deleteSecret($, account(n, f))
    delete all[n]
    await saveProfiles($, all)
    await editAllGrants($, entries => { delete entries[n] })
    await audit($, { event: 'delete-profile', profile: n })
    await refreshProfiles($)
    await update($, viewA, () => 'list')
    await notice($, `已删除 ${n}`)
  },
  toggleExport: n => void update($, exportSelA, (s: string[]) => (s.includes(n) ? s.filter(x => x !== n) : [...s, n])),
  doExport: async () => {
    const sel = (await read($, exportSelA)) as string[]
    const all = (await read($, profilesA)) as Record<string, VaultProfile>
    const profiles = Object.fromEntries(sel.filter(n => all[n]).map(n => [n, all[n]]))
    if (!Object.keys(profiles).length) return notice($, '没有选择任何 profile')
    const day = new Date().toISOString().slice(0, 10).replace(/-/g, '')
    // ask for the passphrase first: cancelling there leaves no half-made file behind
    const pass = await askHidden($, '设置导出口令（至少 12 位，导入时需要）')
    if (!pass) return notice($, '已取消')
    if (pass.length < 12) return notice($, '口令至少 12 位')
    if ((await askHidden($, '再次输入导出口令')) !== pass) return notice($, '两次口令不一致')
    const file = await chooseFileName($, '导出到', `claude-vault-${day}.cvault`)
    if (!file) return notice($, '已取消')
    const bundle: Bundle = { version: 1, exportedAt: new Date().toISOString(), profiles }
    const secrets: Record<string, string> = {}
    for (const [n, p] of Object.entries(profiles)) for (const f of p.secrets) {
      const v = await getSecret($, account(n, f))
      if (v !== undefined) { secrets[`${n}.${f}`] = v; remember(`${n}.${f}`, v) }
    }
    await writePrivate($, file, await seal($, { ...bundle, secrets }, pass))
    await audit($, { event: 'export', profiles: Object.keys(profiles), file, secrets: Object.keys(secrets).length })
    await update($, viewA, () => 'list')
    await notice($, `已导出 ${Object.keys(profiles).length} 个 profile → ${file}`)
  },
  startImport: async () => {
    const file = await chooseFile($, '选择要导入的 .cvault 文件')
    if (!file) return notice($, '已取消')
    let text = ''
    try { text = await $.fs.read(file) } catch { return notice($, '读取文件失败') }
    let bundle: Bundle
    const encrypted = isSealed(text)
    try {
      if (encrypted) {
        const pass = await askHidden($, `输入 ${file.split('/').pop()} 的导出口令`)
        if (!pass) return notice($, '已取消')
        bundle = await open($, text, pass)
        for (const [k, v] of Object.entries(bundle.secrets ?? {})) remember(k, v)
      } else bundle = parsePlain(text)
    } catch {
      return notice($, '口令错误或文件损坏')
    }
    pendingBundle = bundle
    const current = (await read($, profilesA)) as Record<string, VaultProfile>
    const preview: VaultImportPreview = {
      file, encrypted,
      items: Object.entries(bundle.profiles).filter(([n]) => NAME.test(n)).map(([n, p]) => {
        const status = !current[n] ? 'new' : JSON.stringify(current[n]) === JSON.stringify(p) ? 'same' : 'conflict'
        return {
          name: n, status, action: status === 'new' ? 'add' : status === 'same' ? 'overwrite' : 'skip',
          secretCount: Object.keys(bundle.secrets ?? {}).filter(k => k.startsWith(n + '.')).length,
          clientVars: Object.keys(p.env ?? {}),
          problems: envProblems(p.env ?? {}),
        } as VaultImportPreview['items'][number]
      }),
    }
    await update($, importA, () => preview)
    await update($, viewA, () => 'import')
  },
  importAction: (n, action) => void update($, importA, (p: VaultImportPreview | null) =>
    p ? { ...p, items: p.items.map(i => (i.name === n ? { ...i, action: action as typeof i.action } : i)) } : p),
  confirmImport: async () => {
    const p = (await read($, importA)) as VaultImportPreview | null
    const bundle = pendingBundle
    if (!p || !bundle) return
    const all = await loadProfiles($)
    const done: string[] = []
    const clashes: string[] = []
    for (const it of p.items) {
      if (it.action === 'skip') continue
      if (envProblems(bundle.profiles[it.name].env ?? {}).length) { clashes.push(`${it.name}（含不允许的客户端变量）`); continue }
      const target = it.action === 'rename' ? `${it.name}-imported` : it.name
      if (Object.keys(all).some(o => o !== target && aliasKey(o) === aliasKey(target)) || namedClash(target, bundle.profiles[it.name], all)) { clashes.push(target); continue }
      all[target] = bundle.profiles[it.name]
      for (const f of bundle.profiles[it.name].secrets) {
        const v = bundle.secrets?.[`${it.name}.${f}`]
        if (v !== undefined) await setSecret($, account(target, f), v)
      }
      done.push(target)
    }
    await saveProfiles($, all)
    pendingBundle = null
    await update($, importA, () => null)
    await audit($, { event: 'import', profiles: done, file: p.file, encrypted: p.encrypted })
    await refreshProfiles($)
    await update($, viewA, () => 'list')
    await notice($, clashes.length
      ? `⚠ 已导入 ${done.length} 个；跳过：${clashes.join('、')}`
      : `已导入 ${done.length} 个 profile（未授权任何会话）`)
  },
  cancelImport: async () => { pendingBundle = null; await update($, importA, () => null); await update($, viewA, () => 'list') },
  close: () => void $.ui.close({ id: PANE }),
  }
  return acts
}


export const register: Register = on => {
  on('tool.call', { tool: 'mcp__vault__vault_list' }, async $ => {
    const profiles = (await read($, profilesA)) as Record<string, VaultProfile>
    const grants = await activeGrants($)
    const out = Object.entries(profiles).map(([n, p]) => ({
      name: n, type: p.type, host: p.host, port: p.port, user: p.user, database: p.database,
      granted: grants[n] ? { mode: grants[n].mode, directory: grants[n].dir } : false,
      description: p.description,
      auth: p.type === 'ssh' ? variantOf(p.type, p.variant).label : undefined,
      variables: Object.keys(namedVars(n, p)),
      clientVariables: Object.keys(p.env),
    }))
    return { result: JSON.stringify({ profiles: out }, null, 2) }
  })

  on('tool.call', { tool: 'mcp__vault__vault_exec' }, async ($, e) => {
    const { profile, command, cwd: dir, timeoutSec } = e as unknown as { profile: string; command: string; cwd?: string; timeoutSec?: number }
    const peek = peekReason(command) ?? dumpReason(command)
    if (peek) return { deny: peek }
    const c = await checkUse($, profile, command)
    if ('deny' in c) return { deny: c.deny! }
    const timeoutMs = Math.min(600, timeoutSec ?? 120) * 1000
    try {
      const ran = await runWithProfile($, profile, c.p, dir ? `cd ${shq(dir)} && ${command}` : command, timeoutMs)
      if ('deny' in ran) return { deny: ran.deny }
      await audit($, { event: 'exec', profile, command: command.slice(0, 120), exit: ran.exitCode, ms: ran.ms })
      const text = `exit code: ${ran.exitCode}\n--- stdout ---\n${ran.stdout}${ran.stderr ? `\n--- stderr ---\n${ran.stderr}` : ''}`
      return { result: redact(text) }
    } catch (err) {
      await audit($, { event: 'exec', profile, command: command.slice(0, 120), error: String(err).slice(0, 200) })
      return { result: redact(`vault_exec failed: ${String(err)}`) }
    }
  })

  on('tool.call', { tool: 'Bash' }, async ($, e, next) => {
    const command = (e as unknown as { command: string }).command
    const peek = peekReason(command)
    if (peek) return { deny: peek }

    const profiles = (await read($, profilesA)) as Record<string, VaultProfile>
    const granted = new Set(Object.keys(await activeGrants($)))
    const chosen = selectProfiles(command, profiles, granted)
    if ('deny' in chosen) return { deny: chosen.deny }
    const wanted = chosen.picks
    if (wanted.size === 0) return next(e)

    // a background command outlives this call, and with it the temp files it reads
    if ((e as unknown as { run_in_background?: boolean }).run_in_background) {
      return { deny: 'vault: 后台运行的 Bash 命令不能注入凭证（命令返回后临时文件就会被删除）。请去掉 run_in_background，或改用 vault_exec。' }
    }

    const dump = dumpReason(command)
    if (dump) return { deny: dump }

    const env: Record<string, string> = {}
    const files: string[] = []
    for (const [n, vars] of wanted) {
      const c = await checkUse($, n, command)
      if ('deny' in c) { await removeFiles($, files); return { deny: c.deny! } }
      const r = await resolveEnv($, n, { ...c.p, env: vars })
      files.push(...r.files)
      if (r.blocked.length) { await removeFiles($, files); return { deny: `vault: profile ${n} 的客户端变量 ${r.blocked.join(', ')} 不允许设置，请在 /vault 面板里修改。` } }
      if (r.missing.length) { await removeFiles($, files); return { deny: `vault: 钥匙串里缺少密文 ${r.missing.join(', ')}。` } }
      Object.assign(env, r.env)
    }

    const { run } = await paths($)
    const envFile = `${run}/${crypto.randomUUID()}.env`
    liveFiles.add(envFile)
    await writePrivate($, envFile, Object.entries(env).map(([k, v]) => `export ${k}=${shq(v)}`).join('\n') + '\n')
    files.push(envFile)
    const rewritten = `{ . ${shq(envFile)}; rm -f ${shq(envFile)}; }\n${command}`
    const started = now()
    try {
      const ran = await next({ ...e, command: rewritten } as typeof e)
      await audit($, { event: 'bash', profiles: [...wanted.keys()], command: command.slice(0, 120), ms: now() - started })
      return ran
    } finally {
      await removeFiles($, files)
    }
  })

  // every tool: keep the model's file tools out of the vault, and redact any result carrying a known secret
  on('tool.call', async ($, e, next) => {
    const args = e as unknown as Record<string, unknown>
    const { dir } = await paths($)
    for (const key of ['file_path', 'path', 'notebook_path']) {
      const v = args[key]
      if (typeof v !== 'string') continue
      const real = (await $.fs.stat(v, { resolve: true }).catch(() => undefined))?.realPath ?? v
      if (isVaultPath(v, dir) || isVaultPath(real, dir)) return { deny: 'vault: 凭证存储目录不允许被工具访问。' }
      if (e.tool !== 'Read' && e.tool !== 'Grep' && e.tool !== 'Glob' && (isAllowFile(v) || isAllowFile(real))) {
        return { deny: 'vault: .claude/vault.json 只能由用户在 /vault 面板中修改。' }
      }
    }
    const ran = await next(e)
    if ('deny' in ran && ran.deny !== undefined) return ran
    if (!hasSecretsDeep(ran.result) && !(typeof ran.text === 'string' && hasSecretsDeep(ran.text))) return ran
    return { result: redactDeep(ran.result), ...(ran.context ? { context: ran.context } : {}) } as typeof ran
  })

  // last line of defence: every row the conversation keeps
  on('session.append', ($, e, next) => {
    const content = (e.message as { content?: unknown }).content
    if (content === undefined || !hasSecretsDeep(content)) return next(e)
    return next({ ...e, message: { ...e.message, content: redactDeep(content) } } as typeof e)
  })

  // ---------- lifecycle, command, pane ----------
  on('session.start', async ($, e, next) => {
    cwd = e.cwd
    await $.command.register({
      name: 'vault',
      description: '凭证保险库：管理数据库/服务器/集群凭证与目录授权',
      argumentHint: '[grant <p> [read|write]|revoke <p>|list|export|import]',
    })
    await refreshProfiles($)
    await loadUsage($)
    await migrateLegacyAllowlist($)
    await refreshGrants($)
    // grants survive a reload in $.state, the redaction table does not: reload it
    await warmRedaction($)
    await sweepRun($)
    $.clock.every(60_000, () => void sweepRun($))
    return next(e)
  })

  on('command.run', { command: 'vault' }, async ($, e) => {
    const [sub = '', ...rest] = e.args.trim().split(/\s+/).filter(Boolean)
    const byPerson = e.origin.kind === 'composer'
    const openPane = async (view: VaultView = 'list') => {
      await actions($).go(view)
      await $.ui.open({ id: PANE, title: '🔐 Vault', focus: true })
    }
    if (sub !== '' && sub !== 'list' && !byPerson) return { text: 'vault: 该子命令只能由用户本人在输入框执行。' }
    switch (sub) {
      case '': await openPane(); return { text: 'Vault 面板已打开。' }
      case 'grant': {
        const [name, mode] = rest
        if (!name || !((await read($, profilesA)) as Record<string, VaultProfile>)[name]) return { text: `没有 profile: ${name ?? ''}` }
        const m = mode === 'write' ? 'write' : 'read'
        await setGrant($, name, m)
        return { text: `已授权 ${name}（${m === 'write' ? '读写' : '只读'}）给 ${cwd} 及其子目录，撤销前一直有效` }
      }
      case 'revoke': {
        if (!rest[0]) return { text: '用法: /vault revoke <profile>' }
        const g = ((await read($, grantsA)) as Record<string, VaultGrant>)[rest[0]]
        if (!g) return { text: `${rest[0]} 在当前目录没有授权` }
        await setGrant($, rest[0], 'off', g.dir)
        return { text: `已撤销 ${rest[0]} 在 ${g.dir} 的授权` }
      }
      case 'list': {
        const profiles = (await read($, profilesA)) as Record<string, VaultProfile>
        const g = await activeGrants($)
        return { text: Object.keys(profiles).map(n => `${g[n] ? `✅ ${g[n].mode}` : '  ─    '} ${n} (${profiles[n].type})`).join('\n') || '(空)' }
      }
      case 'export': await openPane('export'); return { text: '导出面板已打开。' }
      case 'import': await openPane(); await actions($).startImport(); return { text: '导入：请在弹窗中选择文件。' }
      default: return { text: '用法: /vault [grant <profile> [read|write]|revoke <profile>|list|export|import]' }
    }
  })

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    return renderPane($.ui.resolve(e), {
      cwd,
      cols: e.props.bodyColumns,
      profiles: await read($, profilesA),
      stored: await read($, storedA),
      grants: await read($, grantsA),
      dir: await read($, dirA),
      allGrants: await read($, allGrantsA),
      view: await read($, viewA),
      selected: await read($, selectedA),
      form: await read($, formA),
      exportSel: await read($, exportSelA),
      importPreview: await read($, importA),
      confirmDelete: await read($, confirmDeleteA),
      notice: await read($, noticeA),
      audit: await read($, auditA),
      probes: await read($, probesA),
      probing: await read($, probingA),
      usage: await read($, usageA),
      cleanup: await read($, cleanupA),
      surface: e.surface,
      now: now(),
    } as any, actions($))
  })
}
