import { expect, test } from 'claude-code/testing'
import { renderPane } from './ui'
import type { Actions, PaneState } from './ui'

const now = Date.now()
const noop = new Proxy({}, { get: () => () => {} }) as Actions
const EL = { Box: 'Box', Text: 'Text', Button: 'Button', Input: 'Input', Select: 'Select', Code: 'Code' }

// Approximate text rendering of a tree, for eyeballing layout.
const flat = (n: any): string[] => {
  if (n == null || n === false || n === true) return []
  if (typeof n === 'string' || typeof n === 'number') return [String(n)]
  if (Array.isArray(n)) return n.flatMap(c => flat(c))
  const p = n.props ?? {}
  const kids = n.children ?? p.children ?? []
  const list: any[] = Array.isArray(kids) ? kids : [kids]
  switch (n.type) {
    case 'Text': return [list.flatMap(c => flat(c)).join('')]
    case 'Code': return ['  $ ' + p.source]
    case 'Button': return [p.plain ? p.label : `[ ${p.label}${p.hotkey ? ' ·' + p.hotkey : ''} ]`]
    case 'Input': return [`${p.label ?? ''} ⟦${p.value || p.placeholder || ''}⟧`]
    case 'Select': return [`${p.label ?? ''} ‹${(p.options ?? []).find((o: any) => o.value === p.value)?.label ?? p.value}›`]
    case 'Box': {
      const parts = list.map(c => flat(c)).filter(x => x.length)
      if (p.flexDirection === 'column') {
        const out = parts.flat()
        return p.marginTop ? ['', ...out] : out
      }
      const gap = ' '.repeat(p.gap ?? 0)
      const h = Math.max(0, ...parts.map(x => x.length))
      const rows = Array.from({ length: h }, (_, i) => parts.map(x => x[i] ?? '').join(gap))
      return p.marginTop ? ['', ...rows] : rows
    }
    default: return list.flatMap(c => flat(c))
  }
}

const base = (view: PaneState['view'], cols: number, extra: Partial<PaneState> = {}): PaneState => ({
  cwd: '/Users/me/projects/demo', cols,
  profiles: {
    'prod-db': { type: 'postgres', description: '生产库只读账号，查询订单', host: '10.0.0.5', port: 5432, user: 'ro_user', secrets: ['password'], env: {} },
    'k8s-prod': { type: 'kube', secrets: ['kubeconfig'], env: {} },
    bastion: { type: 'ssh', variant: 'password', host: '1.2.3.4', user: 'deploy', secrets: ['password'], env: {} },
  },
  stored: { 'prod-db.password': true, 'k8s-prod.kubeconfig': true },
  grants: { 'prod-db': { mode: 'read', dir: '/Users/me/projects', at: now - 86400000 }, 'k8s-prod': { mode: 'write', dir: '/Users/me/projects/demo', at: now - 3600000 } },
  dir: '/Users/me/projects/demo',
  allGrants: {
    '/Users/me/projects': { 'prod-db': { mode: 'read', at: now - 86400000 } },
    '/Users/me/projects/demo': { 'k8s-prod': { mode: 'write', at: now - 3600000 } },
    '/Users/me/other': { 'old-db': { mode: 'read', at: now - 864000000 } },
  },
  view, selected: 'prod-db', form: null, exportSel: ['prod-db'],
  importPreview: null, confirmDelete: '', notice: '✔ 已授权 prod-db（本会话）',
  audit: ['10-04 12:01:02 grant prod-db', '10-04 12:03:10 exec prod-db psql -c "select 1"', '10-04 12:05:44 export prod-db'],
  probes: { 'prod-db': { ok: true, at: now - 120000, ms: 320, message: '' }, bastion: { ok: false, at: now, ms: 0, message: 'Permission denied (password).' } },
  probing: 'k8s-prod',
  usage: { 'prod-db': { count: 12, last: now - 180000 } },
  surface: 'desktop',
  cleanup: null,
  now, ...extra,
})

const cases: [string, PaneState][] = [
  ['list @100', base('list', 100)],
  ['list @60', base('list', 60)],
  ['list empty', base('list', 100, { profiles: {}, trust: 'none', notice: '' })],
  ['edit', base('edit', 100, { form: { original: 'prod-db', name: 'prod-db', description: '生产库只读', variant: 'default', type: 'postgres', host: '10.0.0.5', port: '5432', user: 'ro_user', database: 'app', secrets: 'password', env: 'PGPASSWORD={secret:password}', advanced: false } })],
  ['edit kube new', base('edit', 100, { form: { name: '', description: '', variant: 'default', type: 'kube', host: '', port: '', user: '', database: '', secrets: 'kubeconfig', env: '', advanced: false } })],
  ['edit ssh saved', base('edit', 56, { stored: { 'bastion.password': true }, form: { original: 'bastion', name: 'bastion', description: '跳板机', variant: 'password', type: 'ssh', host: '1.2.3.4', port: '22', user: 'deploy', database: '', secrets: 'key', env: '', advanced: false } })],
  ['edit custom', base('edit', 100, { form: { original: 'x', name: 'x', description: '', variant: 'default', type: 'custom', host: '', port: '', user: '', database: '', secrets: 'token', env: 'API_TOKEN={secret:token}', advanced: true } })],
  ['export', base('export', 100)],
  ['import', base('import', 100, { importPreview: { file: '/Users/x/backup-20261004.cvault', encrypted: true, items: [
    { name: 'prod-db', status: 'conflict', action: 'skip', secretCount: 1, clientVars: ['PGPASSWORD'], problems: [] },
    { name: 'redis-cache', status: 'new', action: 'add', secretCount: 1, clientVars: ['BASH_ENV'], problems: ['BASH_ENV 会让 shell 或解释器执行任意代码，不允许设置'] }] } })],
  ['audit', base('audit', 100)],
  ['grants', base('grants', 100)],
  ['grants empty', base('grants', 56, { allGrants: {} })],
  ['cleanup', base('cleanup', 100, { cleanup: [
    { key: 'grants', label: '撤销本会话的全部授权', detail: 'prod-db', count: 1, on: true },
    { key: 'orphans', label: '删除孤立的钥匙串条目', detail: 'old-db.password', count: 1, on: true },
    { key: 'audit', label: '清空审计日志', detail: '120 条记录，清空后无法恢复', count: 120, on: false },
  ] })],
  ['cleanup checking', base('cleanup', 56)],
]

test('every view draws', () => {
  for (const [, s] of cases) expect(flat(renderPane(EL, s, noop)).length).toBeGreaterThan(3)
})

// Flip DUMP to print the layouts (the test fails on purpose to show them).
const DUMP = false
test('dump layouts', () => {
  if (!DUMP) return
  const text = cases.map(([name, s]) => `\n===== ${name} =====\n` + flat(renderPane(EL, s, noop)).map(l => l.replace(/\s+$/, '')).join('\n')).join('\n')
  expect(text).toBe('')
})

for (const surface of ['terminal', 'desktop'] as const) {
  test(`real pane validates on ${surface}`, async ($: any) => {
    const ui = await $.ui.mount({
      plugin: 'vault', surface, component: 'Pane', requestId: 'vault',
      props: { title: 'Vault', isFocused: true, bodyColumns: 90, placement: 'dock', scroll: { top: 0 }, view: {} },
      viewport: { columns: 94, rows: 40 },
    })
    expect(await ui.find({ text: /还没有凭证/ })).toBeDefined()
    expect(await ui.find({ key: 'new' })).toBeDefined()
    await ui.unmount()
  })
}

// Every view through each surface's real element table: the test's own ui.render
// hook (beneath the plugin) draws each fixture, and the mount validates the tree.
for (const surface of ['terminal', 'desktop'] as const) {
  for (const cols of [100, 56]) {
    test(`all views validate on ${surface} @${cols}`, async ($: any, on: any) => {
      on('ui.render', { component: 'Pane' }, (h$: any, e: any) => {
        const found = cases.find(([name]) => `fx-${name.replace(/\W+/g, '-')}` === e.requestId)
        return renderPane(h$?.ui?.resolve?.(e) ?? EL, { ...found![1], cols: e.props.bodyColumns }, noop)
      })
      for (const [name] of cases) {
        const ui = await $.ui.mount({
          plugin: 'vault', surface, component: 'Pane', requestId: `fx-${name.replace(/\W+/g, '-')}`,
          props: { title: 'Vault', isFocused: true, bodyColumns: cols, placement: 'dock', scroll: { top: 0 }, view: {} },
          viewport: { columns: cols + 4, rows: 50 },
        })
        expect(await ui.drawn()).toBeDefined()
        expect(await ui.find({ text: /Vault/ })).toBeDefined()
        await ui.unmount()
      }
    })
  }
}
