import type { VaultDirGrants, VaultForm, VaultGrant, VaultImportPreview, VaultMode, VaultProbe, VaultProfile, VaultUsage, VaultView } from '../types'
import { TEMPLATES, envToText, exampleFor, namedVars, parseEnv, prefixOf, templateOf, variantOf } from './templates'
import type { FieldKey, SecretDef } from './templates'

export type PaneState = {
  cwd: string
  cols: number
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
  surface?: string
  now: number
}

export type Actions = {
  go: (view: VaultView) => void
  select: (name: string) => void
  setGrant: (name: string, mode: VaultMode | 'off') => void
  revokeAt: (dir: string, name: string) => void
  wipeAll: () => void
  newProfile: () => void
  editProfile: (name: string) => void
  formSet: (patch: Partial<VaultForm>) => void
  formType: (type: string) => void
  saveForm: () => void
  setSecret: (name: string, field: string) => void
  setSecretFromFile: (name: string, field: string) => void
  askDelete: (name: string) => void
  doDelete: (name: string) => void
  toggleExport: (name: string) => void
  doExport: () => void
  startImport: () => void
  importAction: (name: string, action: string) => void
  confirmImport: () => void
  cancelImport: () => void
  close: () => void
  probe: (name: string) => void
  copy: (text: string, surface?: any) => void
}

const TYPE_ICON: Record<string, string> = Object.fromEntries(Object.entries(TEMPLATES).map(([k, t]) => [k, t.icon]))

const target = (p: VaultProfile) =>
  p.host ? `${p.user ? p.user + '@' : ''}${p.host}${p.port ? ':' + p.port : ''}` : ''

const secretState = (name: string, p: VaultProfile, stored: Record<string, boolean>) => {
  const have = p.secrets.filter(f => stored[`${name}.${f}`]).length
  if (p.secrets.length === 0) return { text: '无密文', color: 'gray' }
  if (have === p.secrets.length) return { text: '密文已存', color: 'green' }
  if (have === 0) return { text: '缺少密文', color: 'red' }
  return { text: `密文 ${have}/${p.secrets.length}`, color: 'yellow' }
}

const ago = (now: number, at: number) => {
  const m = Math.max(0, Math.round((now - at) / 60000))
  if (m < 1) return '刚刚'
  if (m < 60) return `${m} 分钟前`
  const h = Math.round(m / 60)
  return h < 48 ? `${h} 小时前` : `${Math.round(h / 24)} 天前`
}

const tilde = (path: string) => path.replace(/^\/Users\/[^/]+/, '~')

const MODE_LABEL = { off: '不授权', read: '只读', write: '读写' } as const

const noticeTone = (n: string) =>
  n.startsWith('✖') ? 'red' : n.startsWith('⚠') ? 'yellow' : n.startsWith('✔') ? 'green' : 'cyan'

export function renderPane(el: unknown, s: PaneState, a: Actions) {
  const { Box, Text, Button, Input, Select, Code } = el as any
  const narrow = (s.cols || 80) < 64

  // ---------- primitives ----------
  const Badge = ({ text, color }: { text: string; color: string }) => (
    <Text color={color} bold>{`● ${text}`}</Text>
  )
  const Card = ({ k, title, tone = 'gray', children }: { k: string; title?: string; tone?: string; children?: unknown }) => (
    <Box key={k} flexDirection="column" borderStyle="round" borderColor={tone} paddingX={1} marginTop={1}>
      {title ? <Text bold color="cyan">{title}</Text> : null}
      {children}
    </Box>
  )
  const Row = ({ label, children }: { label: string; children?: unknown }) => (
    <Box gap={1} alignItems="center">
      <Box width={10} flexShrink={0}><Text dimColor>{label}</Text></Box>
      <Box flexGrow={1}>{children}</Box>
    </Box>
  )
  const Toolbar = ({ children }: { children?: unknown }) => (
    <Box gap={1} flexWrap="wrap" marginTop={1}>{children}</Box>
  )

  // ---------- header ----------
  const granted = Object.keys(s.grants)
  const dirCount = Object.keys(s.allGrants).length
  const total = Object.keys(s.profiles).length
  const crumbs: Record<VaultView, string> = {
    list: '凭证', edit: s.form?.original ? `编辑 ${s.form.original}` : '新建凭证',
    export: '导出', import: '导入', audit: '审计日志', grants: '授权管理',
  }
  const header = (
    <Box key="hdr" flexDirection="column" borderStyle="round" borderColor="cyan" paddingX={1}>
      <Box justifyContent="space-between" flexWrap="wrap">
        <Box gap={1}>
          <Text bold color="cyan">🔐 Vault</Text>
          <Text dimColor>›</Text>
          <Text bold>{crumbs[s.view]}</Text>
        </Box>
        {narrow ? null : <Text dimColor wrap="truncate-start">{tilde(s.dir || s.cwd)}</Text>}
      </Box>
      <Box gap={2} flexWrap="wrap">
        <Badge text={`当前目录已授权 ${granted.length}/${total}`} color={granted.length ? 'green' : 'gray'} />
        <Text dimColor>{`授权对目录及子目录长期有效 · 共 ${dirCount} 个目录有授权`}</Text>
      </Box>
    </Box>
  )
  const notice = s.notice ? (
    <Box key="notice" paddingX={1} marginTop={1}><Text color={noticeTone(s.notice)}>{s.notice}</Text></Box>
  ) : null

  // ---------- edit ----------
  if (s.view === 'edit' && s.form) {
    const f = s.form
    const editing = f.original ?? ''
    const t = templateOf(f.type)
    const v = variantOf(f.type, f.variant)
    const custom = f.advanced || f.type === 'custom'
    const secretNames = custom ? f.secrets.split(',').map(x => x.trim()).filter(Boolean) : v.secrets.map(d => d.name)
    const secretDefs: SecretDef[] = secretNames.map(name => v.secrets.find(d => d.name === name) ?? { name, label: name })
    const input = (key: string, value: string, prop: keyof VaultForm, placeholder = '') => (
      <Input key={key} value={value} placeholder={placeholder}
        onInput={(x: string) => a.formSet({ [prop]: x } as Partial<VaultForm>)}
        onSubmit={(x: string) => a.formSet({ [prop]: x } as Partial<VaultForm>)} />
    )
    const Field = ({ label, required, hint, children }: { label: string; required?: boolean; hint?: string; children?: unknown }) => (
      <Box flexDirection="column" marginTop={1}>
        <Box gap={1}>
          <Text bold>{label}</Text>
          {required ? <Text color="red">*</Text> : null}
          {hint ? <Text dimColor>{hint}</Text> : null}
        </Box>
        {children}
      </Box>
    )
    const describe = (tpl: string) =>
      tpl.replace(/\{secretfile:([\w-]+)\}/g, (_, n) => `🔒 ${n}（临时文件路径）`)
        .replace(/\{secret:([\w-]+)\}/g, (_, n) => `🔒 ${n}（来自钥匙串）`)
        .replace(/\{askpass\}/g, '自动应答密码的 askpass 程序')
        .replace(/\{(host|port|user|database)\}/g, (_, k: FieldKey) => f[k] || '（空）')
    const displayName = f.name.trim() || 'name'
    const named = Object.entries(namedVars(displayName, { type: f.type, variant: v.key, secrets: secretNames, host: f.host, port: f.port, user: f.user, database: f.database }, true))
    const client = Object.entries(custom ? parseEnv(f.env) : v.env)
    const example = exampleFor(v.example, displayName)
    const usage = `vault_exec(profile: "${displayName}", command: ${JSON.stringify(example)})`
    const VarRow = ({ k, tpl }: { k: string; tpl: string }) => (
      <Box gap={1}>
        <Box width={24} flexShrink={0}><Text color="cyan">{k}</Text></Box>
        <Text dimColor wrap="truncate-end">{describe(tpl)}</Text>
      </Box>
    )

    return (
      <Box flexDirection="column">
        {header}
        {notice}

        <Card k="c-type" title="类型">
          <Box gap={1} flexWrap="wrap">
            {Object.entries(TEMPLATES).map(([k, tp]) => (
              <Button key={`t-${k}`} label={`${tp.icon} ${tp.label}`} variant={k === f.type ? 'primary' : 'secondary'}
                onPress={() => k !== f.type && a.formType(k)} />
            ))}
          </Box>
          <Text dimColor>{t.summary}</Text>
        </Card>

        <Card k="c-conn" title="基本信息">
          <Field label="名称" required hint={`小写字母、数字、- 和 _；变量前缀 ${prefixOf(displayName)}_`}>{input('f-name', f.name, 'name', 'prod-db')}</Field>
          <Field label="描述" hint="可选，Claude 会据此选择 profile">{input('f-desc', f.description, 'description', '生产库只读账号，用于查询订单数据')}</Field>
          {t.fields.map(fd => (
            <Field label={fd.label} required={fd.required} hint={fd.hint}>
              {input(`f-${fd.key}`, f[fd.key], fd.key, fd.placeholder ?? '')}
            </Field>
          ))}
        </Card>

        <Card k="c-sec" title={t.variants.length > 1 ? '认证' : '密文'}>
          {t.variants.length > 1 ? (
            <Box flexDirection="column">
              <Box gap={1} alignItems="center" flexWrap="wrap">
                <Text bold>认证方式</Text>
                {t.variants.map(x => (
                  <Button key={`var-${x.key}`} label={x.label} variant={x.key === v.key ? 'primary' : 'secondary'}
                    onPress={() => x.key !== v.key && a.formSet({ variant: x.key, advanced: false, secrets: x.secrets.map(d => d.name).join(','), env: envToText(x.env) })} />
                ))}
              </Box>
              {v.hint ? <Text dimColor>{v.hint}</Text> : null}
            </Box>
          ) : null}
          {secretDefs.map(d => {
            const ok = !!(editing && s.stored[`${editing}.${d.name}`])
            return (
              <Box key={`f-row-${d.name}`} flexDirection="column" marginTop={1}>
                <Box gap={1} alignItems="center" flexWrap="wrap">
                  <Box width={14} flexShrink={0}><Text bold>{d.label}</Text></Box>
                  {editing
                    ? <Badge text={ok ? '已存入钥匙串' : '未设置'} color={ok ? 'green' : 'red'} />
                    : <Text dimColor>创建后可设置</Text>}
                  {editing && d.file
                    ? <Button key={`f-file-${d.name}`} label={ok ? '重新选择文件' : '从文件读取'} variant={ok ? 'secondary' : 'primary'} onPress={() => a.setSecretFromFile(editing, d.name)} />
                    : null}
                  {editing
                    ? <Button key={`f-set-${d.name}`} label={d.file ? '手动输入' : ok ? '重新设置' : '设置'} variant={!d.file && !ok ? 'primary' : 'secondary'} onPress={() => a.setSecret(editing, d.name)} />
                    : null}
                  {editing && !d.file
                    ? <Button key={`f-file-${d.name}`} label="从文件读取" onPress={() => a.setSecretFromFile(editing, d.name)} />
                    : null}
                </Box>
                {d.hint ? <Text dimColor>{d.hint}</Text> : null}
              </Box>
            )
          })}
          <Text dimColor>密文只通过系统掩码输入框或文件写入 macOS 钥匙串，不会显示，也不会进入对话。</Text>
        </Card>

        <Card k="c-env" title="环境变量">
          <Text bold>专属变量</Text>
          <Text dimColor>以名称为前缀，每个 profile 独有，互不冲突；在 Bash 里直接引用即可注入</Text>
          {named.map(([k, tpl]) => <VarRow k={k} tpl={tpl} />)}
          <Box marginTop={1}><Text bold>客户端变量</Text></Box>
          <Text dimColor>客户端工具自动识别的标准变量，只在 vault_exec 或命令首行 #vault:{displayName} 时注入</Text>
          {client.length ? client.map(([k, tpl]) => <VarRow k={k} tpl={tpl} />) : <Text dimColor>（无）</Text>}
          {custom ? (
            <Box flexDirection="column">
              <Field label="密文字段" hint="逗号分隔">{input('f-secrets', f.secrets, 'secrets', 'password,token')}</Field>
              <Field label="客户端变量映射" hint="KEY=模板，用 ; 分隔">{input('f-env', f.env, 'env', 'API_TOKEN={secret:token}; API_HOST={host}')}</Field>
              <Text dimColor>{'占位符：{host} {port} {user} {database} {secret:字段} {secretfile:字段}'}</Text>
            </Box>
          ) : null}
          {f.type !== 'custom' ? (
            <Box marginTop={1}>
              <Button key="f-adv" plain label={custom ? '↺ 恢复为模板' : '⚙ 自定义密文字段和客户端变量（高级）'}
                onPress={() => a.formSet(custom
                  ? { advanced: false, secrets: v.secrets.map(x => x.name).join(','), env: envToText(v.env) }
                  : { advanced: true })} />
            </Box>
          ) : null}
        </Card>

        <Card k="c-ex" title="Claude 的用法">
          <Code source={usage} language="text" />
          <Box gap={1} marginTop={1} flexWrap="wrap">
            <Button key="f-copy" label="复制用法" onPress={() => a.copy(usage, s.surface)} />
            {editing && v.probe
              ? <Button key="f-probe" label={s.probing === editing ? '测试中…' : '测试连接'} onPress={() => s.probing !== editing && a.probe(editing)} />
              : null}
            {editing && s.probes[editing]
              ? <Text color={s.probes[editing].ok ? 'green' : 'red'} wrap="truncate-end">
                  {s.probes[editing].ok ? `✔ 连接正常 · ${s.probes[editing].ms}ms` : `✖ ${s.probes[editing].message}`}
                </Text>
              : null}
          </Box>
          <Text dimColor>或在 Bash 中直接引用专属变量；需要客户端变量时在首行写 #vault:{displayName}</Text>
        </Card>

        <Toolbar>
          <Button key="f-save" label={editing ? '保存修改' : '创建'} hotkey="s" variant="primary" onPress={() => a.saveForm()} />
          <Button key="f-cancel" label="返回" hotkey="b" role="dismiss" onPress={() => a.go('list')} />
          {editing ? (s.confirmDelete === editing
            ? <Button key="f-del-yes" label="确认删除（同时删除钥匙串）" onPress={() => a.doDelete(editing)} />
            : <Button key="f-del" label="删除" onPress={() => a.askDelete(editing)} />) : null}
        </Toolbar>
      </Box>
    )
  }

  // ---------- export ----------
  if (s.view === 'export') {
    const names = Object.keys(s.profiles).sort()
    return (
      <Box flexDirection="column">
        {header}
        {notice}
        <Card k="c-pick" title={`选择 profile（${s.exportSel.length}/${names.length}）`}>
          {names.length === 0 ? <Text dimColor>还没有 profile。</Text> : null}
          {names.map(n => (
            <Box key={`x-row-${n}`} gap={1} alignItems="center">
              <Button key={`x-${n}`} plain label={`${s.exportSel.includes(n) ? '☑' : '☐'}  ${n}`} onPress={() => a.toggleExport(n)} />
              <Text dimColor>{TYPE_ICON[s.profiles[n].type] ?? ''} {s.profiles[n].type}</Text>
            </Box>
          ))}
        </Card>
        <Text dimColor>导出为 .cvault 加密包，包含配置和密文；需要设置口令（至少 12 位），导入时输入同一个口令。</Text>
        <Toolbar>
          <Button key="x-go" label={`导出 ${s.exportSel.length} 项`} variant="primary" hotkey="x" onPress={() => s.exportSel.length && a.doExport()} />
          <Button key="x-back" label="返回" hotkey="b" role="dismiss" onPress={() => a.go('list')} />
        </Toolbar>
      </Box>
    )
  }

  // ---------- import ----------
  if (s.view === 'import' && s.importPreview) {
    const p = s.importPreview
    const st = { new: { t: '新增', c: 'green' }, conflict: { t: '冲突', c: 'yellow' }, same: { t: '相同', c: 'gray' } }
    return (
      <Box flexDirection="column">
        {header}
        {notice}
        <Card k="c-file" title="文件">
          <Box gap={2} flexWrap="wrap">
            <Text bold>{p.file.split('/').pop() ?? p.file}</Text>
            <Badge text={p.encrypted ? '加密包' : '仅元数据'} color={p.encrypted ? 'green' : 'gray'} />
          </Box>
        </Card>
        <Card k="c-items" title={`逐条确认（${p.items.length}）`}>
          {p.items.map(it => (
            <Box key={`i-row-${it.name}`} gap={1} alignItems="center" flexWrap="wrap">
              <Box width={18} flexShrink={0}><Text bold>{it.name}</Text></Box>
              <Box width={8} flexShrink={0}><Badge text={st[it.status].t} color={st[it.status].c} /></Box>
              <Box width={8} flexShrink={0}><Text dimColor>{`密文 ${it.secretCount}`}</Text></Box>
              <Select key={`i-${it.name}`} value={it.action}
                options={it.status === 'new'
                  ? [{ value: 'add', label: '导入' }, { value: 'skip', label: '跳过' }]
                  : [{ value: 'overwrite', label: '覆盖' }, { value: 'skip', label: '跳过' }, { value: 'rename', label: '另存为 -imported' }]}
                onSelect={(v: string) => a.importAction(it.name, v)} />
            </Box>
          ))}
          {p.items.filter(it => it.clientVars.length || it.problems.length).map(it => (
            <Box key={`i-vars-${it.name}`} flexDirection="column" marginTop={1}>
              <Text dimColor wrap="truncate-end">{`${it.name} 的客户端变量：${it.clientVars.join(' ') || '（无）'}`}</Text>
              {it.problems.map((why, i) => <Text key={`i-pb-${it.name}-${i}`} color="red">{`✖ ${why}，导入时会跳过`}</Text>)}
            </Box>
          ))}
          <Text dimColor>导入不会授权任何目录，需要时在列表卡片上授权。</Text>
        </Card>
        <Toolbar>
          <Button key="i-go" label="确认导入" variant="primary" onPress={() => a.confirmImport()} />
          <Button key="i-cancel" label="取消" role="dismiss" onPress={() => a.cancelImport()} />
        </Toolbar>
      </Box>
    )
  }

  // ---------- grants ----------
  if (s.view === 'grants') {
    const dirs = Object.keys(s.allGrants).sort()
    const here = s.dir || s.cwd
    return (
      <Box flexDirection="column">
        {header}
        {notice}
        {dirs.length === 0 ? (
          <Card k="g-empty" title="还没有任何授权">
            <Text dimColor>在列表卡片上点「只读」或「读写」，就会授权给当前目录及其子目录。</Text>
          </Card>
        ) : null}
        {dirs.map(d => {
          const entries = s.allGrants[d]
          const applies = here === d || here.startsWith(d.endsWith('/') ? d : `${d}/`)
          return (
            <Card key={`g-${d}`} k={`g-${d}`} title={tilde(d)} tone={applies ? 'green' : 'gray'}>
              {applies ? <Text color="green">{here === d ? '● 当前目录' : '● 当前目录的上级，对当前目录生效'}</Text> : null}
              {Object.entries(entries).sort().map(([n, g]) => (
                <Box key={`g-${d}-${n}`} gap={1} alignItems="center">
                  <Box width={20} flexShrink={0}><Text bold>{n}</Text></Box>
                  <Box width={6} flexShrink={0}><Text color={g.mode === 'write' ? 'yellow' : 'cyan'}>{MODE_LABEL[g.mode]}</Text></Box>
                  <Text dimColor>{`授权于 ${ago(s.now, g.at)}`}</Text>
                  {s.profiles[n] ? null : <Text color="red">profile 已删除</Text>}
                  <Button key={`g-rv-${d}-${n}`} label="撤销" onPress={() => a.revokeAt(d, n)} />
                </Box>
              ))}
            </Card>
          )
        })}
        <Toolbar>
          <Button key="g-back" label="返回" hotkey="b" role="dismiss" onPress={() => a.go('list')} />
        </Toolbar>
      </Box>
    )
  }

  // ---------- audit ----------
  if (s.view === 'audit') {
    const tone = (ev: string) =>
      /delete|revoke/.test(ev) ? 'red' : /grant|trust/.test(ev) ? 'green' : /export|import/.test(ev) ? 'magenta' : 'cyan'
    return (
      <Box flexDirection="column">
        {header}
        {notice}
        <Card k="c-audit" title={`最近 ${s.audit.length} 条`}>
          {s.audit.length === 0 ? <Text dimColor>暂无记录。</Text> : null}
          {s.audit.map((l, i) => {
            const [d, t, event = '', ...rest] = l.split(' ')
            return (
              <Box key={`a-${i}`} gap={1}>
                <Box width={15} flexShrink={0}><Text dimColor>{`${d} ${t}`}</Text></Box>
                <Box width={14} flexShrink={0}><Text color={tone(event)} bold>{event}</Text></Box>
                <Text wrap="truncate-end">{rest.join(' ')}</Text>
              </Box>
            )
          })}
        </Card>
        <Toolbar>
          <Button key="a-back" label="返回" hotkey="b" role="dismiss" onPress={() => a.go('list')} />
        </Toolbar>
      </Box>
    )
  }

  // ---------- list ----------
  const names = Object.keys(s.profiles).sort()
  return (
    <Box flexDirection="column">
      {header}
      {notice}
      {names.length === 0 ? (
        <Card k="c-empty" title="还没有凭证">
          <Text><Text color="cyan" bold>1 </Text>点「新建」，选类型模板，填主机和用户</Text>
          <Text><Text color="cyan" bold>2 </Text>在编辑页点「设置」，用系统掩码框把密文写进钥匙串</Text>
          <Text><Text color="cyan" bold>3 </Text>在卡片上点「只读」或「读写」授权给当前目录，Claude 就能通过 vault_exec 使用</Text>
          <Text dimColor>已有备份？点「导入」选择 .cvault 或模板 .json</Text>
        </Card>
      ) : (
        names.map(n => {
          const p = s.profiles[n]
          const g = s.grants[n]
          const inherited = g && g.dir !== (s.dir || s.cwd)
          const sec = secretState(n, p, s.stored)
          const sel = s.selected === n
          const probe = s.probes[n]
          const use = s.usage[n]
          const canProbe = !!variantOf(p.type, p.variant).probe
          const missingSecret = sec.color === 'red' || sec.color === 'yellow'
          const grantBadge = g
            ? { text: `已授权 · ${MODE_LABEL[g.mode]}`, color: g.mode === 'write' ? 'yellow' : 'green' }
            : { text: '未授权', color: 'gray' }
          const info = (
            <Box flexDirection="column" flexGrow={1}>
              <Box gap={1} alignItems="center">
                <Text>{TYPE_ICON[p.type] ?? '🧩'}</Text>
                <Button key={`sel-${n}`} plain label={n} onPress={() => a.select(n)} />
                <Text dimColor>{p.type}{p.type === 'ssh' ? ` · ${variantOf(p.type, p.variant).label}` : ''}</Text>
              </Box>
              <Text dimColor wrap="truncate-end">{target(p) || '—'}</Text>
              {p.description ? <Text wrap="truncate-end">{p.description}</Text> : null}
              {probe
                ? <Text color={probe.ok ? 'green' : 'red'} wrap="truncate-end">
                    {probe.ok ? `✔ 连接正常 · ${probe.ms}ms · ${ago(s.now, probe.at)}` : `✖ ${probe.message}`}
                  </Text>
                : null}
              <Text dimColor>{use ? `最近使用 ${ago(s.now, use.last)} · 共 ${use.count} 次` : '尚未被 Claude 使用'}</Text>
            </Box>
          )
          const side = (
            <Box flexDirection="column" alignItems={narrow ? 'flex-start' : 'flex-end'} flexShrink={0}>
              <Box gap={2}>
                <Badge text={sec.text} color={sec.color} />
                <Badge text={grantBadge.text} color={grantBadge.color} />
              </Box>
              <Box gap={1}>
                {canProbe && !missingSecret
                  ? <Button key={`pr-${n}`} label={s.probing === n ? '测试中…' : '测试连接'} onPress={() => s.probing !== n && a.probe(n)} />
                  : null}
                <Button key={`ed-${n}`} label="编辑" onPress={() => a.editProfile(n)} />
                {missingSecret
                  ? <Button key={`gr-${n}`} label="先设置密文" variant="primary" onPress={() => a.editProfile(n)} />
                  : null}
              </Box>
            </Box>
          )
          const current = g?.mode ?? 'off'
          const access = (
            <Box gap={1} alignItems="center" flexWrap="wrap" marginTop={1}>
              <Box width={10} flexShrink={0}><Text dimColor>当前目录</Text></Box>
              {missingSecret && !g ? (
                <Text color="yellow">缺少密文，设置后才能授权</Text>
              ) : (
                (['off', 'read', 'write'] as const).map(m => (
                  <Button key={`gt-${n}-${m}`} label={MODE_LABEL[m]} variant={current === m ? 'primary' : 'secondary'}
                    onPress={() => current !== m && a.setGrant(n, m)} />
                ))
              )}
              {inherited ? <Text dimColor wrap="truncate-start">{`继承自 ${tilde(g.dir)}`}</Text> : null}
              {p.type === 'ssh' && g?.mode === 'read'
                ? <Text color="yellow">只读不会拦截 SSH 上执行的命令，建议在服务器上用受限账号</Text>
                : null}
            </Box>
          )
          return (
            <Box key={`card-${n}`} flexDirection="column" borderStyle="round" borderColor={sel ? 'cyan' : g ? 'green' : 'gray'}
              hover={{ borderColor: 'cyan' }} paddingX={1} marginTop={1}>
              <Box gap={2} flexDirection={narrow ? 'column' : 'row'} justifyContent="space-between">
                {info}
                {side}
              </Box>
              {access}
            </Box>
          )
        })
      )}

      <Toolbar>
        <Button key="new" label="＋ 新建" hotkey="n" variant="primary" onPress={() => a.newProfile()} />
        <Button key="import" label="导入" hotkey="i" onPress={() => a.startImport()} />
        <Button key="export" label="导出" hotkey="x" onPress={() => a.go('export')} />
        <Button key="grants" label="授权管理" hotkey="g" onPress={() => a.go('grants')} />
        <Button key="audit" label="审计日志" hotkey="l" onPress={() => a.go('audit')} />
        <Button key="cleanup" label="🧹 一键清理" hotkey="c" onPress={() => a.wipeAll()} />
        <Button key="close" label="关闭" role="dismiss" onPress={() => a.close()} />
      </Toolbar>
    </Box>
  )
}
