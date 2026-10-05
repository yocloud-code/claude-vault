import type { VaultProfile } from '../types'

export type FieldKey = 'host' | 'port' | 'user' | 'database'

/** A connection field the type's form shows. `suffix` names its per-profile variable (`<NAME>_<suffix>`). */
export type FieldDef = { key: FieldKey; label: string; placeholder?: string; required?: boolean; hint?: string; suffix?: string }

/** A secret the profile holds. A `file` secret reaches commands as a 0600 temp file path. */
export type SecretDef = { name: string; label: string; file?: boolean; hint?: string }

/**
 * One way of authenticating with the type (SSH: key or password). `env` is the client's own
 * standard variables (PGPASSWORD, KUBECONFIG, ...), injected only when the profile is chosen
 * explicitly; the per-profile `<NAME>_*` variables are derived from fields and secrets.
 */
export type Variant = {
  key: string; label: string; secrets: SecretDef[]; env: Record<string, string>; example: string; hint?: string
  /** A read-only command that succeeds (exit 0) when the connection works; `${P}` as in `example`. */
  probe?: string
  /** Per-profile variables computed when a command runs (`TOKEN: '{supabase_token}'` → `<PREFIX>_TOKEN`). */
  derived?: Record<string, string>
}

export type Template = { label: string; icon: string; summary: string; fields: FieldDef[]; port?: number; variants: Variant[] }

const one = (v: Omit<Variant, 'key' | 'label'>): Variant[] => [{ key: 'default', label: '默认', ...v }]

export const TEMPLATES: Record<string, Template> = {
  postgres: {
    label: 'PostgreSQL', icon: '🐘', summary: 'psql / pg_dump 直接可用', port: 5432,
    fields: [
      { key: 'host', label: '主机', placeholder: 'db.internal 或 10.0.0.5', required: true },
      { key: 'port', label: '端口', placeholder: '5432' },
      { key: 'user', label: '用户', placeholder: 'readonly_user', required: true, hint: '建议使用只读账号' },
      { key: 'database', label: '数据库', placeholder: 'app' },
    ],
    variants: one({
      secrets: [{ name: 'password', label: '密码' }],
      env: { PGHOST: '{host}', PGPORT: '{port}', PGUSER: '{user}', PGDATABASE: '{database}', PGPASSWORD: '{secret:password}' },
      example: `psql -c 'select now()'`,
      probe: `psql -X -A -t -c 'select 1'`,
    }),
  },
  mysql: {
    label: 'MySQL', icon: '🐬', summary: 'mysql 客户端直接可用', port: 3306,
    fields: [
      { key: 'host', label: '主机', placeholder: 'db.internal', required: true },
      { key: 'port', label: '端口', placeholder: '3306' },
      { key: 'user', label: '用户', placeholder: 'readonly_user', required: true, hint: '建议使用只读账号' },
      { key: 'database', label: '数据库', placeholder: 'app' },
    ],
    variants: one({
      secrets: [{ name: 'password', label: '密码' }],
      env: { MYSQL_HOST: '{host}', MYSQL_TCP_PORT: '{port}', MYSQL_PWD: '{secret:password}' },
      example: `mysql -u "\${P}_USER" "\${P}_DATABASE" -e 'select 1'`,
      probe: `mysql -u "\${P}_USER" -e 'select 1'`,
    }),
  },
  redis: {
    label: 'Redis', icon: '🟥', summary: 'redis-cli 免输密码', port: 6379,
    fields: [
      { key: 'host', label: '主机', placeholder: 'cache.internal', required: true },
      { key: 'port', label: '端口', placeholder: '6379' },
      { key: 'user', label: 'ACL 用户', placeholder: '留空表示 default' },
      { key: 'database', label: 'DB 编号', placeholder: '0', suffix: 'DB' },
    ],
    variants: one({
      secrets: [{ name: 'password', label: '密码' }],
      env: { REDISCLI_AUTH: '{secret:password}' },
      example: `redis-cli -h "\${P}_HOST" -p "\${P}_PORT" ping`,
      probe: `redis-cli -h "\${P}_HOST" -p "\${P}_PORT" ping | grep -q PONG`,
    }),
  },
  mongo: {
    label: 'MongoDB', icon: '🍃', summary: '整条连接串作为密文保存',
    fields: [
      { key: 'host', label: '集群', placeholder: 'cluster0.example.net（仅用于展示）', suffix: 'CLUSTER' },
      { key: 'database', label: '数据库', placeholder: 'app' },
    ],
    variants: one({
      secrets: [{ name: 'uri', label: '连接串', hint: 'mongodb+srv://user:pass@host/db' }],
      env: { MONGODB_URI: '{secret:uri}' },
      example: `mongosh "\${P}_URI" --eval 'db.runCommand({ ping: 1 })'`,
      probe: `mongosh "\${P}_URI" --quiet --eval 'db.runCommand({ ping: 1 }).ok'`,
    }),
  },
  ssh: {
    label: 'SSH 服务器', icon: '🖥', summary: '支持私钥或密码登录', port: 22,
    fields: [
      { key: 'host', label: '主机', placeholder: 'bastion.example.com', required: true },
      { key: 'port', label: '端口', placeholder: '22' },
      { key: 'user', label: '用户', placeholder: 'deploy', required: true },
    ],
    variants: [
      {
        key: 'key', label: '私钥',
        secrets: [{ name: 'key', label: '私钥', file: true, hint: '用「从文件读取」选择私钥文件；命令执行时写入 0600 临时文件，结束即删除' }],
        env: { GIT_SSH_COMMAND: 'ssh -i {secretfile:key} -o IdentitiesOnly=yes -p {port}' },
        example: `ssh -i "\${P}_KEY_FILE" -o IdentitiesOnly=yes -p "\${P}_PORT" "\${P}_USER@\${P}_HOST" uptime`,
        probe: `ssh -i "\${P}_KEY_FILE" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new -p "\${P}_PORT" "\${P}_USER@\${P}_HOST" true`,
      },
      {
        key: 'password', label: '密码',
        secrets: [{ name: 'password', label: '密码' }],
        env: { SSHPASS: '{secret:password}', SSH_ASKPASS: '{askpass}', SSH_ASKPASS_REQUIRE: 'force' },
        example: `ssh -o StrictHostKeyChecking=accept-new -p "\${P}_PORT" "\${P}_USER@\${P}_HOST" uptime`,
        probe: `ssh -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 -p "\${P}_PORT" "\${P}_USER@\${P}_HOST" true`,
        hint: '通过 SSH_ASKPASS 自动应答密码（需要 OpenSSH 8.4+），不需要安装 sshpass；只在 vault_exec 或 #vault: 指定时生效',
      },
    ],
  },
  kube: {
    label: 'Kubernetes', icon: '☸', summary: 'kubeconfig 写入临时文件并设置 KUBECONFIG',
    fields: [
      { key: 'host', label: '集群', placeholder: 'prod-cluster（仅用于展示）', suffix: 'CLUSTER' },
      { key: 'database', label: '命名空间', placeholder: 'default', suffix: 'NAMESPACE' },
    ],
    variants: one({
      secrets: [{ name: 'kubeconfig', label: 'kubeconfig', file: true, hint: '用「从文件读取」选择 kubeconfig 文件' }],
      env: { KUBECONFIG: '{secretfile:kubeconfig}' },
      example: `kubectl -n "\${\${P}_NAMESPACE:-default}" get pods`,
      probe: `kubectl get --raw /version --request-timeout=8s`,
    }),
  },
  supabase: {
    label: 'Supabase 账号', icon: '🟩', summary: '用账号密码登录 Supabase，注入访问令牌；密码和令牌都不会出现在对话里',
    fields: [
      { key: 'host', label: '项目地址', placeholder: 'https://xxxx.supabase.co', required: true, suffix: 'URL' },
      { key: 'user', label: '登录邮箱', placeholder: 'ops3.accountant@example.test', required: true, suffix: 'EMAIL' },
    ],
    variants: one({
      secrets: [
        { name: 'password', label: '密码' },
        { name: 'anon_key', label: 'anon key', hint: '项目的公开 anon key（Supabase 控制台 → Project Settings → API），登录接口需要它' },
      ],
      env: { SUPABASE_URL: '{host}', SUPABASE_ANON_KEY: '{secret:anon_key}', SUPABASE_ACCESS_TOKEN: '{supabase_token}' },
      derived: { TOKEN: '{supabase_token}' },
      example: `curl -s "\${P}_URL/rest/v1/<表名>?select=*&limit=5" -H "apikey: \${P}_ANON_KEY" -H "Authorization: Bearer \${P}_TOKEN"`,
      probe: `curl -fsS --max-time 8 -o /dev/null "\${P}_URL/auth/v1/user" -H "apikey: \${P}_ANON_KEY" -H "Authorization: Bearer \${P}_TOKEN"`,
      hint: '每次执行命令时由 Mod 用账号密码登录，令牌只在这一条命令里有效；同一条命令可以同时使用多个账号',
    }),
  },
  'http-token': {
    label: 'HTTP API Token', icon: '🔑', summary: 'API 地址和 Token，配合 curl 使用',
    fields: [
      { key: 'host', label: 'Base URL', placeholder: 'https://api.example.com', required: true, suffix: 'URL' },
    ],
    variants: one({
      secrets: [{ name: 'token', label: 'Token' }],
      env: {},
      example: `curl -H "Authorization: Bearer \${P}_TOKEN" "\${P}_URL/health"`,
      probe: `curl -fsS -o /dev/null --max-time 8 -H "Authorization: Bearer \${P}_TOKEN" "\${P}_URL"`,
    }),
  },
  custom: {
    label: '自定义', icon: '🧩', summary: '自由定义字段、密文和客户端变量',
    fields: [
      { key: 'host', label: '主机' },
      { key: 'port', label: '端口' },
      { key: 'user', label: '用户' },
      { key: 'database', label: '库名' },
    ],
    variants: one({
      secrets: [{ name: 'secret', label: '密文' }],
      env: {},
      example: `some-cli --token "\${P}_SECRET"`,
    }),
  },
}

export const templateOf = (type: string) => TEMPLATES[type] ?? TEMPLATES.custom

export const variantOf = (type: string, variant?: string) => {
  const t = templateOf(type)
  return t.variants.find(v => v.key === variant) ?? t.variants[0]
}

/** The variable prefix a profile name gives: `prod-db` → `PROD_DB`. */
export const prefixOf = (name: string) => name.toUpperCase().replace(/[^A-Z0-9]/g, '_')

/** `${P}` in an example becomes `$PREFIX` (and `${${P}_X:-d}` becomes `${PREFIX_X:-d}`). */
export const exampleFor = (example: string, name: string) =>
  example.replace(/\$\{\$\{P\}/g, '${' + prefixOf(name)).replace(/\$\{P\}/g, '$' + prefixOf(name))

/**
 * The per-profile variables: `<PREFIX>_<FIELD>` for each connection field of its type that has a
 * value (or every field with `all`), and `<PREFIX>_<SECRET>` (`_FILE` for a file secret) per secret.
 */
export const namedVars = (name: string, p: Pick<VaultProfile, 'type' | 'variant' | 'secrets'> & Partial<Record<FieldKey, unknown>>, all = false) => {
  const P = prefixOf(name)
  const t = templateOf(p.type)
  const defs = variantOf(p.type, p.variant).secrets
  const out: Record<string, string> = {}
  for (const f of t.fields) {
    if (all || (p[f.key] !== undefined && p[f.key] !== '')) out[`${P}_${f.suffix ?? f.key.toUpperCase()}`] = `{${f.key}}`
  }
  for (const s of p.secrets) {
    const file = defs.find(d => d.name === s)?.file
    out[`${P}_${prefixOf(s)}${file ? '_FILE' : ''}`] = file ? `{secretfile:${s}}` : `{secret:${s}}`
  }
  for (const [suffix, tpl] of Object.entries(variantOf(p.type, p.variant).derived ?? {})) out[`${P}_${suffix}`] = tpl
  return out
}

/** Templates whose value is secret: Keychain values and anything derived from them. */
export const isSecretTemplate = (tpl: string) => /\{(secret|secretfile|supabase_token)\b/.test(tpl)

export const envToText = (env: Record<string, string>) =>
  Object.entries(env).map(([k, v]) => `${k}=${v}`).join('; ')

export const parseEnv = (text: string) => {
  const env: Record<string, string> = {}
  for (const part of text.split(/[;\n]/)) {
    const m = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(part)
    if (m) env[m[1]] = m[2]
  }
  return env
}

/** A profile uses its template unchanged unless its secrets or client variables differ. */
export const isDefaultMapping = (p: Pick<VaultProfile, 'type' | 'variant' | 'secrets' | 'env'>) => {
  const v = variantOf(p.type, p.variant)
  return p.type !== 'custom'
    && JSON.stringify(p.secrets) === JSON.stringify(v.secrets.map(s => s.name))
    && JSON.stringify(p.env) === JSON.stringify(v.env)
}

/** Required fields of the type missing in the form, by label. */
export const missingFields = (type: string, values: Record<FieldKey, string>) =>
  templateOf(type).fields.filter(f => f.required && !values[f.key].trim()).map(f => f.label)

// Variables a client mapping may never set: each makes the shell, the dynamic loader or an
// interpreter run code of the setter's choosing (BASH_ENV runs a file on every `bash -c`).
const DANGEROUS = /^(BASH_ENV|ENV|BASH_FUNC_.*|SHELLOPTS|BASHOPTS|PROMPT_COMMAND|PS[0-4]|IFS|CDPATH|PATH|HOME|SHELL|TMPDIR|ZDOTDIR|LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT|DYLD_.*|NODE_OPTIONS|NODE_PATH|PYTHONSTARTUP|PYTHONPATH|PYTHONHOME|PERL5OPT|PERL5LIB|RUBYOPT|RUBYLIB|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS)$/

// Variables that name a program to run: allowed only with a value one of the templates itself uses.
const PROGRAM_VARS = new Set(['SSH_ASKPASS', 'GIT_SSH_COMMAND', 'GIT_SSH', 'GIT_ASKPASS', 'EDITOR', 'VISUAL', 'PAGER', 'GIT_PAGER', 'GIT_EXTERNAL_DIFF', 'LESSOPEN', 'LESSCLOSE', 'SUDO_ASKPASS'])

const templateValues = (key: string) =>
  new Set(Object.values(TEMPLATES).flatMap(t => t.variants.map(v => v.env[key]).filter((x): x is string => x !== undefined)))

/** Why a client variable may not be set this way, or undefined when it may. */
export const envProblem = (key: string, tpl: string): string | undefined => {
  if (DANGEROUS.test(key)) return `${key} 会让 shell 或解释器执行任意代码，不允许设置`
  if (PROGRAM_VARS.has(key) && !templateValues(key).has(tpl)) return `${key} 会指定要执行的程序，只能使用模板自带的值`
  return undefined
}

/** Every problem of a client mapping, as `KEY: reason` lines. */
export const envProblems = (env: Record<string, string>) =>
  Object.entries(env).flatMap(([k, v]) => {
    const why = envProblem(k, v)
    return why ? [why] : []
  })

/**
 * What is wrong with a secret's content for its type, or undefined. Catches truncated pastes:
 * a kubeconfig whose user has a certificate but no key, a private key without its end line.
 */
export const secretProblem = (type: string, field: string, value: string): string | undefined => {
  const v = value.trim()
  if (!v) return '内容为空'
  if (type === 'kube' && field === 'kubeconfig') return kubeconfigProblem(v)
  if (type === 'ssh' && field === 'key') {
    if (!/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(v)) return '不是私钥文件：缺少 BEGIN PRIVATE KEY 行'
    if (!/-----END [A-Z ]*PRIVATE KEY-----\s*$/.test(v)) return '私钥不完整：缺少 END PRIVATE KEY 行（多半是粘贴被截断）'
    return undefined
  }
  if (type === 'supabase' && field === 'anon_key' && !/^[\w-]+\.[\w-]+\.[\w-]+$/.test(v) && !/^sb_publishable_/.test(v)) {
    return 'anon key 格式不对：应为 eyJ… 开头的 JWT 或 sb_publishable_ 开头的密钥'
  }
  return undefined
}

// A kubeconfig in YAML or JSON. Each user with a client certificate needs its key, inline or as
// a path; inline key data that is too short or not base64 was cut off.
const kubeconfigProblem = (v: string): string | undefined => {
  const truncated = 'kubeconfig 不完整：有 client-certificate-data 却没有 client-key-data（多半是粘贴被截断）'
  const shortKey = 'kubeconfig 不完整：client-key-data 内容被截断'
  const badKey = (data: string) => data.length < 100 || !/^[A-Za-z0-9+/=]+$/.test(data)
  if (v.startsWith('{')) {
    let doc: { clusters?: unknown; users?: { user?: Record<string, unknown> }[] }
    try { doc = JSON.parse(v) } catch { return 'kubeconfig 不完整：JSON 无法解析' }
    if (!Array.isArray(doc.clusters) || !Array.isArray(doc.users)) return 'kubeconfig 不完整：缺少 clusters 或 users 段'
    for (const u of doc.users) {
      const user = u?.user ?? {}
      if (user['client-certificate-data'] && !user['client-key-data'] && !user['client-key']) return truncated
      if (typeof user['client-key-data'] === 'string' && badKey(user['client-key-data'])) return shortKey
    }
    return undefined
  }
  if (!/^\s*clusters\s*:/m.test(v) || !/^\s*users\s*:/m.test(v)) return 'kubeconfig 不完整：缺少 clusters 或 users 段'
  if (/client-certificate-data\s*:/.test(v) && !/client-key-data\s*:/.test(v) && !/client-key\s*:/.test(v)) return truncated
  for (const m of v.matchAll(/client-key-data\s*:\s*["']?([^"'\s]*)["']?/g)) if (badKey(m[1])) return shortKey
  return undefined
}
