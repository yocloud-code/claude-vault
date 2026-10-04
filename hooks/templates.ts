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
export type Variant = { key: string; label: string; secrets: SecretDef[]; env: Record<string, string>; example: string; hint?: string }

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
      },
      {
        key: 'password', label: '密码',
        secrets: [{ name: 'password', label: '密码' }],
        env: { SSHPASS: '{secret:password}', SSH_ASKPASS: '{askpass}', SSH_ASKPASS_REQUIRE: 'force' },
        example: `ssh -o StrictHostKeyChecking=accept-new -p "\${P}_PORT" "\${P}_USER@\${P}_HOST" uptime`,
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
  return out
}

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
