import type { VaultProfile } from '../types'

const PEEK = [
  /\bsecurity\b[^|;&]*\b(find-generic-password|find-internet-password|dump-keychain|export|-i\b)/,
  /\.claude\/vault(\/|$|[\s'"`;|&)])/,
  /(^|\s)-[sl]\s*['"]?claude-vault['"]?(\s|$)/,
]

const DUMP = /(^|[;&|]\s*|\s)(env|printenv|export\s+-p|declare\s+-p|set)\s*($|[;&|>])/

export const peekReason = (command: string) =>
  PEEK.some(r => r.test(command))
    ? 'vault: 这条命令会直接读取凭证存储（钥匙串/vault 目录），已拒绝。请通过已授权的 profile 使用凭证。'
    : undefined

export const dumpReason = (command: string) =>
  DUMP.test(command) ? 'vault: 注入凭证的命令里不允许整体导出环境变量 (env/printenv/set)。' : undefined

export const isVaultPath = (path: string, vaultDir: string) =>
  path.startsWith(vaultDir + '/') || path === vaultDir || /(^|\/)\.claude\/vault(\/|$)/.test(path)

export const isAllowFile = (path: string) => /(^|\/)\.claude\/vault\.json$/.test(path)

const WRITES: Record<string, RegExp> = {
  postgres: /\b(insert|update|delete|drop|alter|truncate|create|grant|revoke|merge|copy\s+\w+\s+from|vacuum|reindex)\b/i,
  mysql: /\b(insert|update|delete|drop|alter|truncate|create|grant|revoke|replace|load\s+data|rename)\b/i,
  mongo: /\b(insert\w*|update\w*|delete\w*|drop\w*|remove|replaceOne|bulkWrite|createIndex|renameCollection)\b/,
  redis: /\b(set|setex|mset|del|unlink|expire|hset|hdel|lpush|rpush|lpop|rpop|sadd|srem|zadd|zrem|flushall|flushdb|config\s+set|rename)\b/i,
  kube: /\bkubectl\b[^|;&]*\b(delete|apply|create|edit|patch|replace|scale|rollout\s+(restart|undo)|drain|cordon|uncordon|taint|label|annotate|exec|cp|set|run|expose|autoscale)\b|\bhelm\b[^|;&]*\b(install|upgrade|uninstall|rollback)\b/,
}

// Best-effort only: real read-only guarantees come from a read-only DB user or RBAC role.
export const writeReason = (profile: VaultProfile, command: string) => {
  const r = WRITES[profile.type]
  return r && r.test(command)
    ? `vault: 该 profile 在本会话只授权了 read 模式，命令疑似写操作（匹配 ${profile.type} 写规则），已拒绝。需要写权限请让用户在 vault.json 里把 mode 改成 write。`
    : undefined
}
