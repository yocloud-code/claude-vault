// Plaintexts seen this module lifetime. Never written to $.state or $.store.
const known = new Map<string, string>()
// `known` longest first, so a full value wins over its substrings; rebuilt only after a change
let ordered: [string, string][] | null = null

const variants = (v: string) => {
  const out = [v]
  try { out.push(btoa(v)) } catch {}
  const enc = encodeURIComponent(v)
  if (enc !== v) out.push(enc)
  return out
}

export const remember = (label: string, value: string) => {
  if (value.length < 4) return
  ordered = null
  for (const v of variants(value)) known.set(v, label)
  // multi-line secrets (keys, kubeconfigs): also mask each substantial line
  for (const line of value.split('\n')) if (line.trim().length >= 16) known.set(line.trim(), label)
}

export const hasSecrets = (text: string) => {
  for (const v of known.keys()) if (text.includes(v)) return true
  return false
}

export const redact = (text: string) => {
  if (!known.size) return text
  ordered ??= [...known].sort((a, b) => b[0].length - a[0].length)
  for (const [v, label] of ordered) {
    if (text.includes(v)) text = text.split(v).join(`«vault:${label}»`)
  }
  return text
}

export const redactDeep = <T>(value: T): T => {
  if (typeof value === 'string') return redact(value) as T
  if (Array.isArray(value)) return value.map(redactDeep) as T
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value)) out[k] = redactDeep(v)
    return out as T
  }
  return value
}

// Detection over every string of a value, as `redactDeep` replaces. Checking `JSON.stringify`
// instead misses secrets holding `"`, `\` or newlines, whose JSON form differs from the raw text.
export const hasSecretsDeep = (value: unknown): boolean => {
  if (typeof value === 'string') return hasSecrets(value)
  if (Array.isArray(value)) return value.some(hasSecretsDeep)
  if (value && typeof value === 'object') return Object.values(value).some(hasSecretsDeep)
  return false
}
