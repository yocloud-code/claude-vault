# claude-vault

> 一个 Claude Code Mod：让 Claude 使用数据库、服务器、集群等凭证，却永远看不到明文。
> A Claude Code mod that lets Claude use database, server and cluster credentials without ever seeing them.

[中文](#中文) · [English](#english)

---

## 中文

### 项目介绍

直接把数据库密码、SSH 私钥、kubeconfig 写进对话，会把明文留在 transcript 里，Claude 也常常因为安全原因拒绝执行。`claude-vault` 换了一种做法：

- **Claude 只知道凭证的名字和用途**，例如 `prod-db (postgres, ro_user@10.0.0.5)`。
- **密文只存 macOS 钥匙串**，由 Mod 在宿主进程里读取，并作为环境变量注入到命令里。
- **输出回到模型前先脱敏**：明文、base64、URL 编码三种形式都替换成 `«vault:prod-db.password»`。
- **按目录授权**：授权给某个目录后，对该目录及其子目录长期有效，直到你撤销。
- **带 UI 面板**：增删改凭证、设置密文、授权/撤销、导出/导入、审计日志都在面板里完成。

### 架构

```
你 ──系统掩码输入框──▶ macOS 钥匙串（密文，service = claude-vault）
~/.claude/vault/profiles.json   元数据：名称、类型、主机、端口、用户、环境变量映射（无密文）
~/.claude/vault/grants.json     目录授权：哪个目录可以用哪些 profile、只读还是读写（不在任何仓库里）
                │
      Mod（运行在 Claude Code 宿主进程，不在模型上下文里）
   ├─ session.start      读目录授权 → 计算当前目录生效的授权（含上级目录继承）
   ├─ mcp__vault__vault_list   列出 profile 名、类型、变量名（无密文）
   ├─ mcp__vault__vault_exec   {profile, command} → 注入环境变量执行 → 脱敏输出
   ├─ Bash 钩子          透明注入 + 拦截窥探命令 + 输出脱敏
   ├─ 文件工具钩子        禁止 Read/Edit/Grep 访问 vault 目录（授权文件也在其中）
   ├─ session.append     最后一道防线：写入对话的每一行都脱敏
   ├─ /vault 命令 + 面板  管理、授权、导出导入、审计
   └─ ~/.claude/vault/audit.log  审计日志（不含明文）
```

### 环境要求

- macOS（依赖 `/usr/bin/security`、`/usr/bin/osascript`、`/usr/bin/openssl`，系统自带）
- 支持函数钩子（function hooks）Mod 的 Claude Code

### 安装

任选一种：

```bash
# 1. 单次会话加载（/path/to/claude-vault 换成本仓库所在路径）
claude --plugin-dir /path/to/claude-vault
```

```jsonc
// 2. 长期加载（桌面版 / SDK 会话也生效）：写进 ~/.claude/settings.json
{ "env": { "CLAUDE_CODE_PLUGIN_DIRS": "/path/to/claude-vault" } }
```

加载后，状态栏出现 `🔐 vault: …`（有授权时），并可以使用 `/vault` 命令。

### 使用方式

**1. 新建凭证**：输入 `/vault` 打开面板，按 `n` 新建，先选类型，表单会按类型只显示需要的字段（`*` 为必填）。每个 profile 还可以填一段**描述**，显示在列表卡片上，也会告诉 Claude，帮它选对 profile。

| 类型 | 表单字段 | 密文 | 客户端变量 |
| --- | --- | --- | --- |
| 🐘 PostgreSQL | 主机*、端口、用户*、数据库 | 密码 | `PGHOST` `PGPORT` `PGUSER` `PGDATABASE` `PGPASSWORD` |
| 🐬 MySQL | 主机*、端口、用户*、数据库 | 密码 | `MYSQL_HOST` `MYSQL_TCP_PORT` `MYSQL_PWD` |
| 🟥 Redis | 主机*、端口、ACL 用户、DB 编号 | 密码 | `REDISCLI_AUTH` |
| 🍃 MongoDB | 集群（展示用）、数据库 | 连接串 | `MONGODB_URI` |
| 🖥 SSH（私钥） | 主机*、端口、用户* | 私钥（文件） | `GIT_SSH_COMMAND` |
| 🖥 SSH（密码） | 主机*、端口、用户* | 密码 | `SSHPASS` `SSH_ASKPASS` `SSH_ASKPASS_REQUIRE` |
| ☸ Kubernetes | 集群（展示用）、命名空间 | kubeconfig（文件） | `KUBECONFIG` |
| 🔑 HTTP API Token | Base URL* | Token | （无） |
| 🧩 自定义 | 全部字段可选 | 自定义 | 自定义 |

**环境变量分两类：**

- **专属变量**：以 profile 名称为前缀，每个 profile 独有，互不冲突。例如 `prod-db` 有 `PROD_DB_HOST` `PROD_DB_PORT` `PROD_DB_USER` `PROD_DB_DATABASE` `PROD_DB_PASSWORD`；文件类密文是 `<前缀>_<字段>_FILE`（如 `BASTION_KEY_FILE`，值为临时文件路径）。字段名后缀随类型变化：Redis 的 DB 编号是 `_DB`，Kubernetes 是 `_CLUSTER` `_NAMESPACE`，HTTP 是 `_URL`。
- **客户端变量**：`psql`、`kubectl`、`redis-cli` 等工具自动识别的标准变量（见上表），只在明确选定 profile 时注入：`vault_exec`，或 Bash 命令首行写 `#vault:<名称>`。

**SSH 密码登录**通过 `SSH_ASKPASS` 实现：Mod 提供一个 askpass 小程序，它只读取当前 ssh 进程环境里的 `SSHPASS`，文件本身不含密码。需要 OpenSSH 8.4 及以上（macOS 自带版本即可），不需要安装 sshpass。

编辑页会实时显示两类变量和 Claude 的用法示例。需要改密文字段或客户端变量时点「⚙ 自定义（高级）」，可随时「↺ 恢复为模板」。切换类型时，新类型用不到的字段会被清空。

自定义客户端变量可用的占位符：

| 占位符 | 含义 |
| --- | --- |
| `{host}` `{port}` `{user}` `{database}` | 对应字段的值 |
| `{secret:字段}` | 从钥匙串取出的值，直接作为变量值 |
| `{secretfile:字段}` | 取出后写入 0600 临时文件，变量值是文件路径，命令结束后删除（适合私钥、kubeconfig） |

**2. 设置密文**：新建 profile 点「创建」后，会自动弹出第一个密文的系统**掩码输入框**（私钥、kubeconfig 这类文件密文则弹出文件选择），值直接写进钥匙串。之后也可以在编辑页点「设置」或「从文件读取」修改。

改名 profile 时，钥匙串里的密文和所有目录上的授权会一起迁移到新名称，不会丢失。

**2.5 测试连接**：列表卡片和编辑页都有「测试连接」按钮，会按类型执行一条只读探测（SSH 执行 `true`、PostgreSQL `select 1`、Redis `ping`、Kubernetes 读 `/version`、HTTP 请求 Base URL 等），结果和耗时显示在卡片上。本机没装对应客户端时会提示「未安装 psql」。测试由你本人在面板里触发，不需要先授权。

卡片上还会显示「最近使用 · 共 N 次」，数据来自审计日志里 Claude 实际调用的记录。缺少密文的 profile 不显示「授权」，而是显示「先设置密文」。

**3. 授权给目录**：在列表卡片的「当前目录」一行点「只读」或「读写」，就授权给当前目录及其子目录；点「不授权」撤销。不用进编辑页。

**4. 让 Claude 使用**：

```text
# 方式 A：专用工具（推荐），专属变量和客户端变量都会注入
mcp__vault__vault_exec({ profile: "prod-db", command: "psql -c 'select count(*) from users'" })

# 方式 B：Bash 里直接引用专属变量，只注入该 profile 的专属变量
PGPASSWORD="$PROD_DB_PASSWORD" psql -h "$PROD_DB_HOST" -U "$PROD_DB_USER" -c 'select 1'

# 方式 C：Bash 首行指定 profile，额外注入客户端变量
#vault:prod-db
psql -c 'select 1'
```

### 授权模型

- **授权的对象是目录**，不是会话。授权给 `~/work/shop` 后，在这个目录和它的所有子目录里打开的会话都能用，**长期有效，没有时长**，直到你撤销。
- 子目录可以覆盖上级目录：比如上级授权只读，子目录可以单独授权读写，离当前目录最近的那条生效。卡片上会显示「继承自 ~/work」。对继承来的授权点「不授权」，会撤销上级目录上的那条（它的所有子目录同时失效）。
- 授权记录在 `~/.claude/vault/grants.json`，不在任何仓库里，所以 clone 来的项目不能给自己授权；Claude 的工具也读写不了这个文件。
- 「授权管理」（快捷键 `g`）列出所有有授权的目录，可以逐条撤销；当前目录和对它生效的上级目录会标出来。
- `read` 模式会拦截常见写操作（SQL DML/DDL、`kubectl apply/delete`、redis `set`……），但只是尽力而为。**真正的只读保证请用只读账号或只读 RBAC**。
- 旧版本的项目白名单 `.claude/vault.json`：如果你以前信任过它，第一次打开时会自动迁移成该目录的授权；之后这个文件不再使用，可以删掉。

### 一键清理

工具栏「🧹 一键清理」（快捷键 `c`）会先检查一遍，列出可以清理的内容，勾选后执行：失效的授权（profile 已删除或目录已不存在）、孤立的钥匙串条目、残留的临时文件、测试连接结果；「撤销当前目录的全部授权」和「清空审计日志」默认不勾选。不会删除任何 profile 或正在使用的密文。

### 环境变量的生命周期与冲突

**生命周期**

| 对象 | 存在多久 |
| --- | --- |
| `vault_exec` 注入的变量 | 只设置在这一个子进程上，进程退出即消失；不写文件，不影响其他命令 |
| Bash 注入的变量 | 写入 0600 临时 env 文件，命令开头 `source` 后立即删除；Bash 每条命令都是新 shell，命令结束变量就没了 |
| `{secretfile:}` 临时文件 | 归属于发起它的命令，命令结束后删除。清理任务只删除无人认领（例如重载、崩溃留下的）且超过 15 分钟的文件，不会误删正在运行的命令的文件 |
| 授权 | 按目录长期有效，直到撤销；只在命令**启动时**检查，撤销不会终止已在运行的进程 |
| 脱敏明文表 | 存在 Mod 内存中；授权时以及每次加载/热重载时，都会从钥匙串重新载入已授权 profile 的密文 |

变量会被该命令启动的所有子进程继承；用 `nohup`、`&` 拉起的常驻进程会一直持有这些变量，直到它退出。

**冲突规则**

- 专属变量以名称为前缀，**天然不冲突**，同一条命令可以引用多个 profile 的专属变量（例如从 prod 导出、导入 staging）。
- 客户端变量**不会被隐式注入**，所以两个 PostgreSQL profile 不会再抢 `PGPASSWORD`。
- `#vault:a,b` 同时指定两个会设置相同客户端变量的 profile（例如两个 PostgreSQL）时拒绝；不同客户端（例如一个数据库加一个集群）可以一起指定。
- 只匹配**已授权**的 profile；引用未授权 profile 的专属变量会被拒绝，其他无关变量（如 `$HOME`）不受影响。
- 名称规范化后前缀相同（如 `a-b` 和 `a_b`），或专属变量重名（如名称 `prod` 加密文字段 `db_password`，与 `prod-db` 的 `password` 都是 `PROD_DB_PASSWORD`）时，保存或导入会被拒绝。
- 后台运行（`run_in_background`）的 Bash 命令不能注入凭证，请改用前台命令或 `vault_exec`。

### 命令

| 命令 | 作用 |
| --- | --- |
| `/vault` | 打开面板 |
| `/vault list` | 文字列出 profile 和授权状态 |
| `/vault grant <p> [read\|write]` | 授权给当前目录及其子目录 |
| `/vault revoke <p>` | 撤销对当前目录生效的那条授权 |
| `/vault export` / `/vault import` | 打开导出面板 / 选择文件导入 |

除 `/vault` 和 `/vault list` 外，其他子命令只认你在输入框里亲手输入的。

面板快捷键：`n` 新建 · `e` 编辑 · `x` 导出 · `i` 导入 · `g` 授权管理 · `l` 审计 · `c` 一键清理 · `s` 保存 · `b` 返回。

### 导出 / 导入

- **导出**：勾选 profile → 设置口令（至少 12 位，输两次）→ 选择保存位置，生成一个包含配置和密文的 `.cvault` 加密包。格式是 `CLAUDE-VAULT-V1` 头 + openssl `AES-256-CBC` / `PBKDF2-SHA256 600000` 轮，内嵌 SHA-256 完整性校验，口令至少 12 位，文件权限 0600。
- **导入**：选择 `.cvault` 文件（也兼容旧版导出的 `.json` 模板）→ 输入口令 → 预览每条是「新增 / 冲突 / 相同」，逐条选择导入、覆盖、跳过或另存为 `-imported` → 确认。**导入不会授权任何目录。**
- 不借助 Mod 手动解密：

```bash
tail -n +2 backup.cvault | openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -md sha256 -a -A
```

### 安全边界

**会拦截的操作：**
- `security find-generic-password` / `dump-keychain`、带 `-s claude-vault` 的钥匙串命令
- 任何工具访问 `~/.claude/vault/`
- 在注入了凭证的命令里执行 `env` / `printenv` / `set`
- 模型修改授权：授权文件在 `~/.claude/vault/` 下，任何工具都读写不了；`/vault grant` 等命令只认你亲手输入的
- 客户端变量里设置 `BASH_ENV`、`ENV`、`LD_PRELOAD`、`DYLD_*`、`PROMPT_COMMAND`、`PATH`、`NODE_OPTIONS` 等会让 shell 或解释器执行任意代码的变量：保存、导入和注入时都会拒绝（防止恶意模板文件借此执行代码）
- `SSH_ASKPASS`、`GIT_SSH_COMMAND`、`EDITOR`、`PAGER` 这类"指定要执行的程序"的变量，只允许使用模板自带的值

**已知限制：**
- 只读模式只对数据库、Redis、kubectl 生效，**不拦截 SSH 上执行的命令**；编辑页对 SSH 选只读时会提示。只想让 Claude 查看服务器时，请为它使用权限受限的账号。
- 脱敏基于已知明文的字符串匹配；被模型先变换再输出的形式（如逐字符拆开、hex）无法识别。
- 导出口令通过子进程环境变量传给 openssl，同一用户的进程理论上能读到。
- 改写后的 Bash 命令里会出现临时 env 文件路径；文件在命令开头就被 source 后删除，另有定时清理。

### 开发

```text
claude-vault/
├── .claude-plugin/plugin.json   Mod 清单
├── hooks/hooks.json             指向 register.tsx
├── hooks/register.tsx           入口：钥匙串、弹窗、授权、工具、钩子、命令、面板
├── hooks/ui.tsx                 面板渲染（纯函数）
├── hooks/guard.ts               拦截规则
├── hooks/redact.ts              脱敏
├── hooks/transfer.ts            导出包格式
├── hooks/templates.ts           类型模板
├── hooks/*.test.ts(x)           测试
└── types/index.d.ts             $.state 类型契约
```

注意：引擎要求所有接收 `$` 的函数都**定义在 `register.tsx` 本文件顶层**，不能从其他文件导入，所以其他文件里只放纯函数。

```bash
claude plugin validate .
```

```bash
claude plugin test .
```

请使用与正在运行的 Claude Code 同版本的 `claude` 命令验证；版本较旧的 CLI 可能不认识新事件（如 `session.append`）而误报。

---

## English

### Overview

Pasting database passwords, SSH keys or kubeconfigs into a conversation leaves them in the transcript in plaintext, and Claude often refuses to run commands that need them. `claude-vault` takes a different approach:

- **Claude only knows a credential's name and purpose**, e.g. `prod-db (postgres, ro_user@10.0.0.5)`.
- **Secrets live only in the macOS Keychain.** The mod reads them in the host process and injects them into commands as environment variables.
- **Output is redacted before the model sees it**: the raw value and its base64 and URL-encoded forms all become `«vault:prod-db.password»`.
- **Grants belong to directories**: a profile granted to a directory works there and in every subdirectory, with no expiry, until you revoke it.
- **A UI pane** covers create/edit/delete, setting secrets, grant/revoke, export/import, and the audit log.

### Architecture

```
You ──native masked dialog──▶ macOS Keychain (secrets, service = claude-vault)
~/.claude/vault/profiles.json   metadata: name, type, host, port, user, env mapping (no secrets)
~/.claude/vault/grants.json     directory grants: which directory may use which profiles, read or write (in no repository)
                │
      Mod (runs in the Claude Code host process, outside the model's context)
   ├─ session.start      read directory grants → work out what applies here (parents included)
   ├─ mcp__vault__vault_list   profile names, types, env var names (no secrets)
   ├─ mcp__vault__vault_exec   {profile, command} → run with injected env → redacted output
   ├─ Bash hook          transparent injection + snooping guard + redaction
   ├─ file-tool hook     blocks Read/Edit/Grep on the vault dir (the grants file included)
   ├─ session.append     last line of defence: every stored conversation row is redacted
   ├─ /vault + pane      manage, grant, export/import, audit
   └─ ~/.claude/vault/audit.log  audit log (no plaintext)
```

### Requirements

- macOS (uses the built-in `/usr/bin/security`, `/usr/bin/osascript`, `/usr/bin/openssl`)
- A Claude Code build that supports function-hook mods

### Install

Pick one:

```bash
# 1. One session (replace /path/to/claude-vault with where you cloned this repo)
claude --plugin-dir /path/to/claude-vault
```

```jsonc
// 2. Always (also for desktop / SDK sessions): in ~/.claude/settings.json
{ "env": { "CLAUDE_CODE_PLUGIN_DIRS": "/path/to/claude-vault" } }
```

Once loaded, the status line shows `🔐 vault: …` while grants are active, and `/vault` is available.

### Usage

**1. Create a profile**: run `/vault`, press `n`, and pick a type first; the form then shows only the fields that type needs (`*` = required). Each profile can also carry a **description**, shown on its card and passed to Claude so it picks the right profile.

| Type | Form fields | Secret | Client variables |
| --- | --- | --- | --- |
| 🐘 PostgreSQL | host*, port, user*, database | password | `PGHOST` `PGPORT` `PGUSER` `PGDATABASE` `PGPASSWORD` |
| 🐬 MySQL | host*, port, user*, database | password | `MYSQL_HOST` `MYSQL_TCP_PORT` `MYSQL_PWD` |
| 🟥 Redis | host*, port, ACL user, DB index | password | `REDISCLI_AUTH` |
| 🍃 MongoDB | cluster (display only), database | connection URI | `MONGODB_URI` |
| 🖥 SSH (key) | host*, port, user* | private key (file) | `GIT_SSH_COMMAND` |
| 🖥 SSH (password) | host*, port, user* | password | `SSHPASS` `SSH_ASKPASS` `SSH_ASKPASS_REQUIRE` |
| ☸ Kubernetes | cluster (display only), namespace | kubeconfig (file) | `KUBECONFIG` |
| 🔑 HTTP API token | base URL* | token | (none) |
| 🧩 Custom | every field optional | your own | your own |

**Two kinds of variables:**

- **Profile variables** carry the profile's name as a prefix, so every profile has its own and they never collide. `prod-db` gets `PROD_DB_HOST` `PROD_DB_PORT` `PROD_DB_USER` `PROD_DB_DATABASE` `PROD_DB_PASSWORD`; a file secret becomes `<PREFIX>_<FIELD>_FILE` (e.g. `BASTION_KEY_FILE`, holding a temp file path). Suffixes follow the type: Redis's DB index is `_DB`, Kubernetes uses `_CLUSTER` `_NAMESPACE`, HTTP uses `_URL`.
- **Client variables** are the standard ones tools like `psql`, `kubectl` and `redis-cli` read (table above). They are injected only when a profile is chosen explicitly: through `vault_exec`, or a Bash command whose first line is `#vault:<name>`.

**SSH password login** uses `SSH_ASKPASS`: the mod provides a tiny askpass helper that only prints `SSHPASS` from the ssh process's own environment, so the file holds no password. It needs OpenSSH 8.4+ (the one macOS ships is fine); no sshpass required.

The edit page shows both kinds of variables and a usage example for Claude as you type. To change the secret fields or client variables, click "⚙ 自定义（高级）" (custom, advanced); "↺ 恢复为模板" restores the template. Switching type clears the fields the new type doesn't use.

Placeholders for custom client variables:

| Placeholder | Meaning |
| --- | --- |
| `{host}` `{port}` `{user}` `{database}` | the field's value |
| `{secret:field}` | value from the Keychain, used as the variable's value |
| `{secretfile:field}` | value written to a 0600 temp file; the variable holds its path; deleted after the command (for keys, kubeconfigs) |

**2. Set the secret**: after "创建" (Create), the native **masked dialog** for the first secret opens on its own (a file picker for file secrets such as private keys and kubeconfigs), and the value goes straight to the Keychain. You can change it later with "设置" (Set) or "从文件读取" (From file) on the edit page.

Renaming a profile carries its Keychain secrets and its grants on every directory over to the new name.

**2.5 Test the connection**: profile cards and the edit page have a "测试连接" (Test connection) button that runs a read-only probe for the type (SSH runs `true`, PostgreSQL `select 1`, Redis `ping`, Kubernetes reads `/version`, HTTP requests the base URL, …) and shows the result and timing on the card. A missing client tool is reported as such (e.g. "psql not installed"). You trigger the test yourself in the pane, so it needs no grant.

Cards also show "last used · N times" from the audit log's record of Claude's actual calls. A profile with missing secrets shows "先设置密文" (Set secret first) instead of "授权" (Grant).

**3. Grant it to a directory**: on the card's "当前目录" (current directory) row, click "只读" (read) or "读写" (write) to grant it to the current directory and its subdirectories; "不授权" (none) revokes. No need to open the editor.

**4. Let Claude use it**:

```text
# A: the dedicated tool (recommended); injects profile and client variables
mcp__vault__vault_exec({ profile: "prod-db", command: "psql -c 'select count(*) from users'" })

# B: plain Bash referencing profile variables; injects only that profile's own variables
PGPASSWORD="$PROD_DB_PASSWORD" psql -h "$PROD_DB_HOST" -U "$PROD_DB_USER" -c 'select 1'

# C: name the profile on the first line to get the client variables as well
#vault:prod-db
psql -c 'select 1'
```

### Authorization model

- **Grants belong to a directory**, not to a session. A profile granted to `~/work/shop` is available to every session opened there or in any subdirectory, **with no expiry**, until you revoke it.
- A subdirectory can override its parent (read above, write below): the nearest directory's grant wins, and the card shows "继承自 ~/work" (inherited from). Choosing "不授权" (none) on an inherited grant revokes it on the parent, for all of that parent's subdirectories.
- Grants are stored in `~/.claude/vault/grants.json`, outside every repository, so a cloned project cannot grant itself, and Claude's tools cannot read or write the file.
- "授权管理" (Grants, hotkey `g`) lists every directory with grants and revokes them one by one; the current directory and the parents that apply to it are marked.
- `read` mode blocks common writes (SQL DML/DDL, `kubectl apply/delete`, redis `set`, …) on a best-effort basis. **For a real read-only guarantee, use a read-only DB user or RBAC role.**
- The old per-project allowlist `.claude/vault.json`: if you had trusted it, it is migrated into grants on that directory the first time the project is opened; afterwards the file is unused and can be deleted.

### One-click cleanup

"🧹 一键清理" (hotkey `c`) checks first, lists what can be cleaned, and runs the items you tick: stale grants (deleted profile or missing directory), orphaned Keychain items, leftover temp files, connection-test results. "Revoke all grants of the current directory" and "clear the audit log" start unticked. No profile and no secret in use is ever removed.

### Variable lifecycle and conflicts

**Lifecycle**

| What | How long it lives |
| --- | --- |
| Variables from `vault_exec` | set on that one child process only and gone when it exits; no file, no effect on other commands |
| Variables from Bash injection | written to a 0600 temp env file that is sourced and deleted at the start of the command; every Bash command is a fresh shell, so they end with it |
| `{secretfile:}` temp files | owned by the command that created them and deleted when it ends. The sweep only removes files nobody owns (left by a reload or crash) once they are older than 15 minutes, so a running command never loses its files |
| Grants | last per directory until revoked; checked only when a command **starts**, so revoking does not stop running processes |
| Redaction table | kept in mod memory, and reloaded from the Keychain for every granted profile on grant and on every load or hot reload |

Child processes inherit the variables; a daemon started with `nohup` or `&` keeps them until it exits.

**Conflict rules**

- Profile variables are prefixed with the profile name and **cannot collide**; one command may use several profiles' variables (dump from prod, load into staging).
- Client variables are **never injected implicitly**, so two PostgreSQL profiles no longer fight over `PGPASSWORD`.
- `#vault:a,b` naming two profiles that set the same client variable (two PostgreSQL profiles) is refused; different clients (a database plus a cluster) can be named together.
- Only **granted** profiles are matched; referencing an ungranted profile's variables is refused, and unrelated variables (such as `$HOME`) are left alone.
- Names that normalise to the same prefix (`a-b` and `a_b`), or profile variables that would collide (name `prod` with secret `db_password` and `prod-db` with `password` both give `PROD_DB_PASSWORD`), are refused on save and on import.
- Bash commands run with `run_in_background` cannot have credentials injected; run them in the foreground or use `vault_exec`.

### Commands

| Command | Effect |
| --- | --- |
| `/vault` | open the pane |
| `/vault list` | list profiles and grants as text |
| `/vault grant <p> [read\|write]` | grant to the current directory and its subdirectories |
| `/vault revoke <p>` | revoke the grant that applies to the current directory |
| `/vault export` / `/vault import` | open the export view / pick a file to import |

Every subcommand except `/vault` and `/vault list` is accepted only when you type it yourself at the prompt.

Pane hotkeys: `n` new · `e` edit · `x` export · `i` import · `g` grants · `l` audit · `c` cleanup · `s` save · `b` back.

### Export / import

- **Export**: tick profiles → set a passphrase (at least 12 characters, typed twice) → choose where to save. The result is one `.cvault` file holding the configuration and the secrets: a `CLAUDE-VAULT-V1` header plus openssl `AES-256-CBC` with `PBKDF2-SHA256`, 600,000 iterations, an embedded SHA-256 integrity check, a passphrase of at least 12 characters, and file mode 0600.
- **Import**: pick a `.cvault` file (`.json` templates from older versions still import) → enter the passphrase → preview each entry as new / conflict / same and choose import, overwrite, skip or save as `-imported` → confirm. **Importing never grants anything.**
- Decrypt by hand without the mod:

```bash
tail -n +2 backup.cvault | openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -md sha256 -a -A
```

### Security boundaries

**Blocked:**
- `security find-generic-password` / `dump-keychain`, and Keychain commands with `-s claude-vault`
- any tool touching `~/.claude/vault/`
- `env` / `printenv` / `set` in a command that has credentials injected
- the model changing grants: the grants file lives under `~/.claude/vault/`, out of every tool's reach, and `/vault grant` and the like only accept what you type yourself
- client variables that make a shell or interpreter run code (`BASH_ENV`, `ENV`, `LD_PRELOAD`, `DYLD_*`, `PROMPT_COMMAND`, `PATH`, `NODE_OPTIONS`, …): refused on save, on import and at injection, so a malicious template file cannot use them to run code
- variables that name a program to run (`SSH_ASKPASS`, `GIT_SSH_COMMAND`, `EDITOR`, `PAGER`, …): only the values the templates themselves use

**Known limits:**
- Read-only mode applies to databases, Redis and kubectl; it **does not restrict commands run over SSH**, and the edit page says so when SSH is set to read-only. To let Claude only look at a server, give it a restricted account there.
- Redaction matches known plaintext strings; values the model transforms before printing (split into characters, hex) are not caught.
- The export passphrase reaches openssl through the child's environment, which other processes of the same user could in principle read.
- A rewritten Bash command contains the temp env file's path. The file is sourced and deleted at the start of the command, and a timer sweeps any leftovers.

### Development

```text
claude-vault/
├── .claude-plugin/plugin.json   mod manifest
├── hooks/hooks.json             points to register.tsx
├── hooks/register.tsx           entry: keychain, dialogs, grants, tools, hooks, commands, pane
├── hooks/ui.tsx                 pane rendering (pure)
├── hooks/guard.ts               guard rules
├── hooks/redact.ts              redaction
├── hooks/transfer.ts            export format
├── hooks/templates.ts           type templates
├── hooks/*.test.ts(x)           tests
└── types/index.d.ts             $.state contract
```

Note: the engine requires every function that receives `$` to be declared **at the top level of `register.tsx` itself**; `$` cannot be passed into imported functions, so the other files hold pure code only.

```bash
claude plugin validate .
```

```bash
claude plugin test .
```

Validate with a `claude` CLI that matches the running Claude Code version; an older CLI may not know newer events (such as `session.append`) and report false errors.
