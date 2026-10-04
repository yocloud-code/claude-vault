# claude-vault

让 Claude Code 使用数据库、服务器、集群的凭证，却看不到密码。
Let Claude Code use your database, server and cluster credentials without ever seeing the passwords.

[中文](#中文) · [English](#english)

---

## 中文

### 它解决什么问题

把密码、私钥、kubeconfig 贴进对话，明文会永久留在聊天记录里，Claude 也常常因此拒绝执行。装上 claude-vault 之后：

- 密码只存在 **macOS 钥匙串**里，Claude 只知道凭证的名字和用途；
- 命令执行时由 Mod 把凭证注入成环境变量，输出里的密码会自动替换成 `«vault:名称.字段»`；
- 你决定**哪个目录**可以用哪个凭证，只读还是读写。

### 安装

需要 macOS 和支持 Mod 的 Claude Code。

```bash
claude --plugin-dir /path/to/claude-vault
```

想每次启动都自动加载（包括桌面版），在 `~/.claude/settings.json` 里加上：

```json
{ "env": { "CLAUDE_CODE_PLUGIN_DIRS": "/path/to/claude-vault" } }
```

### 快速上手

1. **打开面板**：输入 `/vault`。
2. **新建凭证**：点「＋ 新建」，选类型（PostgreSQL、SSH、Kubernetes……），填主机、用户等信息，写一句描述（Claude 会据此选择凭证），点「创建」。
3. **输入密码**：创建后会自动弹出系统的密码输入框（私钥、kubeconfig 会弹出文件选择），内容直接存进钥匙串，界面上永远不会显示。
4. **测试连接**：点卡片上的「测试连接」，确认能连上。
5. **授权**：在卡片的「当前目录」一行点「只读」或「读写」。授权对当前目录及其子目录长期有效，点「不授权」撤销。

之后在这个目录里直接跟 Claude 说"查一下 prod-db 的订单表"就行。

### Claude 怎么用凭证

- **`vault_exec` 工具**（Claude 默认会用）：指定凭证名和命令，`psql`、`kubectl`、`ssh` 等客户端不用加任何参数就能连上。
- **在 Bash 里引用专属变量**：每个凭证都有以名称为前缀的变量，例如 `prod-db` 有 `$PROD_DB_HOST`、`$PROD_DB_PASSWORD`。
- **命令首行写 `#vault:prod-db`**：同时注入 `PGPASSWORD` 这类客户端标准变量。

每个凭证有哪些变量，在编辑页的「环境变量」里能看到。

### 授权

- 授权给的是**目录**，不是会话；没有时长，撤销前一直有效。
- 子目录继承上级目录的授权，也可以单独设置，离得最近的那条生效。
- 「授权管理」列出所有目录的授权，可以逐条撤销。
- 授权记录保存在你的用户目录里，不在项目仓库中：别人的项目不能给自己授权，Claude 也改不了授权。
- 「只读」会拦截数据库、Redis、kubectl 的常见写操作，**但对 SSH 无效**。真正的只读请使用只读账号。

### 备份、恢复与清理

- **导出**：勾选凭证，设置口令（至少 12 位），生成一个加密的 `.cvault` 文件，里面包含配置和密码。
- **导入**：选择 `.cvault` 文件，输入口令，预览后确认。冲突的凭证可以选择覆盖、跳过或另存一份。导入后需要重新授权。
- **一键清理**：清空全部凭证、钥匙串里的 vault 密码、所有授权和日志。会弹出确认框，**无法撤销**，请先导出备份。钥匙串里其他应用的密码不受影响。

### 常见问题

**输出里出现 `«vault:prod-db.password»`？**
这是密码被自动隐藏了，属于正常现象。

**Claude 说凭证"未授权"？**
在 `/vault` 面板里，给当前目录授权这个凭证。

**命令被拒绝"疑似写操作"？**
当前授权是「只读」。需要写入时，在卡片上改成「读写」。

**能防住什么，不能防住什么？**
- 能防住：Claude 读取钥匙串或 vault 文件、在注入了凭证的命令里导出环境变量、导入的配置里夹带能执行代码的危险变量。
- 防不住：密码被变换成其他形式后再输出（例如逐字符拆开），这类内容无法自动识别。

### 命令

| 命令 | 作用 |
| --- | --- |
| `/vault` | 打开面板 |
| `/vault list` | 列出凭证和授权状态 |
| `/vault grant <名称> [read\|write]` | 授权给当前目录 |
| `/vault revoke <名称>` | 撤销授权 |
| `/vault export`、`/vault import` | 导出、导入 |

面板快捷键：`n` 新建 · `e` 编辑 · `g` 授权管理 · `x` 导出 · `i` 导入 · `l` 审计日志 · `c` 一键清理 · `b` 返回

### 支持的凭证类型

| 类型 | 需要填写 | 密码 | 客户端自动识别的变量 |
| --- | --- | --- | --- |
| PostgreSQL | 主机、用户 | 密码 | `PGHOST` `PGUSER` `PGPASSWORD` 等 |
| MySQL | 主机、用户 | 密码 | `MYSQL_HOST` `MYSQL_PWD` 等 |
| Redis | 主机 | 密码 | `REDISCLI_AUTH` |
| MongoDB | — | 连接串 | `MONGODB_URI` |
| SSH | 主机、用户 | 私钥文件或密码 | `GIT_SSH_COMMAND`，密码登录无需 sshpass |
| Kubernetes | — | kubeconfig 文件 | `KUBECONFIG` |
| HTTP API Token | Base URL | Token | — |
| 自定义 | — | 自定义 | 在编辑页「高级」里自定义 |

<details>
<summary>开发</summary>

```bash
claude plugin validate .
claude plugin test .
```

接收 `$` 的函数必须写在 `hooks/register.tsx` 顶层，其他文件只放纯函数。请使用与当前 Claude Code 同版本的 `claude` 命令做校验。
</details>

---

## English

### What it solves

Pasting passwords, keys or kubeconfigs into a chat leaves them in the transcript for good, and Claude often refuses to run such commands. With claude-vault:

- secrets live only in the **macOS Keychain**; Claude only knows each credential's name and purpose;
- the mod injects credentials into commands as environment variables, and any secret in the output is replaced with `«vault:name.field»`;
- you decide **which directory** may use which credential, read-only or read-write.

### Install

Requires macOS and a Claude Code build that supports mods.

```bash
claude --plugin-dir /path/to/claude-vault
```

To load it every time (desktop app included), add to `~/.claude/settings.json`:

```json
{ "env": { "CLAUDE_CODE_PLUGIN_DIRS": "/path/to/claude-vault" } }
```

### Getting started

1. **Open the pane**: type `/vault`.
2. **Create a credential**: click "＋ 新建" (New), pick a type (PostgreSQL, SSH, Kubernetes, …), fill in host and user, add a short description (Claude uses it to pick the right credential), and click "创建" (Create).
3. **Enter the secret**: a native password dialog opens right away (a file picker for keys and kubeconfigs). The value goes straight to the Keychain and is never shown.
4. **Test it**: click "测试连接" (Test connection) on the card.
5. **Grant it**: on the card's "当前目录" (current directory) row, click "只读" (read) or "读写" (write). The grant covers this directory and its subdirectories until you revoke it with "不授权" (none).

From then on, just ask Claude, e.g. "check the orders table on prod-db".

### How Claude uses credentials

- **The `vault_exec` tool** (Claude's default): name the credential and the command; clients like `psql`, `kubectl` and `ssh` connect without any flags.
- **Profile variables in Bash**: every credential has variables prefixed with its name, e.g. `prod-db` gets `$PROD_DB_HOST` and `$PROD_DB_PASSWORD`.
- **A first line `#vault:prod-db`**: also injects the client's standard variables such as `PGPASSWORD`.

The edit page lists every variable a credential provides.

### Grants

- Grants belong to **directories**, not sessions, and never expire until revoked.
- Subdirectories inherit their parent's grants and can override them; the nearest one wins.
- "授权管理" (Grants) lists every directory's grants and revokes them one by one.
- Grants are stored in your home directory, outside any repository: a project cannot grant itself, and Claude cannot change grants.
- "Read" blocks common writes to databases, Redis and kubectl, **but not over SSH**. Use a read-only account for real read-only access.

### Backup, restore and cleanup

- **Export**: tick credentials, set a passphrase (12+ characters), and get one encrypted `.cvault` file holding the configuration and secrets.
- **Import**: pick the `.cvault` file, enter the passphrase, review, confirm. For conflicts, choose overwrite, skip, or keep a copy. Imported credentials need to be granted again.
- **One-click cleanup** ("🧹 一键清理"): wipes every credential, every vault secret in the Keychain, all grants and logs. It asks for confirmation and **cannot be undone**, so export first. Other apps' Keychain items are untouched.

### FAQ

**The output shows `«vault:prod-db.password»`?**
A secret was hidden automatically. This is expected.

**Claude says the credential is "not granted"?**
Grant it to the current directory in the `/vault` pane.

**A command was refused as a "possible write"?**
The grant is read-only. Switch it to "读写" (write) on the card.

**What is protected, and what isn't?**
- Blocked: Claude reading the Keychain or vault files, dumping the environment in a command that has credentials injected, and imported configurations that try to set code-running variables.
- Not caught: a secret transformed before printing (e.g. split into single characters).

### Commands

| Command | Effect |
| --- | --- |
| `/vault` | open the pane |
| `/vault list` | list credentials and grants |
| `/vault grant <name> [read\|write]` | grant to the current directory |
| `/vault revoke <name>` | revoke a grant |
| `/vault export`, `/vault import` | export, import |

Pane hotkeys: `n` new · `e` edit · `g` grants · `x` export · `i` import · `l` audit log · `c` cleanup · `b` back

### Supported types

| Type | You fill in | Secret | Variables clients read |
| --- | --- | --- | --- |
| PostgreSQL | host, user | password | `PGHOST` `PGUSER` `PGPASSWORD` … |
| MySQL | host, user | password | `MYSQL_HOST` `MYSQL_PWD` … |
| Redis | host | password | `REDISCLI_AUTH` |
| MongoDB | — | connection URI | `MONGODB_URI` |
| SSH | host, user | key file or password | `GIT_SSH_COMMAND`; password login needs no sshpass |
| Kubernetes | — | kubeconfig file | `KUBECONFIG` |
| HTTP API token | base URL | token | — |
| Custom | — | your own | define them under "Advanced" on the edit page |

<details>
<summary>Development</summary>

```bash
claude plugin validate .
claude plugin test .
```

Functions that take `$` must live at the top level of `hooks/register.tsx`; other files hold pure code only. Validate with a `claude` CLI that matches the running Claude Code version.
</details>
