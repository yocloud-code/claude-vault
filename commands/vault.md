---
description: 凭证保险库：管理数据库/服务器/集群凭证与目录授权
argument-hint: "[grant <p> [read|write]|revoke <p>|list|export|import]"
---
This command is normally answered by the claude-vault mod's hooks, so this text only reaches you when those hooks did not load in this session.

Tell the user, in their language, that the claude-vault mod is installed but its hooks are not active in this session, and that a new session after enabling it should fix it: the plugin folder must be listed in `CLAUDE_CODE_PLUGIN_DIRS` in `~/.claude/settings.json`. Do not run any command to inspect credentials.
