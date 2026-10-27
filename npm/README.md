# agenticdisk

PC diagnostics and safe cleanup built for AI agents, as an MCP server and a CLI. Windows 10/11.

Your agent sees the whole PC in about two seconds: where the disk space went, caches and build
folders (with when they were last used), drivers, startup apps, privacy settings, bloatware,
security and blue screens. It turns that into a plan with the questions to ask you, and applies
only what you approve. Every change is journaled and undoable, and personal files are never deleted.

## Install: paste this into your agent

```text
Install agenticdisk as an MCP server. It lets you inspect this Windows PC (disk space, caches, drivers, startup apps, privacy settings, bloatware, security, crashes) and apply only the changes I approve. It needs Node.js 18+: check with `node --version`, and if it is missing, tell me instead of installing it.

- Claude Code: run `claude mcp add agenticdisk --scope user -- cmd /c npx -y agenticdisk mcp` (on Windows, npx needs the `cmd /c` wrapper).
- Other MCP clients (Claude Desktop, Cursor, VS Code, Windsurf, Codex...): add a server named "agenticdisk" with command "cmd" and args ["/c", "npx", "-y", "agenticdisk", "mcp"] to the client's MCP config (Claude Desktop: %APPDATA%\Claude\claude_desktop_config.json under "mcpServers"; Cursor: %USERPROFILE%\.cursor\mcp.json under "mcpServers"; VS Code: .vscode\mcp.json under "servers"; Codex: [mcp_servers.agenticdisk] in %USERPROFILE%\.codex\config.toml). Edit the file in place and keep every server already in it.
- If you can't add MCP servers, use the CLI instead: `npx -y agenticdisk goals`, `npx -y agenticdisk plan <goal>` and the other commands print the same JSON.

Check it works with `npx -y agenticdisk goals` (it prints JSON with 8 goals). A newly added MCP server usually loads only in a new session: if the pc_* tools are not available to you yet, tell me to restart you, and use the CLI meanwhile. Don't run anything as administrator unless I ask: it works without admin and reports what it could not see.

Tell me in one line when it's ready, then ask me what I want to fix: more space, a faster PC, less tracking, removing bloat, a malware check, crashes, or gaming. Answer in the language of my request.
```

## Manual setup

```bash
claude mcp add agenticdisk --scope user -- cmd /c npx -y agenticdisk mcp
```

```json
{
  "mcpServers": {
    "agenticdisk": { "command": "cmd", "args": ["/c", "npx", "-y", "agenticdisk", "mcp"] }
  }
}
```

The same binary is a CLI: `npx -y agenticdisk` (overview), `goals`, `plan <goal>`, `apply`,
`undo`, `disk <path>`, `explain <path>`, `stability`, `security`... Run `npx -y agenticdisk --help`.

## Tools

| Tool | What it does |
|---|---|
| `pc_goals` | What the user can ask for, and the question to ask them |
| `pc_overview` | Everything at once, ranked, ~2 s |
| `pc_plan` | Numbered actions for a goal + grouped questions for the user (changes nothing) |
| `pc_preview` | Read-only: the exact text of what will change, and a one-use token |
| `pc_apply` | The only tool that changes anything: takes the token, after the user agrees |
| `pc_undo`, `pc_history` | Revert registry changes; list past runs |
| `pc_inspect` | Full detail for one area (system, cleanup, drivers, privacy, startup, apps, security, stability) |
| `pc_disk` | Size tree with largest files and known caches, with idle days |
| `pc_explain` | What a folder is, and whether it is protected or safe to delete |
| `pc_clean_preview` | Dry run of a cache cleanup |
| `pc_rules` | The knowledge base |

Plus the `fix_my_pc` prompt and the `agents` / `safety` documents as resources.

## Safety

agenticdisk itself only empties known cache folders (skipping anything changed in the last days),
deletes the build folders the user names (re-checked against their project marker) and sets
allow-listed registry values. Both kinds of change are journaled and verified, and
settings can be undone. Uninstalls, driver removal and admin steps become a script you review and
run. Personal folders are protected. Provided as is, without warranty (MIT License).
