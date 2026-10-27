# agenticdisk

**PC diagnostics and safe cleanup, built for AI agents.**

Ask your agent "my PC is slow", "my disk is full" or "I keep getting blue screens". With
agenticdisk it gets the whole picture in about two seconds as compact, ranked JSON. It turns that
picture into a numbered plan with the questions it should ask you. It applies only what you
approve, and every change is journaled and undoable.

```
agenticdisk                     # overview: everything, in parallel, ~2s
agenticdisk goals               # what the user can ask for
agenticdisk plan space          # numbered actions + questions; changes nothing
agenticdisk preview space-1a2b3c4d --actions a2,a5  # exactly what would change + a token
agenticdisk apply --token t-0123456789abcdef        # after the user agrees
agenticdisk undo <journal>      # reverts the settings that run changed
```

## Use it from your agent (MCP)

Paste this into Claude Code, Cursor, Codex or any agent with a shell:

```text
Install agenticdisk as an MCP server. It lets you inspect this Windows PC (disk space, caches, drivers, startup apps, privacy settings, bloatware, security, crashes) and apply only the changes I approve. It needs Node.js 18+: check with `node --version`, and if it is missing, tell me instead of installing it.

- Claude Code: run `claude mcp add agenticdisk --scope user -- cmd /c npx -y agenticdisk mcp` (on Windows, npx needs the `cmd /c` wrapper).
- Other MCP clients (Claude Desktop, Cursor, VS Code, Windsurf, Codex...): add a server named "agenticdisk" with command "cmd" and args ["/c", "npx", "-y", "agenticdisk", "mcp"] to the client's MCP config (Claude Desktop: %APPDATA%\Claude\claude_desktop_config.json under "mcpServers"; Cursor: %USERPROFILE%\.cursor\mcp.json under "mcpServers"; VS Code: .vscode\mcp.json under "servers"; Codex: [mcp_servers.agenticdisk] in %USERPROFILE%\.codex\config.toml). Edit the file in place and keep every server already in it.
- If you can't add MCP servers, use the CLI instead: `npx -y agenticdisk goals`, `npx -y agenticdisk plan <goal>` and the other commands print the same JSON.

Check it works with `npx -y agenticdisk goals` (it prints JSON with 8 goals). A newly added MCP server usually loads only in a new session: if the pc_* tools are not available to you yet, tell me to restart you, and use the CLI meanwhile. Don't run anything as administrator unless I ask: it works without admin and reports what it could not see.

Tell me in one line when it's ready, then ask me what I want to fix: more space, a faster PC, less tracking, removing bloat, a malware check, crashes, or gaming. Answer in the language of my request.
```

The server is the same binary (`agenticdisk mcp`, stdio): every tool runs the same code as the
CLI command it mirrors. Tools: `pc_goals`, `pc_overview`, `pc_plan`, `pc_preview` (read-only: the
exact confirmation text and a token), `pc_apply` (the only one that changes anything: takes that
token), `pc_undo`, `pc_history`, `pc_inspect`, `pc_disk`, `pc_explain`, `pc_clean_preview`,
`pc_rules`; prompt `fix_my_pc`; resources `agenticdisk://docs/agents` and
`agenticdisk://docs/safety`. Previewing is a separate read-only tool so that clients which gate
destructive tools (permission rules, auto-mode classifiers) let the agent show the user what will
change before asking.

### Testing before the npm release

```powershell
cargo build --release
# 1. The binary directly:
claude mcp add agenticdisk-dev --scope user -- C:\path\to\agenticdisk\target\release\agenticdisk.exe mcp
# 2. The npm package exactly as users get it (npx does not run bins from a local .tgz; npm exec does):
cd npm; npm pack
claude mcp add agenticdisk-dev --scope user -- cmd /c npm exec --yes --package=C:\path\to\agenticdisk\npm\agenticdisk-0.1.0.tgz -- agenticdisk mcp
```

CI also uploads `agenticdisk.exe` and the `.tgz` as artifacts on every push. To publish:
`cargo build --release`, then `npm publish` in `npm/` (`prepack` copies the binary and refuses a
version that differs from `Cargo.toml`).

## Why

An agent with a shell can already poke at a PC. It does it slowly, burns tokens and makes the same
mistakes every time:

- it calls a folder "unused since 2024" from the folder's date, while the game inside was played last week;
- it reads "access denied" as "not there";
- it wipes the active project's 90 GB build folder along with the dead ones;
- it pastes `New-Item -Force` from a blog, which silently wipes a registry key;
- it bundles risky deletions into a single "yes".

agenticdisk encodes what a careful expert would do:

| What the agent needs | What agenticdisk provides |
|---|---|
| The picture, fast and small | 8 collectors in parallel, ranked findings, sizes as `"12.4G"`, `--max-findings` |
| "What is this folder? Can I delete it?" | Knowledge base: 57 space rules (91 locations and build-folder patterns), 18 privacy checks, 62 app entries, `explain <path>`, real last-used age |
| What the user actually wants | Goals (`space`, `speed`, `privacy`, `debloat`, `security`, `stability`, `gaming`, `all`) mapped to findings, with grouped questions to ask |
| Root causes, not symptoms | Blue screens with stop codes and dump paths, boot-time service timeouts with dates, hardware (WHEA) errors |
| Safe changes | Consent classes, protected paths, journaled and verified writes, `undo`, scripts for anything risky |
| Honesty | `blind_spots` for everything that needs admin, "did not stick" when Windows reverts a setting |

## What it covers

| Area | Highlights |
|---|---|
| **Space** | Temp and caches (age-aware), GPU shader caches, browser caches, developer caches across every project (`node_modules`, Rust `target`, venvs, Gradle, Go, npm, pip...) with idle age, Docker/WSL disks, superseded driver packages, hibernation, Windows.old |
| **Speed** | Sign-in apps (reversible disable, like Task Manager), auto-start services and tasks, memory pressure, pending restarts, HDD system drive, failing devices |
| **Stability** | Blue screens (stop code + meaning + dump) and how long since the last one, unexpected shutdowns, WHEA hardware errors, services timing out at boot, crash-dump settings |
| **Privacy** | Telemetry level, advertising ID, activity history, Bing in Start, inking/typing, feedback prompts, Recall policy |
| **Debloat** | Preinstalled apps (safe set vs. "do you use these?"), OEM trialware, silent app installs, Start/lock-screen/Settings ads |
| **Security** | Defender state and threats, active antivirus, IFEO/Winlogon/AppInit hijacks, UAC/firewall/SmartScreen, hosts/proxy tampering, suspicious autostarts and processes (signature checks), PUPs, known-vulnerable kernel drivers, orphan driver services, memory integrity |
| **Drivers** | Problem devices with codes, superseded packages (in-use and rollback versions kept, exported before removal), third-party inventory |

## Safety

Reading is broad and never changes anything. Writing is narrow:

- agenticdisk itself only empties knowledge-base cache folders, deletes the build folders you name (re-checked against their project marker) and sets allow-listed registry values;
- everything else (uninstalls, DISM, drivers, admin steps) becomes a script you review and run, with one confirmation per step;
- every write is journaled and verified, and settings can be undone;
- personal files are never deleted, and protected folders cannot be targeted by any rule, variable or `..`.

See [SAFETY.md](SAFETY.md) for the full guarantees and [AGENTS.md](AGENTS.md) for the agent playbook.

> agenticdisk is provided **as is, without warranty** (MIT License). It is designed never to delete
> personal files and never to change anything without explicit approval, but you remain responsible
> for what you approve and run. Keep backups of anything you cannot afford to lose.

## Output contract

Every report prints one JSON document: `summary` (counts and reclaimable space, computed before any
filtering), `findings` (most severe and largest first), `sections`, `blind_spots` and `next`. Each
finding has a stable `id`, `severity`, `evidence`, `reclaim` (or `size` when a fix frees only part of
it) and a `fix` with `safety`, `consent`, `admin` and either `command` (for the user to run) or
`auto: true` (agenticdisk applies it itself through `plan` + `apply`, journaled and undoable, so the
raw command is left out on purpose). Over MCP, `next` hints name tools (`pc_preview(...)`) instead of
command lines. `plan` lists actions of one kind (build folders, virtual disks) once, as a group whose
`items` carry the per-folder `id`, `path`, `reclaim` and `idle_days`, and for `space` adds
`coverage`: how much of the drive's used space the plan accounts for. `--bytes` (MCP: `bytes: true`)
prints exact integers.

## Architecture

```
crates/
  agenticdisk-core/      OS-independent: output model, knowledge base (kb/*.toml), parallel
                         scanner, cleanup engine, goals, plan/apply/journal/undo
  agenticdisk-windows/   collectors: registry, WMI, Task Scheduler COM, WinVerifyTrust,
                         Event Log; kb/privacy.toml, kb/apps.toml
  agenticdisk/           CLI, JSON envelope and the MCP server (`mcp`)
npm/                     launcher package that bundles the binary (`npx -y agenticdisk mcp`)
```

Knowledge is data, not code: a new cache location is a `[[rule]]`, a new privacy setting a
`[[check]]` (its `reg add` fix and journaled op are generated). Other operating systems plug in as
sibling crates implementing the same collectors and the `Platform` write interface.

## Performance

Windows 11, 12 threads, NVMe, not elevated:

| Run | Time |
|---|---|
| `overview` | ~1.5-2 s warm |
| `stability` (90 days of event log) | ~0.1 s |
| `plan space` (includes a build-folder scan of the user profile) | ~8 s warm |
| `disk C:\Users\me` (449 GB, ~2M files) | 6-7 s warm; ~15.5 s cold with the default 64 I/O threads (~24 s with 12) |

Cold directory enumeration is latency-bound, so the walker keeps many requests in flight on SSDs
(4 threads on spinning disks). Signatures are checked from the PE header, and the full hash is
computed only where it can change a verdict. `--trace` prints per-step timings.

## Roadmap

1. NTFS MFT reader when elevated (cold full-disk scans in seconds).
2. Publish to npm and the MCP Registry; code-sign the binary (unsigned executables trip SmartScreen and some antivirus heuristics).
3. Restore point before system-wide changes; quarantine (Recycle Bin) for user-approved file removal.
4. Linux and macOS collectors.

## Build

```
cargo build --release      # target/release/agenticdisk.exe
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```
