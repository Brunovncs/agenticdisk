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
agenticdisk apply space-1a2b3c4d --actions a2,a5        # shows exactly what would change
agenticdisk apply space-1a2b3c4d --actions a2,a5 --yes  # after the user agrees
agenticdisk undo <journal>      # reverts the settings that run changed
```

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
| "What is this folder? Can I delete it?" | Knowledge base: 56 space rules (87 locations and build-folder patterns), 18 privacy checks, 62 app entries, `explain <path>`, real last-used age |
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

- agenticdisk itself only empties knowledge-base cache folders and sets allow-listed registry values;
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
it) and a `fix` with `safety`, `consent`, `admin`, `command` and, when agenticdisk can apply it
itself, a machine-readable `op`.

## Architecture

```
crates/
  agenticdisk-core/      OS-independent: output model, knowledge base (kb/*.toml), parallel
                         scanner, cleanup engine, goals, plan/apply/journal/undo
  agenticdisk-windows/   collectors: registry, WMI, Task Scheduler COM, WinVerifyTrust,
                         Event Log; kb/privacy.toml, kb/apps.toml
  agenticdisk/           CLI and JSON envelope
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
| `disk C:\Users\me` (449 GB, ~2M files) | 6-7 s warm; ~15.5 s cold with the default 64 I/O threads (~24 s with 12) |

Cold directory enumeration is latency-bound, so the walker keeps many requests in flight on SSDs
(4 threads on spinning disks). Signatures are checked from the PE header, and the full hash is
computed only where it can change a verdict. `--trace` prints per-step timings.

## Roadmap

1. NTFS MFT reader when elevated (cold full-disk scans in seconds).
2. MCP server exposing the same commands.
3. Restore point before system-wide changes; quarantine (Recycle Bin) for user-approved file removal.
4. Linux and macOS collectors.

## Build

```
cargo build --release      # target/release/agenticdisk.exe
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```
