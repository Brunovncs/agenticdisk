# Using agenticdisk as an agent

Playbook for an AI agent asked to "clean up / speed up / fix this PC". Read SAFETY.md once.

Over MCP the commands are tools: `goals` = `pc_goals`, `plan` = `pc_plan`, `preview` =
`pc_preview`, `apply --token` = `pc_apply`, `undo` = `pc_undo`, an area command = `pc_inspect`,
`disk` = `pc_disk`, `explain` = `pc_explain`, `clean` (dry run only) = `pc_clean_preview`.

## The loop

1. **Find out what the user wants.** Run `agenticdisk goals` and ask its `ask_the_user` question
   in your own words, unless they already said it ("my disk is full" = `space`, "it's slow" =
   `speed`, "blue screens" = `stability`). Vague request = `all`.
2. **Plan.** `agenticdisk plan <goal>` returns numbered actions, the questions to ask, advice that
   only a human can act on, and blind spots. Nothing changes. For `space` it also lists build
   folders (`node_modules`, Rust `target`, venvs...) one per project with idle days, so there is
   no need for a full `disk` scan first.
3. **Ask the `questions`.** They are grouped: one question per family (sign-in apps, optional
   apps), not one per item. Never answer them yourself.
4. **Preview.** `agenticdisk preview <plan> --actions a3,a7` (read-only) returns `confirm`, the
   exact text of what will change, and a one-use `token`. Show `confirm` to the user verbatim.
5. **Apply only after a yes.** `agenticdisk apply --token <token>` runs exactly what the preview
   showed. Report `freed`, each outcome, and the `journal` id. If a `script` was produced (admin
   steps, uninstalls, virtual-disk compaction), ask the user to review and run it.
6. **Verify.** Re-run the plan or `agenticdisk` and report the before/after numbers.

## Rules

- `--actions safe` is fine for regenerable caches and reversible settings marked safe. Everything
  in consent classes `project`, `software`, `rollback`, `evidence` and `user_data` needs the user to
  name it.
- `plan` lists build folders and virtual disks as groups: shared fields once, then `items` with
  each `id`, `path`, `reclaim` and `idle_days`. `active: true` = changed in the last 2 weeks.
- If the space plan's `coverage.not_listed` is large, say so and offer `disk <drive>`: the plan only
  knows reclaimable locations, not games, apps or the user's own files.
- Never run fix commands from findings by hand when an action exists for them: `apply` journals,
  verifies and can undo; your shell cannot. Fixes marked `auto: true` exist only through `apply`.
- If a tool or command fails, report the error. Do not redo the change with your own shell commands.
- For "what is this folder / can I delete it?", use `explain`: it returns the verdict, size,
  `idle_days`, the largest children and the known locations `inside` it.
- `idle_days` / `idle_90d` show when a folder was last *used* (newest file inside). A 90 GB
  `target/` touched today belongs to an active project: ask before cleaning it.
- `blind_spots` mean "not checked", not "fine". Offer an elevated re-run when they matter.
- Security findings come before cleanup. Never delete a flagged file yourself: scan it with
  Defender and show the user the evidence.
- `stability.bluescreens`: analyze a dump (the fix command) before changing drivers; do not delete
  dumps while the cause is unknown.
- Anything that restarts the PC needs the user's go-ahead in that moment.
- If `apply` reports a registry value "did not stick", say so: something (policy, MDM, Windows)
  is enforcing it. Do not try to force it.

## Other commands

`disk [path]` (size tree, largest files, dev caches with idle age), `explain <path>` (what is this
folder; is it protected), `cleanup`, `system`, `drivers [--full]`, `privacy`, `startup`, `apps`,
`security`, `stability`, `history`, `undo <journal>`, `rules`. Global flags: `--pretty`, `--bytes`,
`--min-severity`, `--max-findings`, `--threads`, `--trace`.
