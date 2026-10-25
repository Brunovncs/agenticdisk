# Using agenticdisk as an agent

Playbook for an AI agent asked to "clean up / speed up / fix this PC". Read SAFETY.md once.

## The loop

1. **Find out what the user wants.** Run `agenticdisk goals` and ask its `ask_the_user` question
   in your own words, unless they already said it ("my disk is full" = `space`, "it's slow" =
   `speed`, "blue screens" = `stability`). Vague request = `all`.
2. **Plan.** `agenticdisk plan <goal>` returns numbered actions, the questions to ask, advice that
   only a human can act on, and blind spots. Nothing changes.
3. **Ask the `questions`.** They are grouped: one question per family (sign-in apps, optional
   apps), not one per item. Never answer them yourself.
4. **Preview.** `agenticdisk apply <plan> --actions a3,a7` (no `--yes`) returns `confirm`, the exact
   text of what will change. Show it to the user verbatim.
5. **Apply only after a yes.** Re-run with `--yes`. Report `freed`, each outcome, and the `journal`
   id. If a `script` was produced (admin steps, uninstalls), ask the user to review and run it.
6. **Verify.** Re-run the plan or `agenticdisk` and report the before/after numbers.

## Rules

- `--actions safe` is fine for regenerable caches and reversible settings marked safe. Everything
  in consent classes `software`, `rollback`, `evidence` and `user_data` needs the user to name it.
- Never run fix commands from findings by hand when an action exists for them: `apply` journals,
  verifies and can undo; your shell cannot.
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
