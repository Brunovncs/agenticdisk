# Safety model

agenticdisk is built so that an AI agent can use it on someone's computer without being able to
hurt them. Reading is broad; writing is narrow, explicit and auditable.

## Guarantees

1. **Read commands never change anything.** `overview`, `goals`, `plan`, `disk`, `cleanup`,
   `system`, `drivers`, `privacy`, `startup`, `apps`, `security`, `stability`, `explain`, `rules`,
   `history`, `preview` and `apply` without `--yes` only read. (`plan` saves the plan file it
   prints, `preview` its token; `apply` writes its journal.)
2. **Nothing changes without an explicit, specific approval.** `preview` shows the exact text of
   what will change and returns a one-use token (valid 1 hour); `apply --token` runs exactly those
   actions and nothing else. Over MCP that is the only way: `pc_preview` is read-only and
   `pc_apply` takes nothing but the token. From a terminal, `apply <plan> --actions` also works
   with `--yes` or an interactive "y". There is no "apply everything": `all` is rejected, and the
   `safe` shorthand only covers regenerable caches and reversible settings.
3. **Personal files are never deleted by agenticdisk.** Actions in the `user_data` consent class
   are refused by the engine itself. These folders can never be the target of a deletion, however
   a rule, environment variable or `..` resolves: the user profile, Documents, Desktop, Pictures,
   Videos, Music, Downloads, OneDrive, AppData (and Local/Roaming/LocalLow), C:\Users, Windows,
   ProgramData, Program Files and Program Files (x86). Nothing *inside* WinSxS, Installer,
   System32, SysWOW64, `.ssh` or a `.git` folder can ever be deleted.
4. **Only three kinds of writes are performed by agenticdisk itself:**
   - emptying knowledge-base cache folders (rules marked `clean = "contents"`), skipping anything
     modified in the rule's age window (7 days for temp folders) and names it must keep;
   - deleting a build folder the user named (`target`, `node_modules`, a venv...). At apply time
     it must still match its rule, project marker included (`Cargo.toml` next to `target`,
     `package.json` next to `node_modules`), or it is refused;
   - setting registry values that appear in the knowledge base, plus Task Manager's
     StartupApproved entries. Every other key is refused.
5. **Everything else becomes a script the user reads and runs**: uninstalls, DISM, pnputil, driver
   removal, admin-only steps when not elevated. Each step asks for its own confirmation; backups
   (`reg export`, `pnputil /export-driver`) run first.
6. **Every write is journaled** (`%LOCALAPPDATA%\agenticdisk\journal`) with the prior value of each
   registry setting, re-read after writing to verify it stuck, and reversible with
   `agenticdisk undo <journal>`. Cache deletions are not undoable by design: those files regenerate.
7. **Plans expire after 24 hours** and are re-validated at apply time (paths re-resolved and
   re-guarded, registry allow-list re-checked).
8. **Links are never followed when deleting.** A cache folder that is a junction or symlink is
   refused; links inside it are removed as links, never their targets.
9. **Unknown is not "no".** When something cannot be read without admin, it is reported as a blind
   spot, never as absent or clean.

## Consent classes

| Class | Meaning | In the `safe` batch? |
|---|---|---|
| `cache` | Regenerable data (caches, temp). Costs at most a re-download or rebuild. | yes, when safety is `safe` |
| `setting` | A reversible setting (registry value, startup entry). | yes, when safety is `safe` |
| `project` | A build folder of one of the user's projects (`active` = changed in the last 2 weeks). | no, the user picks the projects |
| `software` | Uninstalls apps, drivers or features. | no, name each id |
| `rollback` | Removes the ability to roll back (Windows.old, hibernation, update backups). | no |
| `evidence` | Crash dumps and logs that may still be needed. | no |
| `user_data` | The user's files. | never executed by agenticdisk |

## What agenticdisk will not do

Registry "cleaning", deleting WinSxS or Installer contents, disabling Windows Update or Defender,
removing the Store, WebView2 or app frameworks, blocking Microsoft domains in `hosts`, disabling the
pagefile, `vssadmin delete shadows`, or "RAM cleaners". These are popular and harmful.

## Disclaimer

agenticdisk is provided "as is", without warranty of any kind (see LICENSE). It is designed never
to delete personal files and never to change anything without explicit approval, but computers
differ, and you remain responsible for the actions you choose to approve and the scripts you choose
to run. Keep backups of anything you cannot afford to lose.
