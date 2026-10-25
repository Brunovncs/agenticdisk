mod collect;
mod output;

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use agenticdisk_core::action::{Action, Applier, Journal, Op, Plan, Platform, confirmation_text};
use agenticdisk_core::goals::{self, GOALS, Goal};
use agenticdisk_core::kb::normalize;
use agenticdisk_core::scan::{ScanOptions, du};
use agenticdisk_core::{Bytes, Consent, Kb, Safety, Severity, cleanup, scan, size};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::{Value, json};

use output::{DISCLAIMER, View, envelope};

/// PC diagnostics and safe cleanup for AI agents.
///
/// Reading is broad and never changes anything. Writing happens only through `apply` (or
/// `clean --apply`) with the exact action ids the user approved, is journaled, and is undoable
/// where possible. Personal files are never deleted.
#[derive(Parser)]
#[command(name = "agenticdisk", version, about, long_about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
    /// Indented JSON (more tokens; for humans).
    #[arg(long, global = true)]
    pretty: bool,
    /// Sizes as exact byte integers instead of "12.4G".
    #[arg(long, global = true)]
    bytes: bool,
    /// Hide findings below this severity (default: low for overview, info elsewhere).
    #[arg(long, global = true, value_enum)]
    min_severity: Option<Level>,
    /// Keep at most this many findings.
    #[arg(long, global = true)]
    max_findings: Option<usize>,
    /// Filesystem walker threads (default: 64 on SSD, 4 on a spinning disk).
    #[arg(long, global = true)]
    threads: Option<usize>,
    /// Print per-step timings to stderr (diagnose a slow run).
    #[arg(long, global = true)]
    trace: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum Level {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<Level> for Severity {
    fn from(l: Level) -> Self {
        match l {
            Level::Info => Severity::Info,
            Level::Low => Severity::Low,
            Level::Medium => Severity::Medium,
            Level::High => Severity::High,
            Level::Critical => Severity::Critical,
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Everything at once, in parallel: the starting point for an agent (default).
    Overview {
        /// Only these areas, e.g. --only system,security
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
        /// Seconds to wait for collectors; slower ones are reported as blind spots.
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },
    /// What the user can ask for (space, speed, privacy, debloat, security, stability, gaming, all).
    Goals,
    /// Build a numbered action plan for one goal, with the questions to ask the user. Read-only.
    Plan {
        /// space | speed | privacy | debloat | security | stability | gaming | all
        goal: String,
    },
    /// Apply actions from a plan. Without --yes it only shows exactly what would change.
    Apply {
        plan: String,
        /// Action ids (a1,a4) or `safe` (safe cache/setting actions only). Never a wildcard.
        #[arg(long, value_delimiter = ',', required = true)]
        actions: Vec<String>,
        /// The user has seen the confirmation text and agreed.
        #[arg(long)]
        yes: bool,
    },
    /// Revert the registry changes of an `apply` run (cache deletions regenerate on their own).
    Undo { journal: String },
    /// Past `apply` runs, newest first.
    History,
    /// OS, hardware, volumes, memory, pending reboot, GPU driver age.
    System,
    /// Full size tree of a folder or drive, largest files, extensions and knowledge-base matches.
    Disk {
        /// Folder or drive to scan (default: system drive).
        path: Option<PathBuf>,
        /// Children per tree level.
        #[arg(long, default_value_t = 8)]
        top: usize,
        /// Tree depth below the root.
        #[arg(long, default_value_t = 3)]
        depth: usize,
        /// Hide subtrees smaller than this % of the total.
        #[arg(long, default_value_t = 1.0)]
        min_share: f64,
        /// Number of largest files listed.
        #[arg(long, default_value_t = 15)]
        files: usize,
    },
    /// Size of every known cache / temp / leftover location (no full scan needed).
    Cleanup,
    /// Empty knowledge-base locations by rule id. Dry run unless --apply (journaled).
    Clean {
        /// Rule ids from `cleanup` findings (fix.clean_rule), e.g. win.temp_user.
        #[arg(required = true)]
        rules: Vec<String>,
        #[arg(long)]
        apply: bool,
    },
    /// Problem devices, superseded driver packages, vulnerable and orphan drivers.
    Drivers {
        /// Also list every third-party driver with version and date (slower, ~3s).
        #[arg(long)]
        full: bool,
    },
    /// Telemetry, ads and privacy settings with exact fixes.
    Privacy,
    /// Everything that starts automatically, with signatures and suspicious markers.
    Startup,
    /// Installed programs and Store apps: bloat, trialware, largest installs.
    Apps,
    /// Defender state, active threats, hijacks, suspicious autostarts/processes, PUPs.
    Security,
    /// Blue screens with stop codes, unexpected shutdowns, hardware errors, boot service failures.
    Stability,
    /// What is this file or folder, and is it safe to delete?
    Explain { path: PathBuf },
    /// Dump the space knowledge base (optionally one rule).
    Rules { id: Option<String> },
}

#[cfg(windows)]
pub fn elevated() -> bool {
    agenticdisk_windows::elevated()
}

#[cfg(not(windows))]
pub fn elevated() -> bool {
    std::env::var("USER").is_ok_and(|u| u == "root")
}

#[cfg(windows)]
fn platform() -> &'static dyn Platform {
    &agenticdisk_windows::platform::Windows
}

#[cfg(not(windows))]
fn platform() -> &'static dyn Platform {
    struct Unsupported;
    impl Platform for Unsupported {
        fn elevated(&self) -> bool {
            elevated()
        }
        fn reg_allowed(&self, _: &str, _: &str) -> bool {
            false
        }
        fn reg_read(&self, _: &str, _: &str) -> Result<Option<agenticdisk_core::action::RegData>, String> {
            Err("no registry on this platform".into())
        }
        fn reg_write(&self, _: &str, _: &str, _: &agenticdisk_core::action::RegData) -> Result<(), String> {
            Err("no registry on this platform".into())
        }
        fn reg_delete(&self, _: &str, _: &str) -> Result<(), String> {
            Err("no registry on this platform".into())
        }
    }
    &Unsupported
}

#[cfg(windows)]
fn rotational(path: &std::path::Path) -> Option<bool> {
    agenticdisk_windows::system::is_rotational(path)
}

#[cfg(not(windows))]
fn rotational(_: &std::path::Path) -> Option<bool> {
    None
}

fn default_root() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(format!("{}\\", std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into())))
    } else {
        PathBuf::from("/")
    }
}

fn admin_hint(next: &mut Vec<String>) {
    if !elevated() {
        next.push("Some checks are partial without admin (see blind_spots). Re-run from an elevated shell for the full picture.".into());
    }
}

fn head(command: &str, started: Instant) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    m.insert("tool".into(), "agenticdisk".into());
    m.insert("version".into(), env!("CARGO_PKG_VERSION").into());
    m.insert("command".into(), command.into());
    m.insert("elevated".into(), elevated().into());
    m.insert("took_ms".into(), (started.elapsed().as_millis() as u64).into());
    m
}

fn goals_listing() -> Value {
    json!({
        "tool": "agenticdisk",
        "command": "goals",
        "ask_the_user": "What do you want to fix on this PC? More free space, a faster/lighter PC, less tracking, removing bloat and ads, checking for malware, crashes/blue screens, gaming performance, or a full checkup?",
        "goals": GOALS.iter().map(|g| json!({
            "goal": g.name,
            "title": g.title,
            "user_says": g.user_says,
            "covers": g.covers,
        })).collect::<Vec<_>>(),
        "next": ["agenticdisk plan <goal> : numbered actions + questions for the user; nothing is changed"],
    })
}

fn action_view(a: &Action, elevated: bool) -> Value {
    let runs = if matches!(a.op, Op::Script { .. }) || (a.admin && !elevated) { "script" } else { "agenticdisk" };
    json!({
        "id": a.id,
        "title": a.title,
        "consent": a.consent,
        "safety": a.safety,
        "admin": a.admin,
        "reclaim": a.reclaim,
        "runs": runs,
        "what": a.describe(),
        "undo": a.undo,
        "note": a.note,
    })
}

fn plan(kb: &'static Kb, goal_name: &str, started: Instant) -> anyhow::Result<Value> {
    let goal =
        Goal::parse(goal_name).ok_or_else(|| anyhow::anyhow!("unknown goal `{goal_name}`; run `agenticdisk goals`"))?;
    let info = goal.info();
    let sections = collect::run(collect::named(kb, info.collectors, false), Duration::from_secs(45));
    let (findings, blind_spots, _) = output::merge(sections);
    let built = goals::build(goal, &findings);
    built.plan.save()?;
    let elevated = elevated();
    let actions = &built.plan.actions;
    let reclaim = |pred: &dyn Fn(&Action) -> bool| {
        Bytes(actions.iter().filter(|a| pred(a)).filter_map(|a| a.reclaim).map(|b| b.0).sum())
    };
    let safe_batch = built.plan.select(&["safe".into()], elevated).unwrap_or_default();
    let mut m = head("plan", started);
    m.insert("goal".into(), info.name.into());
    m.insert("plan".into(), built.plan.id.clone().into());
    m.insert("expires_in_hours".into(), 24.into());
    m.insert(
        "summary".into(),
        json!({
            "actions": actions.len(),
            "safe_batch": safe_batch.iter().map(|a| a.id.clone()).collect::<Vec<_>>(),
            "safe_batch_reclaim": reclaim(&|a| safe_batch.iter().any(|s| s.id == a.id)),
            "total_reclaim_if_all_approved": reclaim(&|_| true),
            "needs_admin": actions.iter().filter(|a| a.admin).count(),
            "questions": built.questions.len(),
        }),
    );
    m.insert("actions".into(), actions.iter().map(|a| action_view(a, elevated)).collect());
    m.insert("questions".into(), serde_json::to_value(&built.questions)?);
    m.insert("advice".into(), serde_json::to_value(&built.advice)?);
    m.insert("blind_spots".into(), blind_spots.into());
    m.insert(
        "next".into(),
        json!([
            "Ask the user the `questions`, then decide the action ids together. Never pick consent classes software/rollback/evidence/user_data on your own.",
            format!("agenticdisk apply {} --actions <ids|safe> : shows exactly what will change (no changes yet)", built.plan.id),
            "Show the user the returned `confirm` text verbatim; only after they agree, re-run with --yes.",
        ]),
    );
    Ok(Value::Object(m))
}

fn ask_interactively(text: &str) -> bool {
    eprintln!("{text}\n\nProceed? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).is_ok()
        && matches!(line.trim().to_lowercase().as_str(), "y" | "yes" | "s" | "sim")
}

fn apply(kb: &'static Kb, plan_id: &str, selectors: &[String], yes: bool, started: Instant) -> anyhow::Result<Value> {
    let plan = Plan::load(plan_id).map_err(anyhow::Error::msg)?;
    let elevated = elevated();
    let chosen = plan.select(selectors, elevated).map_err(anyhow::Error::msg)?;
    if chosen.is_empty() {
        anyhow::bail!("no actions selected");
    }
    let applier = Applier { kb, platform: platform() };
    let confirm = confirmation_text(&chosen);
    let approved = yes || (std::io::stdin().is_terminal() && ask_interactively(&confirm));
    let mut m = head("apply", started);
    m.insert("plan".into(), plan.id.clone().into());
    if !approved {
        m.insert("status".into(), "awaiting_confirmation".into());
        m.insert("confirm".into(), confirm.into());
        m.insert("preview".into(), applier.preview(&chosen).into());
        m.insert(
            "next".into(),
            json!([format!(
                "Show `confirm` to the user word for word. Only if they agree: agenticdisk apply {} --actions {} --yes",
                plan.id,
                chosen.iter().map(|a| a.id.as_str()).collect::<Vec<_>>().join(",")
            )]),
        );
        return Ok(Value::Object(m));
    }
    let journal = applier.run(&plan, &chosen);
    let freed: u64 = journal.outcomes.iter().filter_map(|o| o.freed).map(|b| b.0).sum();
    m.insert("status".into(), "applied".into());
    m.insert("journal".into(), journal.id.clone().into());
    m.insert("freed".into(), Bytes(freed).to_string().into());
    m.insert("outcomes".into(), serde_json::to_value(&journal.outcomes)?);
    let mut next = Vec::new();
    if journal.outcomes.iter().any(|o| !o.registry.is_empty()) {
        next.push(format!("agenticdisk undo {} : reverts the registry changes above", journal.id));
    }
    if let Some(script) = &journal.script {
        m.insert("script".into(), script.display().to_string().into());
        next.push(format!(
            "Some actions need the user's hands (admin rights or external tools). Ask them to review and run: powershell -ExecutionPolicy Bypass -File \"{}\"{}",
            script.display(),
            if chosen.iter().any(|a| a.admin) { " from an elevated (Run as administrator) terminal" } else { "" }
        ));
    }
    next.push("Re-run `agenticdisk plan <goal>` or `agenticdisk` to verify the result.".into());
    m.insert("next".into(), next.into());
    m.insert("disclaimer".into(), DISCLAIMER.into());
    Ok(Value::Object(m))
}

fn explain(kb: &'static Kb, raw: &std::path::Path) -> Value {
    let path = normalize(raw);
    let protected = cleanup::protected(&path);
    let explained = kb.explain(&path);
    // A drive root or a top-level folder can take minutes to size; skip it.
    let sized = (path.components().count() >= 3).then(|| du(&path));
    let verdict = if protected {
        "protected location (personal or system folder): agenticdisk never deletes it"
    } else {
        match explained.as_ref().map(|(r, _)| r.safety) {
            Some(Safety::Safe) => "known, safe to remove (regenerated automatically)",
            Some(Safety::Caution) => "known, removable with a cost (see note)",
            Some(Safety::Manual) => "known, user data or a choice: ask the user",
            Some(Safety::Never) => "known, do NOT delete: use the command instead",
            None => "unknown to the knowledge base: inspect contents and ask the user",
        }
    };
    json!({
        "tool": "agenticdisk",
        "command": "explain",
        "path": path.display().to_string(),
        "exists": agenticdisk_core::kb::exists(&path),
        "size": sized.map(|s| Bytes(s.0)),
        "files": sized.map(|s| s.1),
        "unreadable_dirs": sized.map(|s| s.2),
        "protected": protected,
        "rule": explained.as_ref().map(|(r, _)| serde_json::to_value(r).expect("rule serializes")),
        "matched": explained.as_ref().map(|(_, p)| p.display().to_string()),
        "verdict": verdict,
    })
}

fn run(cli: Cli, started: Instant) -> anyhow::Result<Value> {
    let kb: &'static Kb = Box::leak(Box::new(Kb::load()));
    let command = cli.command.unwrap_or(Cmd::Overview { only: Vec::new(), timeout: 30 });
    if cli.threads.is_none() {
        let root = match &command {
            Cmd::Disk { path: Some(p), .. } => p.clone(),
            _ => default_root(),
        };
        agenticdisk_core::io::set_threads(agenticdisk_core::io::default_threads(rotational(&root)));
    }
    let view = |default: Severity| View {
        min: cli.min_severity.map(Severity::from).unwrap_or(default),
        max: cli.max_findings,
    };

    Ok(match &command {
        Cmd::Overview { only, timeout } => {
            let names: Vec<&str> =
                if only.is_empty() { collect::AREAS.to_vec() } else { only.iter().map(String::as_str).collect() };
            let sections = collect::run(collect::named(kb, &names, false), Duration::from_secs(*timeout));
            let mut next = vec![
                "agenticdisk goals : ask the user what they want to fix, then agenticdisk plan <goal>".to_string(),
                format!(
                    "agenticdisk disk {} : full space tree, largest files, dev caches across all projects",
                    default_root().display()
                ),
                "agenticdisk explain <path> : what a folder is and whether it is safe to delete".into(),
            ];
            admin_hint(&mut next);
            envelope("overview", sections, view(Severity::Low), next, started)
        }
        Cmd::Goals => goals_listing(),
        Cmd::Plan { goal } => plan(kb, goal, started)?,
        Cmd::Apply { plan: id, actions, yes } => apply(kb, id, actions, *yes, started)?,
        Cmd::Undo { journal } => {
            let journal = Journal::load(journal).map_err(anyhow::Error::msg)?;
            let results = Applier { kb, platform: platform() }.undo(&journal);
            let mut m = head("undo", started);
            m.insert("journal".into(), journal.id.into());
            m.insert("restored".into(), results.into());
            Value::Object(m)
        }
        Cmd::History => {
            let mut m = head("history", started);
            m.insert("runs".into(), Journal::list().into());
            m.insert("data_dir".into(), agenticdisk_core::action::data_dir().display().to_string().into());
            Value::Object(m)
        }
        Cmd::Disk { path, top, depth, min_share, files } => {
            let root = path.clone().unwrap_or_else(default_root);
            let opts = ScanOptions { top: *top, depth: *depth, min_share: *min_share, largest_files: *files };
            let section = scan::scan(kb, &root, &opts);
            let next = vec![
                "agenticdisk disk <subfolder> --depth 2 : drill into one branch".into(),
                "agenticdisk explain <path> : classify an unknown folder before deleting".into(),
                "agenticdisk plan space : turn this into approved, journaled actions".into(),
            ];
            envelope("disk", vec![("disk", section)], view(Severity::Info), next, started)
        }
        Cmd::Cleanup => {
            let next =
                vec!["agenticdisk plan space : numbered actions; or agenticdisk clean <rule> for a dry run".into()];
            envelope("cleanup", vec![("cleanup", cleanup::section(kb))], view(Severity::Info), next, started)
        }
        Cmd::Clean { rules, apply } => {
            let mut m = head("clean", started);
            if *apply {
                // Same journaled path as `apply`, with the named rules as the approved actions.
                let actions: Vec<Action> = rules
                    .iter()
                    .enumerate()
                    .map(|(i, r)| Action {
                        id: format!("c{}", i + 1),
                        finding: format!("clean.{r}"),
                        title: format!("clean {r}"),
                        safety: kb.get(r).map(|x| x.safety).unwrap_or(Safety::Manual),
                        consent: kb.get(r).map(|x| x.consent()).unwrap_or(Consent::UserData),
                        admin: kb.get(r).is_some_and(|x| x.admin),
                        reclaim: None,
                        note: None,
                        undo: "not needed: regenerates on demand".into(),
                        op: Op::EmptyDir { rule: r.clone() },
                    })
                    .collect();
                let plan = Plan::new("clean", actions);
                let chosen: Vec<&Action> = plan.actions.iter().collect();
                let journal = Applier { kb, platform: platform() }.run(&plan, &chosen);
                m.insert("journal".into(), journal.id.clone().into());
                m.insert("outcomes".into(), serde_json::to_value(&journal.outcomes)?);
                m.insert("disclaimer".into(), DISCLAIMER.into());
            } else {
                m.insert("result".into(), serde_json::to_value(cleanup::clean(kb, rules, false))?);
            }
            Value::Object(m)
        }
        Cmd::Explain { path } => explain(kb, path),
        Cmd::Rules { id } => {
            let rules: Vec<_> = kb.rules.iter().filter(|r| id.as_ref().is_none_or(|i| &r.id == i)).collect();
            json!({ "tool": "agenticdisk", "command": "rules", "count": rules.len(), "rules": rules })
        }
        area => {
            let (name, detail_flag) = match area {
                Cmd::System => ("system", true),
                Cmd::Drivers { full } => ("drivers", *full),
                Cmd::Privacy => ("privacy", true),
                Cmd::Startup => ("startup", true),
                Cmd::Apps => ("apps", true),
                Cmd::Security => ("security", true),
                Cmd::Stability => ("stability", true),
                _ => unreachable!("all other commands handled above"),
            };
            let detail = detail_flag || name != "drivers";
            let collector = collect::collector(kb, name, detail)
                .ok_or_else(|| anyhow::anyhow!("`{name}` is not available on this platform yet"))?;
            let sections = collect::run(vec![collector], Duration::from_secs(120));
            let mut next = vec!["agenticdisk plan <goal> : turn findings into approved, journaled actions".to_string()];
            admin_hint(&mut next);
            envelope(name, sections, view(Severity::Info), next, started)
        }
    })
}

fn main() {
    let cli = Cli::parse();
    size::set_exact_bytes(cli.bytes);
    if let Some(n) = cli.threads {
        agenticdisk_core::io::set_threads(n);
    }
    if cli.trace {
        agenticdisk_core::trace::enable();
    }
    let pretty = cli.pretty;
    let started = Instant::now();
    let (output, code) = match run(cli, started) {
        Ok(v) => (v, 0),
        Err(e) => (json!({ "tool": "agenticdisk", "error": e.to_string() }), 1),
    };
    let text = if pretty { serde_json::to_string_pretty(&output) } else { serde_json::to_string(&output) };
    println!("{}", text.unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}")));
    std::process::exit(code);
}
