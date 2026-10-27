mod collect;
mod mcp;
mod output;

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use agenticdisk_core::action::{
    Action, Applier, Journal, Op, PREVIEW_TTL_SECS, Plan, Platform, Preview, confirmation_text,
};
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
    /// Show exactly what applying these actions would change, and a token to apply it. Read-only.
    Preview {
        plan: String,
        /// Action ids (a1,a4) or `safe` (safe cache/setting actions only). Never a wildcard.
        #[arg(long, value_delimiter = ',', required = true)]
        actions: Vec<String>,
    },
    /// Apply what a preview showed (`--token`), or actions from a plan (`--actions`; without
    /// --yes that only previews).
    Apply {
        #[arg(required_unless_present = "token")]
        plan: Option<String>,
        /// Action ids (a1,a4) or `safe` (safe cache/setting actions only). Never a wildcard.
        #[arg(long, value_delimiter = ',', required_unless_present = "token")]
        actions: Vec<String>,
        /// Token from `preview`: applies exactly the actions it showed.
        #[arg(long, conflicts_with_all = ["plan", "actions", "yes"])]
        token: Option<String>,
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
    /// Run as a Model Context Protocol server over stdio (for Claude Code, Cursor, VS Code...).
    Mcp,
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

static MCP_MODE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// `next` hints name what the caller can actually invoke: a command line, or an MCP tool.
fn hint(cli: impl Into<String>, mcp: impl Into<String>) -> String {
    if MCP_MODE.load(std::sync::atomic::Ordering::Relaxed) { mcp.into() } else { cli.into() }
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
        "next": [hint("agenticdisk plan <goal>", "pc_plan(goal)") + " : numbered actions + questions for the user; nothing is changed"],
    })
}

fn action_view(a: &Action, elevated: bool) -> Value {
    let runs = if matches!(a.op, Op::Script { .. }) || (a.admin && !elevated) { "script" } else { "agenticdisk" };
    let mut v = json!({
        "id": a.id,
        "title": a.title,
        "consent": a.consent,
        "safety": a.safety,
        "runs": runs,
        "undo": a.undo,
    });
    if let Some(p) = &a.path {
        v["path"] = p.clone().into();
    }
    if let Some(d) = a.idle_days {
        v["idle_days"] = d.into();
    }
    if a.active() {
        v["active"] = true.into();
    }
    if let (None, Some(s)) = (a.reclaim, a.size) {
        v["size"] = json!(s);
    }
    // What agenticdisk itself changes is spelled out by apply's `confirm`; whatever ends up in a
    // script is the user's to read before choosing.
    match &a.op {
        Op::Script { script } => v["script"] = script.clone().into(),
        _ if runs == "script" => v["script"] = a.describe().into(),
        _ => {}
    }
    if a.admin {
        v["admin"] = true.into();
    }
    if let Some(r) = a.reclaim {
        v["reclaim"] = json!(r);
    }
    if let Some(n) = &a.note {
        v["note"] = n.clone().into();
    }
    v
}

fn plan(kb: &'static Kb, goal_name: &str, started: Instant) -> anyhow::Result<Value> {
    let goal =
        Goal::parse(goal_name).ok_or_else(|| anyhow::anyhow!("unknown goal `{goal_name}`; run `agenticdisk goals`"))?;
    let info = goal.info();
    let mut collectors = collect::named(kb, info.collectors, false);
    if matches!(goal, Goal::Space | Goal::All)
        && let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"))
    {
        collectors.push(("build_folders", Box::new(move || scan::build_folders(kb, std::path::Path::new(&home)))));
    }
    let sections = collect::run(collectors, Duration::from_secs(45));
    let (findings, blind_spots, data) = output::merge(sections);
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
    m.insert("actions".into(), group_actions(actions, elevated).into());
    m.insert("questions".into(), serde_json::to_value(&built.questions)?);
    m.insert("advice".into(), serde_json::to_value(&built.advice)?);
    if matches!(goal, Goal::Space | Goal::All)
        && let Some(c) = coverage(&data, actions, &built.advice)
    {
        m.insert("coverage".into(), c);
    }
    m.insert("blind_spots".into(), blind_spots.into());
    m.insert(
        "next".into(),
        json!([
            "Ask the user the `questions`, then decide the action ids together. Never pick consent classes project/software/rollback/evidence/user_data on your own.".to_string(),
            hint(
                format!("agenticdisk preview {} --actions <ids|safe>", built.plan.id),
                format!("pc_preview(plan=\"{}\", actions=[ids] or [\"safe\"])", built.plan.id)
            ) + " : read-only; returns the exact `confirm` text and a token",
            hint(
                "Show the user `confirm` verbatim; only after they agree, run `agenticdisk apply --token <token>`.",
                "Show the user `confirm` verbatim; only after they agree, call pc_apply(token)."
            ),
        ]),
    );
    Ok(Value::Object(m))
}

/// Actions from one rule (build folders, virtual disks) differ only in id, path, size and age.
/// They are listed once, as a group: what all of them share is said once, `items` hold the rest.
fn group_actions(actions: &[Action], elevated: bool) -> Vec<Value> {
    let mut groups: Vec<(&str, Vec<Value>)> = Vec::new();
    for a in actions {
        // `disk.build.dev.rust_target.3` -> `disk.build.dev.rust_target`
        let key = match a.finding.rsplit_once('.') {
            Some((head, n)) if n.chars().all(|c| c.is_ascii_digit()) => head,
            _ => a.finding.as_str(),
        };
        let view = action_view(a, elevated);
        match groups.iter_mut().find(|g| g.0 == key) {
            Some(g) => g.1.push(view),
            None => groups.push((key, vec![view])),
        }
    }
    groups
        .into_iter()
        .map(|(_, mut members)| {
            if members.len() == 1 {
                return members.pop().expect("one member");
            }
            let first = members[0].as_object().cloned().unwrap_or_default();
            let shared: Vec<(String, Value)> =
                first.into_iter().filter(|(k, v)| k != "id" && members.iter().all(|m| m.get(k) == Some(v))).collect();
            for m in members.iter_mut().filter_map(Value::as_object_mut) {
                for (k, _) in &shared {
                    m.remove(k);
                }
            }
            let mut group: serde_json::Map<String, Value> = shared.into_iter().collect();
            group.insert("items".into(), members.into());
            Value::Object(group)
        })
        .collect()
}

/// How much of the system drive's used space this plan accounts for. What it does not list is
/// not reclaimable as far as the plan knows, but the user should see that it exists.
fn coverage(data: &serde_json::Map<String, Value>, actions: &[Action], advice: &[goals::Advice]) -> Option<Value> {
    let drive = default_root().display().to_string();
    let volume = data
        .get("system")?
        .get("volumes")?
        .as_array()?
        .iter()
        .find(|v| v["mount"].as_str().is_some_and(|m| m.eq_ignore_ascii_case(&drive)))?;
    let bytes = |v: &Value| serde_json::from_value::<Bytes>(v.clone()).ok().map(|b| b.0);
    let used = bytes(&volume["size"])?.saturating_sub(bytes(&volume["free"])?);
    let listed: u64 = actions.iter().filter_map(|a| a.reclaim.or(a.size)).map(|b| b.0).sum::<u64>()
        + advice.iter().filter_map(|a| a.size).map(|b| b.0).sum::<u64>();
    let rest = used.saturating_sub(listed);
    let mut c = json!({ "volume": drive, "used": Bytes(used), "listed_here": Bytes(listed.min(used)), "not_listed": Bytes(rest) });
    if rest > used / 10 {
        c["next"] = (hint(format!("agenticdisk disk {drive}"), format!("pc_disk(path={drive:?})"))
            + " : where the rest is (games, installed apps, user files, Windows itself); a whole drive can take a minute the first time")
            .into();
    }
    Some(c)
}

fn ask_interactively(text: &str) -> bool {
    eprintln!("{text}\n\nProceed? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).is_ok()
        && matches!(line.trim().to_lowercase().as_str(), "y" | "yes" | "s" | "sim")
}

fn selected(plan_id: &str, selectors: &[String]) -> anyhow::Result<Plan> {
    let plan = Plan::load(plan_id).map_err(anyhow::Error::msg)?;
    if plan.select(selectors, elevated()).map_err(anyhow::Error::msg)?.is_empty() {
        anyhow::bail!("no actions selected");
    }
    Ok(plan)
}

/// Changes nothing: the exact confirmation text, current values and sizes, and the one-use token
/// that lets `apply` run exactly these actions.
fn preview(kb: &'static Kb, plan_id: &str, selectors: &[String], started: Instant) -> anyhow::Result<Value> {
    let plan = selected(plan_id, selectors)?;
    let chosen = plan.select(selectors, elevated()).map_err(anyhow::Error::msg)?;
    let token = Preview::new(&plan, &chosen);
    token.save()?;
    let mut m = head("preview", started);
    m.insert("plan".into(), plan.id.clone().into());
    m.insert("status".into(), "awaiting_confirmation".into());
    m.insert("confirm".into(), confirmation_text(&chosen).into());
    m.insert("preview".into(), Applier { kb, platform: platform() }.preview(&chosen).into());
    m.insert("token".into(), token.token.clone().into());
    m.insert("expires_in_minutes".into(), (PREVIEW_TTL_SECS / 60).into());
    m.insert(
        "next".into(),
        json!([format!(
            "Show `confirm` to the user word for word. Only if they agree: {}",
            hint(format!("agenticdisk apply --token {}", token.token), format!("pc_apply(token=\"{}\")", token.token))
        )]),
    );
    m.insert("took_ms".into(), (started.elapsed().as_millis() as u64).into());
    Ok(Value::Object(m))
}

fn apply_token(kb: &'static Kb, token: &str, started: Instant) -> anyhow::Result<Value> {
    let shown = Preview::take(token).map_err(anyhow::Error::msg)?;
    let plan = Plan::load(&shown.plan).map_err(anyhow::Error::msg)?;
    let chosen = plan.select(&shown.actions, elevated()).map_err(anyhow::Error::msg)?;
    apply(kb, &plan, &chosen, started)
}

/// `apply <plan> --actions`: with --yes (or a "y" at the terminal) it applies, otherwise it is a
/// preview.
fn apply_selected(
    kb: &'static Kb,
    plan_id: &str,
    selectors: &[String],
    yes: bool,
    started: Instant,
) -> anyhow::Result<Value> {
    let plan = selected(plan_id, selectors)?;
    let chosen = plan.select(selectors, elevated()).map_err(anyhow::Error::msg)?;
    if yes || (std::io::stdin().is_terminal() && ask_interactively(&confirmation_text(&chosen))) {
        apply(kb, &plan, &chosen, started)
    } else {
        preview(kb, plan_id, selectors, started)
    }
}

fn apply(kb: &'static Kb, plan: &Plan, chosen: &[&Action], started: Instant) -> anyhow::Result<Value> {
    let applier = Applier { kb, platform: platform() };
    let mut m = head("apply", started);
    m.insert("plan".into(), plan.id.clone().into());
    let journal = applier.run(plan, chosen);
    let freed: u64 = journal.outcomes.iter().filter_map(|o| o.freed).map(|b| b.0).sum();
    m.insert("status".into(), "applied".into());
    m.insert("journal".into(), journal.id.clone().into());
    m.insert("freed".into(), Bytes(freed).to_string().into());
    m.insert("outcomes".into(), serde_json::to_value(&journal.outcomes)?);
    let mut next = Vec::new();
    if journal.outcomes.iter().any(|o| !o.registry.is_empty()) {
        next.push(
            hint(format!("agenticdisk undo {}", journal.id), format!("pc_undo(journal=\"{}\")", journal.id))
                + " : reverts the registry changes above",
        );
    }
    if let Some(script) = &journal.script {
        m.insert("script".into(), script.display().to_string().into());
        next.push(format!(
            "Some actions need the user's hands (admin rights or external tools). Ask them to review and run: powershell -ExecutionPolicy Bypass -File \"{}\"{}",
            script.display(),
            if chosen.iter().any(|a| a.admin) { " from an elevated (Run as administrator) terminal" } else { "" }
        ));
    }
    next.push(format!(
        "Re-run {} to verify the result.",
        hint("`agenticdisk plan <goal>`", "pc_plan for the same goal")
    ));
    m.insert("next".into(), next.into());
    m.insert("disclaimer".into(), DISCLAIMER.into());
    m.insert("took_ms".into(), (started.elapsed().as_millis() as u64).into());
    Ok(Value::Object(m))
}

fn explain(kb: &'static Kb, raw: &std::path::Path) -> Value {
    let path = normalize(raw);
    let protected = cleanup::protected(&path);
    let explained = kb.explain(&path);
    // Known locations below this folder: "Docker" is unknown, but its WSL disk is a rule.
    let inside: Vec<Value> = if explained.is_none() {
        kb.rules
            .iter()
            .flat_map(|r| Kb::resolve(r).into_iter().map(move |p| (r, p)))
            .filter(|(_, p)| p != &path && agenticdisk_core::kb::is_within(p, &path) && agenticdisk_core::kb::exists(p))
            .take(8)
            .map(|(r, p)| json!({ "path": p.display().to_string(), "rule": r.id, "what": r.what, "safety": r.safety }))
            .collect()
    } else {
        Vec::new()
    };
    let verdict = if protected {
        "protected location (personal or system folder): agenticdisk never deletes it"
    } else {
        match explained.as_ref().map(|(r, _)| r.safety) {
            Some(Safety::Safe) => "known, safe to remove (regenerated automatically)",
            Some(Safety::Caution) => "known, removable with a cost (see note)",
            Some(Safety::Manual) => "known, user data or a choice: ask the user",
            Some(Safety::Never) => "known, do NOT delete: use the command instead",
            None if !inside.is_empty() => "not a known location itself, but it contains known ones (see `inside`)",
            None => "unknown to the knowledge base: look at `largest` and `idle_days`, then ask the user",
        }
    };
    let mut m = head("explain", Instant::now());
    m.remove("took_ms");
    m.insert("path".into(), path.display().to_string().into());
    m.insert("exists".into(), agenticdisk_core::kb::exists(&path).into());
    m.insert("protected".into(), protected.into());
    m.insert("verdict".into(), verdict.into());
    if let Some((rule, matched)) = &explained {
        m.insert("rule".into(), serde_json::to_value(rule).expect("rule serializes"));
        if matched != &path {
            m.insert("matched".into(), matched.display().to_string().into());
        }
    }
    if !inside.is_empty() {
        m.insert("inside".into(), inside.into());
    }
    // A drive root or a top-level folder can take minutes to size; skip it.
    if path.components().count() >= 3 {
        if path.is_dir() {
            let opts = ScanOptions { top: 6, depth: 1, min_share: 1.0, largest_files: 3 };
            let data = scan::scan(kb, &path, &opts).data;
            for (key, from) in [("size", "/size"), ("files", "/files"), ("idle_days", "/tree/idle_days")] {
                if let Some(v) = data.pointer(from) {
                    m.insert(key.into(), v.clone());
                }
            }
            let largest: Vec<Value> = data
                .pointer("/tree/sub")
                .and_then(Value::as_array)
                .map(|sub| {
                    sub.iter()
                        .map(|n| {
                            let mut n = n.clone();
                            if let Some(name) = n["path"].as_str().and_then(|p| p.rsplit(['\\', '/']).next()) {
                                n["path"] = name.to_string().into();
                            }
                            n
                        })
                        .collect()
                })
                .unwrap_or_default();
            if !largest.is_empty() {
                m.insert("largest".into(), largest.into());
            }
            let idle = data.pointer("/tree/idle_days").and_then(Value::as_u64);
            if let (Some((rule, _)), Some(d)) = (&explained, idle)
                && rule.dir_name.is_some()
                && d < 14
                && !protected
            {
                m.insert(
                    "verdict".into(),
                    format!("known and regenerable, but in active use (changed {d} days ago): a full rebuild follows, ask first").into(),
                );
            }
            if let Some(n) = data.pointer("/inaccessible_dirs").filter(|n| n.as_u64() != Some(0)) {
                m.insert("unreadable_dirs".into(), n.clone());
            }
        } else {
            let (bytes, files, unreadable) = du(&path);
            m.insert("size".into(), json!(Bytes(bytes)));
            if unreadable > 0 || files == 0 {
                m.insert("unreadable".into(), true.into());
            }
        }
    }
    Value::Object(m)
}

fn kb() -> &'static Kb {
    static KB: std::sync::OnceLock<Kb> = std::sync::OnceLock::new();
    KB.get_or_init(Kb::load)
}

fn run(cli: Cli, started: Instant) -> anyhow::Result<Value> {
    let kb = kb();
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
                hint("agenticdisk plan <goal>", "pc_plan(goal)")
                    + " : numbered actions and the questions to ask the user (space also lists build folders per project)",
                hint("agenticdisk explain <path>", "pc_explain(path)")
                    + " : what a folder is, what is inside, and whether it is safe to delete",
            ];
            admin_hint(&mut next);
            envelope("overview", sections, view(Severity::Low), next, started)
        }
        Cmd::Goals => goals_listing(),
        Cmd::Plan { goal } => plan(kb, goal, started)?,
        Cmd::Preview { plan: id, actions } => preview(kb, id, actions, started)?,
        Cmd::Apply { token: Some(token), .. } => apply_token(kb, token, started)?,
        Cmd::Apply { plan, actions, yes, .. } => {
            let id =
                plan.as_deref().ok_or_else(|| anyhow::anyhow!("apply needs --token, or a plan id and --actions"))?;
            apply_selected(kb, id, actions, *yes, started)?
        }
        Cmd::Undo { journal } => {
            let mut journal = Journal::load(journal).map_err(anyhow::Error::msg)?;
            let results = Applier { kb, platform: platform() }.undo(&mut journal).map_err(anyhow::Error::msg)?;
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
                hint("agenticdisk disk <subfolder> --depth 2", "pc_disk(path=<subfolder>, depth=2)")
                    + " : drill into one branch",
                hint("agenticdisk explain <path>", "pc_explain(path)")
                    + " : classify an unknown folder before deleting",
                hint("agenticdisk plan space", "pc_plan(goal=\"space\")")
                    + " : turn this into approved, journaled actions",
            ];
            envelope("disk", vec![("disk", section)], view(Severity::Info), next, started)
        }
        Cmd::Cleanup => {
            let next =
                vec![hint("agenticdisk plan space", "pc_plan(goal=\"space\")") + " : numbered actions to approve"];
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
                        size: None,
                        path: None,
                        idle_days: None,
                        note: None,
                        undo: "not needed: regenerates".into(),
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
        Cmd::Mcp => anyhow::bail!("mcp is a server: run `agenticdisk mcp` from an MCP client"),
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
            let mut next = vec![
                hint("agenticdisk plan <goal>", "pc_plan(goal)") + " : turn findings into approved, journaled actions",
            ];
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
    if matches!(cli.command, Some(Cmd::Mcp)) {
        mcp::serve();
        return;
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
