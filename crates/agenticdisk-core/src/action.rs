//! The only write path in agenticdisk.
//!
//! Reading is broad; writing is narrow and auditable:
//! - agenticdisk itself only (a) empties knowledge-base cache folders and (b) writes allow-listed
//!   registry values, each journaled with the prior state and verified by re-reading;
//! - everything else (uninstalls, DISM, pnputil, admin steps when not elevated) is exported as a
//!   PowerShell script the user reads and runs, one confirmation per step;
//! - nothing runs without `--yes` (or an interactive "y"), and only the action ids the user chose.
//!   Consent classes other than cache/setting can never be selected in bulk.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::cleanup;
use crate::kb::{CleanMode, Kb};
use crate::model::{Consent, Finding, Safety};
use crate::size::Bytes;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum RegData {
    Dword(u32),
    Binary(Vec<u8>),
    String(String),
}

impl std::fmt::Display for RegData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegData::Dword(v) => write!(f, "{v} (DWORD)"),
            RegData::Binary(b) => write!(f, "{} (BINARY)", b.iter().map(|x| format!("{x:02x}")).collect::<String>()),
            RegData::String(s) => write!(f, "\"{s}\" (SZ)"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegWrite {
    pub name: String,
    pub data: RegData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Op {
    /// Empty a knowledge-base location (`clean = "contents"`), re-resolved and re-guarded at apply time.
    EmptyDir { rule: String },
    /// Set registry values under one key. Only keys/values the platform allow-lists.
    SetRegistry { key: String, values: Vec<RegWrite> },
    /// Never executed by agenticdisk: exported to a script the user reviews and runs.
    Script { script: String },
}

impl Op {
    pub fn reg(key: impl Into<String>, values: impl IntoIterator<Item = (String, RegData)>) -> Self {
        Op::SetRegistry {
            key: key.into(),
            values: values.into_iter().map(|(name, data)| RegWrite { name, data }).collect(),
        }
    }
}

/// Platform hooks for registry-style settings. Windows implements it; other OSes return errors.
pub trait Platform: Sync {
    fn elevated(&self) -> bool;
    /// Whether agenticdisk may write this value at all (knowledge-base checks, StartupApproved).
    fn reg_allowed(&self, key: &str, name: &str) -> bool;
    fn reg_read(&self, key: &str, name: &str) -> Result<Option<RegData>, String>;
    fn reg_write(&self, key: &str, name: &str, data: &RegData) -> Result<(), String>;
    fn reg_delete(&self, key: &str, name: &str) -> Result<(), String>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub id: String,
    pub finding: String,
    pub title: String,
    pub safety: Safety,
    pub consent: Consent,
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub admin: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reclaim: Option<Bytes>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub note: Option<String>,
    /// How to reverse it: "agenticdisk undo <journal>", "regenerates", or a hint.
    pub undo: String,
    pub op: Op,
}

impl Action {
    pub fn from_finding(id: String, finding: &Finding) -> Option<Self> {
        let fix = finding.fix.as_ref()?;
        let op = fix.op.clone().or_else(|| fix.command.clone().map(|script| Op::Script { script }))?;
        let undo = match &op {
            Op::EmptyDir { .. } => "not needed: regenerates on demand".to_string(),
            Op::SetRegistry { .. } => "agenticdisk undo <journal id> (prior values are journaled)".to_string(),
            Op::Script { .. } => match fix.consent {
                Consent::Software => "reinstall (Store / winget / vendor installer)".to_string(),
                Consent::Rollback | Consent::Evidence | Consent::Cache => "none: cannot be undone".to_string(),
                _ => "see note".to_string(),
            },
        };
        Some(Action {
            id,
            finding: finding.id.clone(),
            title: finding.title.clone(),
            safety: fix.safety,
            consent: fix.consent,
            admin: fix.admin,
            reclaim: finding.reclaim,
            note: fix.note.clone(),
            undo,
            op,
        })
    }

    pub fn describe(&self) -> String {
        match &self.op {
            Op::EmptyDir { rule } => format!("delete the contents of the folders of rule `{rule}`"),
            Op::SetRegistry { key, values } => format!(
                "set {}",
                values.iter().map(|v| format!("{key}\\{} = {}", v.name, v.data)).collect::<Vec<_>>().join("; ")
            ),
            Op::Script { script } => format!("script for the user to run: {script}"),
        }
    }
}

/// Where plans, journals and exported scripts live.
pub fn data_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("AGENTICDISK_HOME") {
        return PathBuf::from(home);
    }
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("XDG_DATA_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(std::env::temp_dir);
    base.join("agenticdisk")
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn write_json(dir: &str, name: &str, value: &impl Serialize) -> std::io::Result<PathBuf> {
    let dir = data_dir().join(dir);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{name}.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(value).map_err(std::io::Error::other)?)?;
    Ok(path)
}

fn read_json<T: for<'de> Deserialize<'de>>(dir: &str, name: &str) -> Result<T, String> {
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(format!("invalid id `{name}`"));
    }
    let path = data_dir().join(dir).join(format!("{name}.json"));
    let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub id: String,
    pub goal: String,
    pub created: u64,
    pub actions: Vec<Action>,
}

/// Plans expire: the machine changes, and a stale plan must not be applied blindly.
pub const PLAN_TTL_SECS: u64 = 24 * 3600;

impl Plan {
    pub fn new(goal: &str, actions: Vec<Action>) -> Self {
        let created = unix_now();
        let digest = serde_json::to_vec(&actions).unwrap_or_default();
        let hash = digest.iter().fold(0xcbf29ce484222325u64, |h, b| (h ^ u64::from(*b)).wrapping_mul(0x100000001b3));
        Plan { id: format!("{goal}-{:08x}", (hash ^ created) as u32), goal: goal.to_string(), created, actions }
    }

    pub fn save(&self) -> std::io::Result<PathBuf> {
        write_json("plans", &self.id, self)
    }

    pub fn load(id: &str) -> Result<Self, String> {
        let plan: Plan = read_json("plans", id)?;
        if unix_now().saturating_sub(plan.created) > PLAN_TTL_SECS {
            return Err(format!("plan {id} is older than 24h; run `agenticdisk plan {}` again", plan.goal));
        }
        Ok(plan)
    }

    /// Resolves `a1,a3` or the `safe` shorthand (safe + cache/setting + no admin needed).
    pub fn select(&self, selectors: &[String], elevated: bool) -> Result<Vec<&Action>, String> {
        let mut out: Vec<&Action> = Vec::new();
        for sel in selectors {
            if sel == "safe" {
                out.extend(self.actions.iter().filter(|a| {
                    a.safety == Safety::Safe
                        && a.consent.batchable()
                        && (elevated || !a.admin)
                        && !matches!(a.op, Op::Script { .. })
                }));
            } else if sel == "all" {
                return Err("`all` is not accepted: name the actions (or use `safe` for the safe batch)".into());
            } else {
                let a = self
                    .actions
                    .iter()
                    .find(|a| &a.id == sel)
                    .ok_or_else(|| format!("no action `{sel}` in plan {}", self.id))?;
                out.push(a);
            }
        }
        out.sort_by_key(|a| &a.id);
        out.dedup_by_key(|a| &a.id);
        Ok(out)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegChange {
    pub key: String,
    pub name: String,
    /// None = the value did not exist (undo deletes it).
    pub before: Option<RegData>,
    pub after: RegData,
    /// Re-read after writing matched. False = something reverted or blocked it (policy, UCPD, MDM).
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outcome {
    pub action: String,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub freed: Option<Bytes>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub registry: Vec<RegChange>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Done,
    Partial,
    Failed,
    /// Written to the exported script instead of executed.
    Scripted,
    Refused,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Journal {
    pub id: String,
    pub plan: String,
    pub created: u64,
    pub outcomes: Vec<Outcome>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub script: Option<PathBuf>,
}

impl Journal {
    pub fn load(id: &str) -> Result<Self, String> {
        read_json("journal", id)
    }

    pub fn list() -> Vec<serde_json::Value> {
        let dir = data_dir().join("journal");
        let mut entries: Vec<(u64, serde_json::Value)> = std::fs::read_dir(dir)
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| serde_json::from_slice::<Journal>(&std::fs::read(e.path()).ok()?).ok())
                    .map(|j| {
                        let summary = serde_json::json!({
                            "id": j.id,
                            "plan": j.plan,
                            "created": j.created,
                            "actions": j.outcomes.iter().map(|o| format!("{} {:?}", o.action, o.status)).collect::<Vec<_>>(),
                            "undoable": j.outcomes.iter().any(|o| !o.registry.is_empty()),
                        });
                        (j.created, summary)
                    })
                    .collect()
            })
            .unwrap_or_default();
        entries.sort_by_key(|e| std::cmp::Reverse(e.0));
        entries.into_iter().map(|e| e.1).collect()
    }
}

/// Text the agent must show the user verbatim before passing `--yes`.
pub fn confirmation_text(actions: &[&Action]) -> String {
    let mut lines = vec!["agenticdisk will make these changes:".to_string()];
    for a in actions {
        let mut line = format!("  [{}] {} -> {}", a.id, a.title, a.describe());
        if a.consent != Consent::Cache || a.safety != Safety::Safe {
            line.push_str(&format!(" ({:?}, {:?}; undo: {})", a.consent, a.safety, a.undo).to_lowercase());
        }
        lines.push(line);
    }
    lines.push("Nothing else is touched. Your documents and personal files are never deleted by agenticdisk.".into());
    lines.join("\n")
}

pub struct Applier<'a> {
    pub kb: &'a Kb,
    pub platform: &'a dyn Platform,
}

/// One pending script step, exported for the user to run.
struct ScriptStep<'a> {
    action: &'a Action,
    reason: &'static str,
}

impl Applier<'_> {
    /// Exact preview of what `run` would do, with current values and sizes.
    pub fn preview(&self, actions: &[&Action]) -> Vec<serde_json::Value> {
        actions
            .iter()
            .map(|a| {
                let detail = match &a.op {
                    Op::EmptyDir { rule } => {
                        let report = cleanup::clean(self.kb, std::slice::from_ref(rule), false);
                        serde_json::to_value(report).unwrap_or_default()
                    }
                    Op::SetRegistry { key, values } => serde_json::Value::Array(
                        values
                            .iter()
                            .map(|v| {
                                let before = self.platform.reg_read(key, &v.name).ok().flatten();
                                serde_json::json!({
                                    "value": format!("{key}\\{}", v.name),
                                    "before": before.map(|b| b.to_string()).unwrap_or_else(|| "(not set)".into()),
                                    "after": v.data.to_string(),
                                    "allowed": self.platform.reg_allowed(key, &v.name),
                                })
                            })
                            .collect(),
                    ),
                    Op::Script { script } => serde_json::json!({ "exported_to_script": script }),
                };
                let runs_where = if matches!(a.op, Op::Script { .. }) || (a.admin && !self.platform.elevated()) {
                    "script (user runs it)"
                } else {
                    "agenticdisk"
                };
                serde_json::json!({ "id": a.id, "title": a.title, "consent": a.consent, "safety": a.safety, "runs": runs_where, "detail": detail })
            })
            .collect()
    }

    pub fn run(&self, plan: &Plan, actions: &[&Action]) -> Journal {
        let elevated = self.platform.elevated();
        let mut outcomes = Vec::new();
        let mut script_steps: Vec<ScriptStep> = Vec::new();
        for a in actions {
            if a.consent == Consent::UserData {
                outcomes.push(refused(a, "user data is never deleted by agenticdisk; the user must do it"));
                continue;
            }
            if matches!(a.op, Op::Script { .. }) {
                script_steps.push(ScriptStep { action: a, reason: "external command" });
                outcomes.push(Outcome {
                    action: a.id.clone(),
                    status: Status::Scripted,
                    freed: None,
                    registry: vec![],
                    message: None,
                });
                continue;
            }
            if a.admin && !elevated {
                script_steps.push(ScriptStep { action: a, reason: "needs an elevated (admin) shell" });
                outcomes.push(Outcome {
                    action: a.id.clone(),
                    status: Status::Scripted,
                    freed: None,
                    registry: vec![],
                    message: Some("needs admin: exported to the script".into()),
                });
                continue;
            }
            outcomes.push(match &a.op {
                Op::EmptyDir { rule } => self.empty(a, rule),
                Op::SetRegistry { key, values } => self.set_registry(a, key, values),
                Op::Script { .. } => unreachable!("handled above"),
            });
        }
        let created = unix_now();
        let id = format!("{}-{created}", plan.id);
        let script = (!script_steps.is_empty()).then(|| export_script(&id, &script_steps)).and_then(Result::ok);
        let journal = Journal { id, plan: plan.id.clone(), created, outcomes, script };
        let _ = write_json("journal", &journal.id, &journal);
        journal
    }

    fn empty(&self, a: &Action, rule_id: &str) -> Outcome {
        let Some(rule) = self.kb.get(rule_id) else { return refused(a, "unknown rule") };
        if rule.clean != CleanMode::Contents || !matches!(rule.safety, Safety::Safe | Safety::Caution) {
            return refused(a, "rule is not auto-cleanable");
        }
        if let Some(p) = Kb::resolve(rule).into_iter().find(|p| cleanup::protected(p)) {
            return refused(a, &format!("{} is a protected location", p.display()));
        }
        let report = cleanup::clean(self.kb, &[rule_id.to_string()], true);
        let skipped: Vec<String> = report.items.iter().filter_map(|i| i.skipped.clone()).collect();
        Outcome {
            action: a.id.clone(),
            status: if skipped.is_empty() { Status::Done } else { Status::Partial },
            freed: Some(report.freed),
            registry: vec![],
            message: (!skipped.is_empty()).then(|| skipped.join("; ")),
        }
    }

    fn set_registry(&self, a: &Action, key: &str, values: &[RegWrite]) -> Outcome {
        if let Some(v) = values.iter().find(|v| !self.platform.reg_allowed(key, &v.name)) {
            return refused(a, &format!("{key}\\{} is not on the allow-list", v.name));
        }
        let mut changes = Vec::new();
        let mut errors = Vec::new();
        for v in values {
            let before = match self.platform.reg_read(key, &v.name) {
                Ok(b) => b,
                Err(e) => {
                    errors.push(e);
                    continue;
                }
            };
            if let Err(e) = self.platform.reg_write(key, &v.name, &v.data) {
                errors.push(e);
                continue;
            }
            let after = self.platform.reg_read(key, &v.name).ok().flatten();
            changes.push(RegChange {
                key: key.to_string(),
                name: v.name.clone(),
                before,
                verified: after.as_ref() == Some(&v.data),
                after: v.data.clone(),
            });
        }
        let unverified = changes.iter().filter(|c| !c.verified).count();
        let status = match (errors.is_empty(), changes.is_empty(), unverified) {
            (true, false, 0) => Status::Done,
            (_, true, _) => Status::Failed,
            _ => Status::Partial,
        };
        let mut message: Vec<String> = errors;
        if unverified > 0 {
            message.push(format!("{unverified} value(s) did not stick after writing (blocked by policy/MDM/UCPD?)"));
        }
        if key.contains("\\Policies\\") {
            message.push("policy key: Settings may show \"Some settings are managed by your organization\"".into());
        }
        Outcome {
            action: a.id.clone(),
            status,
            freed: None,
            registry: changes,
            message: (!message.is_empty()).then(|| message.join("; ")),
        }
    }

    /// Restores every journaled registry value, newest first.
    pub fn undo(&self, journal: &Journal) -> Vec<serde_json::Value> {
        let mut results = Vec::new();
        for outcome in journal.outcomes.iter().rev() {
            for c in outcome.registry.iter().rev() {
                let result = match &c.before {
                    Some(before) => self.platform.reg_write(&c.key, &c.name, before),
                    None => self.platform.reg_delete(&c.key, &c.name),
                };
                results.push(serde_json::json!({
                    "action": outcome.action,
                    "value": format!("{}\\{}", c.key, c.name),
                    "restored": c.before.as_ref().map(|b| b.to_string()).unwrap_or_else(|| "(deleted: was not set)".into()),
                    "ok": result.is_ok(),
                    "error": result.err(),
                }));
            }
        }
        results
    }
}

fn refused(a: &Action, why: &str) -> Outcome {
    Outcome {
        action: a.id.clone(),
        status: Status::Refused,
        freed: None,
        registry: vec![],
        message: Some(why.to_string()),
    }
}

/// A PowerShell single-quoted literal. PowerShell also treats U+2018..U+201B as single quotes,
/// so every one of them is doubled: no file, registry or package name can break out and run code.
pub fn ps_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if matches!(ch, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
            out.push(ch);
        }
        out.push(ch);
    }
    out.push('\'');
    out
}

/// A reviewable script: backups first, one confirmation per step, never a single "yes to all".
fn export_script(journal_id: &str, steps: &[ScriptStep]) -> std::io::Result<PathBuf> {
    let needs_admin = steps.iter().any(|s| s.action.admin);
    let mut out = String::new();
    out.push_str("# Generated by agenticdisk. Review every step before running.\n");
    out.push_str("# Each step asks for confirmation. Nothing here deletes documents or personal files.\n");
    out.push_str("# Provided AS IS, without warranty (MIT License). You run it at your own risk.\n");
    if needs_admin {
        out.push_str("#Requires -RunAsAdministrator\n");
    }
    out.push_str("$ErrorActionPreference = 'Continue'\n");
    out.push_str(&format!("$backup = Join-Path $env:LOCALAPPDATA 'agenticdisk\\backups\\{journal_id}'\n"));
    out.push_str("New-Item -ItemType Directory -Path $backup -ErrorAction SilentlyContinue | Out-Null\n");
    out.push_str("function Confirm-Step($text) { (Read-Host \"$text [y/N]\") -match '^(y|s|yes|sim)$' }\n\n");
    for step in steps {
        let a = step.action;
        out.push_str(&format!(
            "# [{}] {} ({}; consent: {:?}; safety: {:?})\n",
            a.id, a.title, step.reason, a.consent, a.safety
        ));
        if let Some(note) = &a.note {
            out.push_str(&format!("# Note: {note}\n"));
        }
        out.push_str(&format!("# Undo: {}\n", a.undo));
        let body = match &a.op {
            Op::Script { script } => script.clone(),
            Op::SetRegistry { key, values } => {
                let file = format!("{}.reg", a.id);
                let mut lines = vec![format!(
                    "reg export {} (Join-Path $backup {}) /y | Out-Null",
                    ps_literal(key),
                    ps_literal(&file)
                )];
                for v in values {
                    let (kind, data) = match &v.data {
                        RegData::Dword(d) => ("REG_DWORD", d.to_string()),
                        RegData::Binary(b) => ("REG_BINARY", b.iter().map(|x| format!("{x:02x}")).collect()),
                        RegData::String(s) => ("REG_SZ", s.clone()),
                    };
                    lines.push(format!(
                        "reg add {} /v {} /t {kind} /d {} /f",
                        ps_literal(key),
                        ps_literal(&v.name),
                        ps_literal(&data)
                    ));
                }
                lines.join("\n    ")
            }
            Op::EmptyDir { rule } => format!("agenticdisk clean {rule} --apply"),
        };
        out.push_str(&format!(
            "if (Confirm-Step {}) {{\n    {body}\n}}\n\n",
            ps_literal(&format!("[{}] {}", a.id, a.title))
        ));
    }
    let dir = data_dir().join("scripts");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{journal_id}.ps1"));
    // UTF-8 with BOM so Windows PowerShell 5.1 reads non-ASCII paths correctly.
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(out.as_bytes());
    std::fs::write(&path, bytes)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ps_literal_cannot_be_broken_out_of() {
        assert_eq!(ps_literal("a'b"), "'a''b'");
        assert_eq!(ps_literal("x\u{2019};iex"), "'x\u{2019}\u{2019};iex'");
    }

    fn action(id: &str, safety: Safety, consent: Consent, op: Op) -> Action {
        Action {
            id: id.into(),
            finding: "f".into(),
            title: "t".into(),
            safety,
            consent,
            admin: false,
            reclaim: None,
            note: None,
            undo: String::new(),
            op,
        }
    }

    #[derive(Default)]
    struct Fake {
        values: std::sync::Mutex<std::collections::HashMap<(String, String), RegData>>,
        /// Values that silently refuse to change (like a UCPD-protected key).
        sticky: Vec<String>,
    }

    impl Platform for Fake {
        fn elevated(&self) -> bool {
            false
        }
        fn reg_allowed(&self, key: &str, _: &str) -> bool {
            key.starts_with("HKCU\\Allowed")
        }
        fn reg_read(&self, key: &str, name: &str) -> Result<Option<RegData>, String> {
            Ok(self.values.lock().unwrap().get(&(key.into(), name.into())).cloned())
        }
        fn reg_write(&self, key: &str, name: &str, data: &RegData) -> Result<(), String> {
            if !self.sticky.iter().any(|s| s == name) {
                self.values.lock().unwrap().insert((key.into(), name.into()), data.clone());
            }
            Ok(())
        }
        fn reg_delete(&self, key: &str, name: &str) -> Result<(), String> {
            self.values.lock().unwrap().remove(&(key.into(), name.into()));
            Ok(())
        }
    }

    #[test]
    fn apply_journals_verifies_refuses_and_undoes() {
        // SAFETY: only this test reads AGENTICDISK_HOME; it points journals at a scratch folder.
        let home = std::env::temp_dir().join(format!("agenticdisk-journal-test-{}", std::process::id()));
        unsafe { std::env::set_var("AGENTICDISK_HOME", &home) };
        let fake = Fake { sticky: vec!["Blocked".into()], ..Default::default() };
        fake.values.lock().unwrap().insert(("HKCU\\Allowed".into(), "Existing".into()), RegData::Dword(1));
        let kb = Kb::load();
        let plan = Plan::new(
            "privacy",
            vec![
                action(
                    "a1",
                    Safety::Safe,
                    Consent::Setting,
                    Op::reg(
                        "HKCU\\Allowed",
                        [("Existing".to_string(), RegData::Dword(0)), ("New".to_string(), RegData::Dword(0))],
                    ),
                ),
                action(
                    "a2",
                    Safety::Safe,
                    Consent::Setting,
                    Op::reg("HKCU\\Allowed", [("Blocked".to_string(), RegData::Dword(0))]),
                ),
                action(
                    "a3",
                    Safety::Safe,
                    Consent::Setting,
                    Op::reg("HKLM\\Elsewhere", [("X".to_string(), RegData::Dword(0))]),
                ),
                action("a4", Safety::Safe, Consent::UserData, Op::EmptyDir { rule: "win.downloads".into() }),
                action("a5", Safety::Safe, Consent::Software, Op::Script { script: "Remove-Thing".into() }),
            ],
        );
        let applier = Applier { kb: &kb, platform: &fake };
        let chosen: Vec<&Action> = plan.actions.iter().collect();
        let journal = applier.run(&plan, &chosen);
        let status: Vec<Status> = journal.outcomes.iter().map(|o| o.status).collect();
        assert_eq!(status, [Status::Done, Status::Partial, Status::Refused, Status::Refused, Status::Scripted]);
        assert!(journal.outcomes[1].message.as_deref().unwrap().contains("did not stick"));
        assert!(journal.script.as_ref().is_some_and(|s| s.exists()));
        assert_eq!(fake.reg_read("HKCU\\Allowed", "Existing").unwrap(), Some(RegData::Dword(0)));

        let restored = applier.undo(&Journal::load(&journal.id).unwrap());
        assert!(restored.iter().all(|r| r["ok"] == true));
        assert_eq!(
            fake.reg_read("HKCU\\Allowed", "Existing").unwrap(),
            Some(RegData::Dword(1)),
            "prior value restored"
        );
        assert_eq!(fake.reg_read("HKCU\\Allowed", "New").unwrap(), None, "value that did not exist is removed again");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn safe_batch_never_includes_software_rollback_or_scripts() {
        let plan = Plan::new(
            "space",
            vec![
                action("a1", Safety::Safe, Consent::Cache, Op::EmptyDir { rule: "win.temp_user".into() }),
                action("a2", Safety::Safe, Consent::Software, Op::Script { script: "x".into() }),
                action("a3", Safety::Caution, Consent::Cache, Op::EmptyDir { rule: "x".into() }),
                action("a4", Safety::Safe, Consent::Rollback, Op::EmptyDir { rule: "y".into() }),
            ],
        );
        let ids: Vec<_> = plan.select(&["safe".into()], true).unwrap().iter().map(|a| a.id.clone()).collect();
        assert_eq!(ids, ["a1"]);
        assert!(plan.select(&["all".into()], true).is_err());
        assert_eq!(plan.select(&["a2".into(), "a1".into(), "a2".into()], true).unwrap().len(), 2);
    }
}
