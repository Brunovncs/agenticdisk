//! Declarative registry checks from `kb/privacy.toml` (privacy, telemetry, ads, housekeeping).

use std::time::Instant;

use agenticdisk_core::action::{Op, RegData, ps_literal};
use agenticdisk_core::{Area, Consent, Finding, Fix, Safety, Section, Severity};
use serde::{Deserialize, Serialize};

use crate::reg;

const KB: &str = include_str!("../kb/privacy.toml");

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Missing {
    Bad,
    Good,
    Unset,
}

#[derive(Deserialize)]
struct Check {
    id: String,
    area: Area,
    title: String,
    keys: Vec<String>,
    value: String,
    good: Vec<toml::Value>,
    missing: Missing,
    severity: Severity,
    #[serde(default = "safe")]
    safety: Safety,
    set: Option<u32>,
    target: Option<String>,
    #[serde(default)]
    also: Vec<(String, u32)>,
    fix: Option<String>,
    #[serde(default)]
    admin: bool,
    note: Option<String>,
}

fn safe() -> Safety {
    Safety::Safe
}

impl Check {
    /// (command, needs admin). `reg add` creates missing keys and leaves sibling values alone.
    fn fix_command(&self) -> Option<(String, bool)> {
        if let Some(cmd) = &self.fix {
            return Some((cmd.clone(), self.admin));
        }
        let set = self.set?;
        let key = self.target.as_deref().unwrap_or(&self.keys[0]);
        let cmd = std::iter::once((self.value.as_str(), set))
            .chain(self.also.iter().map(|(n, v)| (n.as_str(), *v)))
            .map(|(name, v)| format!("reg add {} /v {} /t REG_DWORD /d {v} /f", ps_literal(key), ps_literal(name)))
            .collect::<Vec<_>>()
            .join("; ");
        Some((cmd, self.admin || key.starts_with("HKLM")))
    }

    /// The journaled, undoable form of the same change (only for `set` checks).
    fn op(&self) -> Option<Op> {
        let set = self.set?;
        let key = self.target.clone().unwrap_or_else(|| self.keys[0].clone());
        let values = std::iter::once((self.value.clone(), RegData::Dword(set)))
            .chain(self.also.iter().map(|(n, v)| (n.clone(), RegData::Dword(*v))));
        Some(Op::reg(key, values))
    }
}

fn checks() -> Vec<Check> {
    toml::from_str::<CheckFile>(KB).expect("embedded privacy KB must parse").check
}

/// Every registry value agenticdisk may write: exactly the ones the knowledge base sets.
pub fn allowed(key: &str, name: &str) -> bool {
    checks().iter().filter(|c| c.set.is_some()).any(|c| {
        let target = c.target.as_deref().unwrap_or(&c.keys[0]);
        target.eq_ignore_ascii_case(key)
            && (c.value.eq_ignore_ascii_case(name) || c.also.iter().any(|(n, _)| n.eq_ignore_ascii_case(name)))
    })
}

#[derive(Deserialize)]
struct CheckFile {
    check: Vec<Check>,
}

#[derive(Serialize)]
struct State {
    id: String,
    ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
}

fn as_text(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

pub fn collect(detail: bool) -> Section {
    let started = Instant::now();
    let checks = CheckFile { check: checks() };
    let mut states = Vec::new();
    let mut findings = Vec::new();

    for check in &checks.check {
        let found = check.keys.iter().find_map(|k| reg::text(k, &check.value).map(|v| (k, v)));
        let ok = match (&found, &check.missing) {
            (Some((_, v)), _) => Some(check.good.iter().any(|g| as_text(g).eq_ignore_ascii_case(v))),
            (None, Missing::Bad) => Some(false),
            (None, Missing::Good) => Some(true),
            (None, Missing::Unset) => None,
        };
        states.push(State { id: check.id.clone(), ok, value: found.as_ref().map(|(_, v)| v.clone()) });

        if ok != Some(false) {
            continue;
        }
        let evidence = match &found {
            Some((key, v)) => format!("{key}\\{} = {v}", check.value),
            None => format!("{}\\{} not set (Windows default)", check.keys[0], check.value),
        };
        let mut finding = Finding::new(&check.id, check.area, check.severity, &check.title).evidence([evidence]);
        if let Some((cmd, admin)) = check.fix_command() {
            let mut fix = Fix::command(check.safety, cmd).consent(Consent::Setting);
            fix.admin = admin;
            fix.note = check.note.clone();
            if let Some(op) = check.op() {
                fix = fix.op(op);
            }
            finding = finding.fix(fix);
        } else if let Some(note) = &check.note {
            finding = finding.detail(note);
        }
        findings.push(finding);
    }

    let mut data = serde_json::json!({ "checked": states.len(), "failing": findings.len() });
    if detail {
        data["states"] = serde_json::to_value(&states).expect("serializes");
    }
    let mut section =
        Section { data, findings, blind_spots: Vec::new(), took_ms: started.elapsed().as_millis() as u64 };
    section.sort_findings();
    section
}

#[cfg(test)]
mod tests {
    #[test]
    fn embedded_kb_parses() {
        let file: super::CheckFile = toml::from_str(super::KB).unwrap();
        assert!(file.check.len() > 10);
        for check in &file.check {
            if let Some((cmd, _)) = check.fix_command() {
                assert!(
                    !cmd.contains("New-Item -Force"),
                    "{}: New-Item -Force wipes existing registry values",
                    check.id
                );
            }
        }
    }

    #[test]
    fn generated_fix_targets_user_key_and_extra_values() {
        let file: super::CheckFile = toml::from_str(super::KB).unwrap();
        let ad = file.check.iter().find(|c| c.id == "privacy.advertising_id").unwrap();
        let (cmd, admin) = ad.fix_command().unwrap();
        assert!(cmd.starts_with(r#"reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' /v 'Enabled' /t REG_DWORD /d 0 /f"#));
        assert!(!admin);
        let ads = file.check.iter().find(|c| c.id == "ads.silent_app_installs").unwrap();
        assert_eq!(ads.fix_command().unwrap().0.matches("reg add").count(), 3);
    }
}
