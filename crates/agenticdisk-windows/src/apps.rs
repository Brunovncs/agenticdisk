//! Installed software: Store packages and desktop programs, matched against `kb/apps.toml`
//! (preinstalled bloat, OEM trialware, PUPs), plus the largest installs.

use std::collections::BTreeMap;
use std::time::Instant;

use agenticdisk_core::action::ps_literal;
use agenticdisk_core::{Area, Bytes, Consent, Finding, Fix, Safety, Section, Severity};
use globset::{GlobBuilder, GlobMatcher};
use serde::{Deserialize, Serialize};

use crate::reg;

const KB: &str = include_str!("../kb/apps.toml");

/// An UninstallString is a raw command line (`\"C:\\x\\unins000.exe\" /SILENT`, `MsiExec.exe /X{...}`),
/// not PowerShell: hand it to cmd.exe verbatim, wrapped so cmd strips only the outer quotes.
fn uninstall_command(raw: &str) -> String {
    format!("Start-Process cmd.exe -ArgumentList {} -Wait", ps_literal(&format!("/c \"{raw}\"")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Bloat,
    Optional,
    Trialware,
    Pup,
}

#[derive(Deserialize)]
struct AppRule {
    name: String,
    what: String,
    category: Category,
    #[serde(default = "low")]
    severity: Severity,
}

fn low() -> Severity {
    Severity::Low
}

#[derive(Deserialize)]
struct AppKb {
    appx: Vec<AppRule>,
    win32: Vec<AppRule>,
}

struct Compiled {
    rule: AppRule,
    matcher: GlobMatcher,
}

fn compile(rules: Vec<AppRule>) -> Vec<Compiled> {
    rules
        .into_iter()
        .filter_map(|rule| {
            let matcher = GlobBuilder::new(&rule.name).case_insensitive(true).build().ok()?.compile_matcher();
            Some(Compiled { rule, matcher })
        })
        .collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct Program {
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub publisher: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<Bytes>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub installed: String,
    #[serde(skip)]
    pub uninstall: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Match {
    pub name: String,
    pub what: String,
    pub category: Category,
    #[serde(skip)]
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remove: Option<String>,
}

pub struct Installed {
    pub appx: Vec<String>,
    pub programs: Vec<Program>,
    pub matches: Vec<Match>,
}

fn appx_packages() -> Vec<String> {
    let repo =
        r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";
    let mut names: Vec<String> =
        reg::subkeys(repo).into_iter().filter_map(|full| full.split('_').next().map(str::to_string)).collect();
    names.sort();
    names.dedup();
    names
}

fn programs() -> Vec<Program> {
    let keys = [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    ];
    let mut by_name: BTreeMap<String, Program> = BTreeMap::new();
    for base in keys {
        for sub in reg::subkeys(base) {
            let Some(k) = reg::open(&format!("{base}\\{sub}")) else { continue };
            let Ok(name) = k.get_value::<String, _>("DisplayName") else { continue };
            let hidden = k.get_value::<u32, _>("SystemComponent").unwrap_or(0) == 1
                || k.get_value::<String, _>("ParentKeyName").is_ok()
                || k.get_value::<String, _>("ReleaseType").is_ok_and(|t| t.contains("Update") || t.contains("Hotfix"));
            if hidden || name.trim().is_empty() {
                continue;
            }
            let get = |v: &str| k.get_value::<String, _>(v).unwrap_or_default();
            let kb_size = k.get_value::<u32, _>("EstimatedSize").ok().filter(|s| *s > 0);
            let uninstall =
                Some(get("QuietUninstallString")).filter(|s| !s.is_empty()).unwrap_or_else(|| get("UninstallString"));
            by_name.entry(name.trim().to_string()).or_insert(Program {
                name: name.trim().to_string(),
                publisher: get("Publisher"),
                version: get("DisplayVersion"),
                size: kb_size.map(|kb| Bytes(u64::from(kb) * 1024)),
                installed: get("InstallDate"),
                uninstall,
            });
        }
    }
    by_name.into_values().collect()
}

pub fn installed() -> Installed {
    let kb: AppKb = toml::from_str(KB).expect("embedded apps KB must parse");
    let (appx_rules, win32_rules) = (compile(kb.appx), compile(kb.win32));
    let (appx, programs) = rayon::join(appx_packages, programs);

    let mut matches = Vec::new();
    for pkg in &appx {
        if let Some(c) = appx_rules.iter().find(|c| c.matcher.is_match(pkg)) {
            matches.push(Match {
                name: pkg.clone(),
                what: c.rule.what.clone(),
                category: c.rule.category,
                severity: c.rule.severity,
                remove: Some(format!("Get-AppxPackage -Name {} | Remove-AppxPackage", ps_literal(pkg))),
            });
        }
    }
    for program in &programs {
        if let Some(c) = win32_rules.iter().find(|c| c.matcher.is_match(&program.name)) {
            matches.push(Match {
                name: program.name.clone(),
                what: c.rule.what.clone(),
                category: c.rule.category,
                severity: c.rule.severity,
                remove: (!program.uninstall.is_empty()).then(|| uninstall_command(&program.uninstall)),
            });
        }
    }
    Installed { appx, programs, matches }
}

/// PUP findings belong to the security area; `security::collect` reports them.
pub fn pup_findings(installed: &Installed) -> Vec<Finding> {
    installed
        .matches
        .iter()
        .filter(|m| m.category == Category::Pup)
        .map(|m| {
            let mut f = Finding::new(format!("security.pup.{}", crate::startup::slug(&m.name)), Area::Security, m.severity, format!("Potentially unwanted program installed: {}", m.name))
                .detail(&m.what);
            if let Some(cmd) = &m.remove {
                f = f.fix(Fix::command(Safety::Caution, cmd.clone()).consent(Consent::Software).note("Uninstaller may show its own dialogs. Afterwards check browser extensions and startup entries it left behind."));
            }
            f
        })
        .collect()
}

pub fn collect(detail: bool) -> Section {
    let started = Instant::now();
    let inv = installed();
    let mut findings = Vec::new();

    let bloat: Vec<&Match> = inv
        .matches
        .iter()
        .filter(|m| {
            m.category == Category::Bloat && m.remove.as_deref().is_some_and(|r| r.starts_with("Get-AppxPackage"))
        })
        .collect();
    if !bloat.is_empty() {
        let names = bloat.iter().map(|m| ps_literal(&m.name)).collect::<Vec<_>>().join(",");
        findings.push(
            Finding::new("apps.preinstalled_bloat", Area::Apps, Severity::Low, format!("{} preinstalled apps nobody asked for", bloat.len()))
                .evidence(bloat.iter().map(|m| format!("{} ({})", m.name, m.what)))
                .fix(Fix::command(Safety::Safe, format!("{names} | ForEach-Object {{ Get-AppxPackage -Name $_ | Remove-AppxPackage }}")).consent(Consent::Software)
                    .note("Current user only; all reinstallable from the Store. To stop them coming back for new users: Get-AppxProvisionedPackage -Online | Where DisplayName -in <names> | Remove-AppxProvisionedPackage -Online (admin).")),
        );
    }
    let bloat_win32: Vec<&Match> = inv
        .matches
        .iter()
        .filter(|m| m.category == Category::Bloat && !bloat.iter().any(|b| b.name == m.name))
        .collect();
    for m in bloat_win32.into_iter().chain(inv.matches.iter().filter(|m| m.category == Category::Trialware)) {
        let mut f = Finding::new(
            format!("apps.{:?}.{}", m.category, crate::startup::slug(&m.name)).to_lowercase(),
            Area::Apps,
            Severity::Low,
            format!("{}: {}", m.name, m.what),
        );
        if let Some(cmd) = &m.remove {
            f = f.fix(
                Fix::command(Safety::Caution, cmd.clone())
                    .consent(Consent::Software)
                    .note("Confirm with the user; trial antivirus should only be removed with Defender active."),
            );
        }
        findings.push(f);
    }
    let optional: Vec<&Match> = inv.matches.iter().filter(|m| m.category == Category::Optional).collect();
    if !optional.is_empty() {
        findings.push(
            Finding::new(
                "apps.optional_preinstalled",
                Area::Apps,
                Severity::Info,
                format!("{} preinstalled apps that some people use", optional.len()),
            )
            .detail("Ask the user which ones they use before removing; each has its own action in the debloat plan.")
            .evidence(optional.iter().map(|m| format!("{} ({})", m.name, m.what))),
        );
        for m in &optional {
            let Some(cmd) = &m.remove else { continue };
            findings.push(
                Finding::new(
                    format!("apps.optional.{}", crate::startup::slug(&m.name)),
                    Area::Apps,
                    Severity::Info,
                    format!("Optional app: {} ({})", m.name, m.what),
                )
                .fix(
                    Fix::command(Safety::Manual, cmd.clone())
                        .consent(Consent::Software)
                        .note("Only if the user says they do not use it. Reinstallable from the Store."),
                ),
            );
        }
    }

    let mut largest: Vec<&Program> = inv.programs.iter().filter(|p| p.size.is_some()).collect();
    largest.sort_unstable_by_key(|x| std::cmp::Reverse(x.size));
    let mut data = serde_json::json!({
        "store_packages": inv.appx.len(),
        "programs": inv.programs.len(),
        "largest": largest.iter().take(if detail { 25 } else { 8 }).map(|p| serde_json::json!({ "name": p.name, "size": p.size })).collect::<Vec<_>>(),
    });
    if detail {
        data["matches"] = serde_json::to_value(&inv.matches).expect("serializes");
        data["all_programs"] = serde_json::to_value(&inv.programs).expect("serializes");
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
        let kb: super::AppKb = toml::from_str(super::KB).unwrap();
        assert!(!kb.appx.is_empty() && !kb.win32.is_empty());
    }
}
