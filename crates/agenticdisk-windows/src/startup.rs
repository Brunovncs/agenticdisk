//! Everything that runs automatically: Run keys, Startup folders, auto-start services and
//! scheduled tasks. Built once per process and shared with the security collector.

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Instant;

use agenticdisk_core::action::{Op, RegData, ps_literal};
use agenticdisk_core::{Area, Consent, Finding, Fix, Safety, Section, Severity, trace};
use rayon::prelude::*;
use serde::Serialize;

use crate::sign::{self, Signature};
use crate::{reg, suspicious, tasks};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Run,
    RunOnce,
    StartupFolder,
    Service,
    Task,
}

#[derive(Debug, Clone, Serialize)]
pub struct AutoStart {
    pub kind: Kind,
    pub name: String,
    pub command: String,
    pub location: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<&'static str>,
    #[serde(skip)]
    pub image: Option<PathBuf>,
    /// Its executable lives in the Windows folder (decided by location, never by name).
    #[serde(skip)]
    pub builtin: bool,
    /// Where Task Manager's enabled/disabled state for this entry lives: (hive, list).
    #[serde(skip)]
    pub approval: Option<(&'static str, &'static str)>,
}

pub struct Inventory {
    pub items: Vec<AutoStart>,
    pub blind_spots: Vec<String>,
}

/// (key, kind, StartupApproved list). RunOnce entries have no enable/disable state.
const RUN_KEYS: [(&str, Kind, &str); 5] = [
    (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", Kind::Run, "Run"),
    (r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", Kind::RunOnce, ""),
    (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Kind::Run, "Run"),
    (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Kind::RunOnce, ""),
    (r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", Kind::Run, "Run32"),
];

pub const APPROVED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";

/// Task Manager's "Disabled": first byte of the StartupApproved value is odd.
fn approved(hive: &str, list: &str, name: &str) -> bool {
    reg::open(&format!("{hive}\\{APPROVED}\\{list}"))
        .and_then(|k| k.get_raw_value(name).ok())
        .and_then(|v| v.bytes.first().copied())
        .is_none_or(|b| b & 1 == 0)
}

fn entry(kind: Kind, name: String, command: String, location: String) -> AutoStart {
    AutoStart {
        kind,
        image: suspicious::image_of(&command),
        name,
        command,
        location,
        enabled: true,
        signature: None,
        flags: Vec::new(),
        builtin: false,
        approval: None,
    }
}

fn run_entries(out: &mut Vec<AutoStart>) {
    for (key, kind, list) in RUN_KEYS {
        let hive: &'static str = if key.starts_with("HKLM") { "HKLM" } else { "HKCU" };
        for (name, command) in reg::values(key) {
            let mut item = entry(kind, name, command, key.to_string());
            if !list.is_empty() {
                item.enabled = approved(hive, list, &item.name);
                item.approval = Some((hive, list));
            }
            out.push(item);
        }
    }
}

fn startup_folders(out: &mut Vec<AutoStart>) {
    let folders = [
        (r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup", "HKCU"),
        (r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp", "HKLM"),
    ];
    for (folder, hive) in folders {
        let Some(dir) = agenticdisk_core::kb::expand_env(folder) else { continue };
        let Ok(read) = std::fs::read_dir(&dir) else { continue };
        for e in read.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            let path = e.path();
            let is_link = name.to_ascii_lowercase().ends_with(".lnk");
            let mut item = entry(Kind::StartupFolder, name, path.display().to_string(), dir.clone());
            // Shortcut targets need IShellLink; the .lnk itself is not an executable to verify.
            item.image = (!is_link).then_some(path);
            item.enabled = approved(hive, "StartupFolder", &item.name);
            item.approval = Some((hive, "StartupFolder"));
            out.push(item);
        }
    }
}

fn services(out: &mut Vec<AutoStart>) {
    let base = r"HKLM\SYSTEM\CurrentControlSet\Services";
    for name in reg::subkeys(base) {
        let key = format!("{base}\\{name}");
        let Some(k) = reg::open(&key) else { continue };
        let kind: u32 = k.get_value("Type").unwrap_or(0);
        let start: u32 = k.get_value("Start").unwrap_or(4);
        // Win32 services (own/shared process) that start automatically.
        if kind & 0x30 == 0 || start != 2 {
            continue;
        }
        let Ok(image_path) = k.get_value::<String, _>("ImagePath") else { continue };
        let display = k.get_value("DisplayName").ok().filter(|d: &String| !d.starts_with('@')).unwrap_or(name.clone());
        let mut item = entry(Kind::Service, display, image_path, key.clone());
        // svchost services run a DLL: that DLL, not svchost.exe, is what to judge.
        if item.image.as_ref().is_some_and(|i| i.file_name().is_some_and(|f| f.eq_ignore_ascii_case("svchost.exe"))) {
            let dll =
                reg::string(&format!("{key}\\Parameters"), "ServiceDll").or_else(|| reg::string(&key, "ServiceDll"));
            if let Some(dll) = dll {
                item.command = format!("{} [ServiceDll: {dll}]", item.command);
                item.image = suspicious::image_of(&format!("\"{dll}\""));
            }
        }
        out.push(item);
    }
}

fn scheduled(out: &mut Vec<AutoStart>, blind_spots: &mut Vec<String>) {
    let list = match tasks::list() {
        Ok(list) => list,
        Err(e) => {
            blind_spots.push(format!("scheduled tasks unavailable: {e}"));
            return;
        }
    };
    let unreadable = list.iter().filter(|t| t.unreadable).count();
    if unreadable > 0 {
        blind_spots.push(format!(
            "{unreadable} scheduled tasks could not be read without admin (their actions are unknown, not absent)"
        ));
    }
    for task in list {
        for (exe, args) in &task.actions {
            let command = if args.is_empty() { exe.clone() } else { format!("{exe} {args}") };
            let location = if task.author.is_empty() {
                "Task Scheduler".into()
            } else {
                format!("Task Scheduler (author: {})", task.author)
            };
            let mut item = entry(Kind::Task, task.path.clone(), command, location);
            // A task's executable path never takes arguments: do not split it at spaces.
            item.image = suspicious::image_of(&format!("\"{}\"", exe.trim_matches('"')));
            item.enabled = task.enabled;
            out.push(item);
        }
    }
}

fn build() -> Inventory {
    let mut items = Vec::new();
    let mut blind_spots = Vec::new();
    let mut tasks = Vec::new();
    let mut task_blind = Vec::new();
    // Task Scheduler COM is the slow part; run it beside the registry/file readers.
    std::thread::scope(|s| {
        s.spawn(|| {
            let _t = trace::span("startup: scheduled tasks (COM)");
            scheduled(&mut tasks, &mut task_blind)
        });
        let _t = trace::span("startup: run keys, folders, services");
        run_entries(&mut items);
        startup_folders(&mut items);
        services(&mut items);
    });
    items.extend(tasks);
    blind_spots.extend(task_blind);

    let _t = trace::span(format!("startup: signatures for {} items", items.len()));
    items.par_iter_mut().for_each(|item| {
        let mut flags = suspicious::command_flags(&item.command);
        if let Some(image) = &item.image {
            item.builtin = suspicious::windows_dir(image);
            let signature = if item.builtin {
                if image.exists() { Signature::System } else { Signature::Missing }
            } else {
                // Full hash verification only where it can change the verdict.
                let deep = !flags.is_empty() || suspicious::user_writable(image);
                sign::assess(image, deep)
            };
            item.signature = Some(signature);
            flags.extend(suspicious::path_flags(image, Some(signature)));
        }
        item.flags = flags;
    });
    Inventory { items, blind_spots }
}

pub fn inventory() -> &'static Inventory {
    static INVENTORY: OnceLock<Inventory> = OnceLock::new();
    INVENTORY.get_or_init(build)
}

/// Same as Task Manager > Disable: reversible, nothing is deleted.
fn disable_op(item: &AutoStart) -> Option<(Op, bool)> {
    let (hive, list) = item.approval?;
    let key = format!("{hive}\\{APPROVED}\\{list}");
    let mut data = vec![0u8; 12];
    data[0] = 3;
    Some((Op::reg(key, [(item.name.clone(), RegData::Binary(data))]), hive == "HKLM"))
}

fn disable_fix(item: &AutoStart, safety: Safety, note: &str) -> Option<Fix> {
    let (op, admin) = disable_op(item)?;
    let (hive, list) = item.approval?;
    let command = format!(
        "reg add {} /v {} /t REG_BINARY /d 030000000000000000000000 /f",
        ps_literal(&format!("{hive}\\{APPROVED}\\{list}")),
        ps_literal(&item.name)
    );
    let mut fix = Fix::command(safety, command).consent(Consent::Setting).op(op).note(note);
    fix.admin = admin;
    Some(fix)
}

pub fn collect(detail: bool) -> Section {
    let started = Instant::now();
    let inv = inventory();
    let mut findings = Vec::new();

    let login: Vec<&AutoStart> =
        inv.items.iter().filter(|i| i.enabled && matches!(i.kind, Kind::Run | Kind::StartupFolder)).collect();
    if !login.is_empty() {
        let severity = if login.len() >= 10 { Severity::Low } else { Severity::Info };
        findings.push(
            Finding::new("startup.login_apps", Area::Startup, severity, format!("{} apps launch at sign-in", login.len()))
                .detail("Each one slows sign-in and keeps running in the background. Ask the user which they need right after boot; disabling is reversible (same as Task Manager).")
                .evidence(login.iter().map(|i| format!("{} = {}", i.name, i.command))),
        );
    }
    // One action per app, so a plan can disable exactly the ones the user picks.
    for item in &login {
        if let Some(fix) = disable_fix(
            item,
            Safety::Manual,
            "Reversible: agenticdisk undo, or re-enable in Task Manager > Startup apps.",
        ) {
            findings.push(
                Finding::new(
                    format!("startup.app.{}", slug(&item.name)),
                    Area::Startup,
                    Severity::Info,
                    format!("Launches at sign-in: {}", item.name),
                )
                .evidence([item.command.clone()])
                .fix(fix),
            );
        }
    }

    for item in inv.items.iter().filter(|i| i.flags.contains(&"missing_target") && !i.builtin && i.enabled) {
        let mut finding = Finding::new(
            format!("startup.broken.{}", slug(&item.name)),
            Area::Startup,
            Severity::Low,
            format!("Autostart points to a file that no longer exists: {}", item.name),
        )
        .evidence([format!("{} -> {}", item.location, item.command)]);
        if let Some(fix) = disable_fix(
            item,
            Safety::Caution,
            "Leftover from an uninstalled program. Disabled, not deleted: reversible with agenticdisk undo.",
        ) {
            finding = finding.fix(fix);
        }
        findings.push(finding);
    }

    let third_party_services = inv.items.iter().filter(|i| i.kind == Kind::Service && !i.builtin).count();
    let third_party_tasks = inv.items.iter().filter(|i| i.kind == Kind::Task && !i.builtin && i.enabled).count();
    let mut data = serde_json::json!({
        "login_apps": login.len(),
        "third_party_services": third_party_services,
        "third_party_tasks": third_party_tasks,
    });
    if detail {
        let mut items: Vec<&AutoStart> = inv.items.iter().filter(|i| !i.builtin || !i.flags.is_empty()).collect();
        items.sort_by_key(|i| (i.kind as u8, i.name.to_lowercase()));
        data["items"] = serde_json::to_value(items).expect("autostart serializes");
    }

    let mut section =
        Section { data, findings, blind_spots: inv.blind_spots.clone(), took_ms: started.elapsed().as_millis() as u64 };
    section.sort_findings();
    section
}

pub fn slug(s: &str) -> String {
    let mut out: String =
        s.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' }).collect();
    out.truncate(48);
    out.trim_matches('_').to_string()
}
