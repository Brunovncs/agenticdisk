//! Crash and stability evidence from the event log: blue screens with their stop codes,
//! unexpected shutdowns, hardware (WHEA) errors, services that hang the boot or keep crashing,
//! and whether Windows is even keeping crash dumps. Evidence first: nothing here deletes dumps.

use std::collections::BTreeMap;
use std::time::Instant;

use agenticdisk_core::action::ps_literal;
use agenticdisk_core::{Area, Finding, Fix, Safety, Section, Severity, trace};
use serde::Serialize;

use crate::events::{self, Event};
use crate::reg;

const DAYS: u64 = 90;

fn within(days: u64) -> String {
    format!("TimeCreated[timediff(@SystemTime) <= {}]", days * 86_400_000)
}

/// Common stop codes, so an agent can reason about the cause without a lookup.
fn stop_code_name(code: u32) -> &'static str {
    match code {
        0x0A => "IRQL_NOT_LESS_OR_EQUAL (driver touched invalid memory)",
        0x1A => "MEMORY_MANAGEMENT (often faulty RAM or overclock)",
        0x1E => "KMODE_EXCEPTION_NOT_HANDLED (driver)",
        0x3B => "SYSTEM_SERVICE_EXCEPTION (driver or system file)",
        0x50 => "PAGE_FAULT_IN_NONPAGED_AREA (driver, RAM or disk)",
        0x7E => "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED (driver)",
        0x7F => "UNEXPECTED_KERNEL_MODE_TRAP (hardware or overclock)",
        0x9F => "DRIVER_POWER_STATE_FAILURE (driver during sleep/wake)",
        0xA0 => "INTERNAL_POWER_ERROR",
        0xC2 | 0x19 => "BAD_POOL (driver memory corruption)",
        0xD1 => "DRIVER_IRQL_NOT_LESS_OR_EQUAL (network/storage/GPU driver)",
        0xEF => "CRITICAL_PROCESS_DIED (system file corruption or disk)",
        0xFC => "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY (driver)",
        0x101 => "CLOCK_WATCHDOG_TIMEOUT (CPU, overclock or BIOS)",
        0x116 => "VIDEO_TDR_FAILURE (GPU driver or GPU)",
        0x117 => "VIDEO_TDR_TIMEOUT_DETECTED (GPU driver or GPU)",
        0x124 => "WHEA_UNCORRECTABLE_ERROR (hardware: CPU, RAM, PCIe, overclock)",
        0x133 => "DPC_WATCHDOG_VIOLATION (a driver hung the CPU; often GPU, storage or network)",
        0x139 => "KERNEL_SECURITY_CHECK_FAILURE (driver or memory corruption)",
        0x13A => "KERNEL_MODE_HEAP_CORRUPTION (driver)",
        0x1D8 => "STORAGE_DEVICE_ABNORMALITY_DETECTED (SSD/NVMe)",
        _ => "see Microsoft's bug check reference",
    }
}

/// Days between an ISO date ("2026-09-11") and today (UTC), for "last one N days ago".
fn days_since(date: &str) -> Option<i64> {
    let mut parts = date.get(..10)?.split('-').map(|p| p.parse::<i64>().ok());
    let (y, m, d) = (parts.next()??, parts.next()??, parts.next()??);
    // Days from civil (Howard Hinnant).
    let to_days = |y: i64, m: i64, d: i64| {
        let y = if m <= 2 { y - 1 } else { y };
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
        era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy
    };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as i64 / 86_400;
    Some(now - (to_days(y, m, d) - to_days(1970, 1, 1)))
}

fn parse_code(text: &str) -> Option<u32> {
    let hex = text.split_whitespace().next()?.trim_start_matches("0x");
    u32::from_str_radix(hex, 16).ok()
}

#[derive(Serialize)]
struct Crash {
    date: String,
    code: String,
    meaning: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    dump: Option<String>,
}

fn crash_dump_settings(findings: &mut Vec<Finding>) -> serde_json::Value {
    let key = r"HKLM\SYSTEM\CurrentControlSet\Control\CrashControl";
    let enabled = reg::dword(key, "CrashDumpEnabled");
    if enabled == Some(0) {
        findings.push(
            Finding::new(
                "stability.crash_dumps_disabled",
                Area::Stability,
                Severity::Medium,
                "Windows is set to keep no crash dumps",
            )
            .detail("Without dumps, the next blue screen leaves no evidence of which driver caused it.")
            .fix(
                Fix::command(
                    Safety::Safe,
                    format!("reg add {} /v CrashDumpEnabled /t REG_DWORD /d 7 /f", ps_literal(key)),
                )
                .admin()
                .note("7 = automatic memory dump (the Windows default)."),
            ),
        );
    }
    let minidump =
        std::path::PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into())).join("Minidump");
    let minidumps = std::fs::read_dir(&minidump).ok().map(|rd| rd.flatten().count());
    serde_json::json!({
        "crash_dump_enabled": enabled,
        // None = folder unreadable without admin (not "zero dumps").
        "minidumps": minidumps,
    })
}

pub fn collect(detail: bool) -> Section {
    let started = Instant::now();
    let mut findings = Vec::new();
    let mut blind_spots = Vec::new();
    let since = within(DAYS);

    let system_query = format!(
        "*[System[(EventID=41 or EventID=6008 or EventID=1001 or EventID=7000 or EventID=7009 or EventID=7011 or EventID=7031 or EventID=7034) and {since}]]"
    );
    let system = {
        let _t = trace::span("stability: System event log");
        events::query("System", &system_query, 5000)
    };
    let events: Vec<Event> = match system {
        Ok(e) => e,
        Err(e) => {
            blind_spots.push(format!("System event log unreadable: {e}"));
            Vec::new()
        }
    };
    let whea = events::query(
        "System",
        &format!("*[System[Provider[@Name='Microsoft-Windows-WHEA-Logger'] and {since}]]"),
        2000,
    );

    let crashes: Vec<Crash> = events
        .iter()
        .filter(|e| e.id == 1001 && e.provider.contains("WER-SystemErrorReporting"))
        .map(|e| {
            let raw = e.get("param1").unwrap_or_default();
            let code = parse_code(raw);
            Crash {
                date: e.date().to_string(),
                code: code.map(|c| format!("0x{c:X}")).unwrap_or_else(|| raw.to_string()),
                meaning: code.map(stop_code_name).unwrap_or("unknown"),
                dump: e.get("param2").filter(|d| !d.is_empty()).map(str::to_string),
            }
        })
        .collect();
    if !crashes.is_empty() {
        let mut by_code: BTreeMap<&str, (usize, &'static str)> = BTreeMap::new();
        for c in &crashes {
            let slot = by_code.entry(c.code.as_str()).or_insert((0, c.meaning));
            slot.0 += 1;
        }
        let summary: Vec<String> =
            by_code.iter().map(|(code, (n, meaning))| format!("{n}x {code} {meaning}")).collect();
        let severity = if crashes.len() >= 3 { Severity::High } else { Severity::Medium };
        let dump = crashes.iter().find_map(|c| c.dump.clone());
        let analyze = match &dump {
            Some(d) => format!("cdb -z {} -c \"!analyze -v; q\"", ps_literal(d)),
            None => "cdb -z <minidump> -c \"!analyze -v; q\"".into(),
        };
        let last = crashes.first().map(|c| c.date.clone()).unwrap_or_default();
        let since = days_since(&last).map(|d| format!(", last one {d} days ago ({last})")).unwrap_or_default();
        findings.push(
            Finding::new("stability.bluescreens", Area::Stability, severity, format!("{} blue screens in the last {DAYS} days{since}", crashes.len()))
                .evidence(summary.into_iter().chain(crashes.iter().take(5).map(|c| format!("{} {} {}", c.date, c.code, c.dump.as_deref().unwrap_or("")))))
                .detail("Analyze a dump to name the faulting driver before changing anything (WinDbg / cdb from the Windows SDK, admin). Keep the dumps: they are the evidence.")
                .fix(Fix::command(Safety::Safe, analyze).admin().note("Read-only analysis. MODULE_NAME / IMAGE_NAME in the output names the driver.")),
        );
    }

    let unexpected: Vec<&Event> =
        events.iter().filter(|e| (e.id == 41 && e.provider.contains("Kernel-Power")) || e.id == 6008).collect();
    let power_losses = unexpected.iter().filter(|e| e.id == 41).count();
    if power_losses > crashes.len() {
        let silent = power_losses - crashes.len();
        findings.push(
            Finding::new("stability.unexpected_shutdowns", Area::Stability, if silent >= 3 { Severity::Medium } else { Severity::Low }, format!("{silent} unexpected shutdowns without a blue screen in the last {DAYS} days"))
                // A 41 on the day of a bug check is that crash's reboot, not a silent one.
                .evidence(
                    unexpected
                        .iter()
                        .filter(|e| e.id == 41 && !crashes.iter().any(|c| c.date == e.date()))
                        .take(8)
                        .map(|e| e.time.clone()),
                )
                .detail("Kernel-Power 41 without a bug check: power loss, holding the power button, a PSU/overheating cut, or a hang the user reset. Ask the user which; if they did not cause them, check temperatures and the power supply."),
        );
    }

    match whea {
        Ok(whea) if !whea.is_empty() => {
            let fatal = whea.iter().filter(|e| matches!(e.id, 1 | 18 | 20 | 46)).count();
            let corrected = whea.len() - fatal;
            let severity = if fatal > 0 {
                Severity::High
            } else if corrected >= 20 {
                Severity::Medium
            } else {
                Severity::Low
            };
            findings.push(
                Finding::new("stability.hardware_errors", Area::Stability, severity, format!("{} hardware errors reported by the CPU/RAM/PCIe in the last {DAYS} days ({fatal} fatal)", whea.len()))
                    .evidence(whea.iter().take(6).map(|e| format!("{} WHEA {} {}", e.date(), e.id, e.get("ErrorSource").or(e.get("ErrorType")).unwrap_or(""))))
                    .detail("WHEA errors come from the hardware itself. Typical causes: unstable overclock/XMP, failing RAM, PCIe link problems (GPU/NVMe riser), outdated BIOS. Software cleanup cannot fix these.")
                    .fix(Fix::manual("Reset overclock/XMP to defaults, update the BIOS, run mdsched.exe (memory test, needs a restart).")),
            );
        }
        Ok(_) => {}
        Err(e) => blind_spots.push(format!("WHEA events unreadable: {e}")),
    }

    // (count, newest date): events come newest first, so the first one seen is the latest.
    let mut hangs: BTreeMap<String, (usize, String)> = BTreeMap::new();
    let mut service_crashes: BTreeMap<String, (usize, String)> = BTreeMap::new();
    for e in &events {
        // 7009/7011 put the timeout (ms) in param1 and the service in param2; the others lead with the service.
        let field = if matches!(e.id, 7009 | 7011) { "param2" } else { "param1" };
        let service = e.get(field).unwrap_or("?").to_string();
        match e.id {
            7000 | 7009 | 7011 => hangs.entry(service).or_insert_with(|| (0, e.date().to_string())).0 += 1,
            7031 | 7034 => service_crashes.entry(service).or_insert_with(|| (0, e.date().to_string())).0 += 1,
            _ => {}
        }
    }
    if !hangs.is_empty() {
        let mut list: Vec<_> = hangs.iter().collect();
        list.sort_by_key(|(_, (n, _))| std::cmp::Reverse(*n));
        findings.push(
            Finding::new("stability.boot_service_failures", Area::Stability, if list[0].1.0 >= 5 { Severity::Medium } else { Severity::Low }, format!("{} services failed or timed out while starting", list.len()))
                .evidence(list.iter().take(8).map(|(s, (n, last))| format!("{n}x {s} (last {last})")))
                .detail("Each timeout can add 30-90 s to boot. Usually leftovers of uninstalled software or a driver that no longer matches the hardware.")
                .fix(Fix::manual("For each service: is the program still installed and used? If not, uninstall it; if it is, set the service to Manual (Set-Service <name> -StartupType Manual, admin).")),
        );
    }
    if !service_crashes.is_empty() {
        let mut list: Vec<_> = service_crashes.iter().collect();
        list.sort_by_key(|(_, (n, _))| std::cmp::Reverse(*n));
        findings.push(
            Finding::new(
                "stability.service_crashes",
                Area::Stability,
                Severity::Low,
                format!("{} services crashed unexpectedly", list.len()),
            )
            .evidence(list.iter().take(8).map(|(s, (n, last))| format!("{n}x {s} (last {last})"))),
        );
    }

    let dumps = crash_dump_settings(&mut findings);
    if dumps["minidumps"].is_null() {
        blind_spots.push("Minidump folder needs admin to list (dumps may exist)".into());
    }

    let mut data = serde_json::json!({
        "window_days": DAYS,
        "bluescreens": crashes.len(),
        "unclean_restarts": power_losses,
        "unclean_restarts_without_bluescreen": power_losses.saturating_sub(crashes.len()),
        "dumps": dumps,
    });
    if detail {
        data["crashes"] = serde_json::to_value(&crashes).expect("serializes");
        data["boot_service_failures"] = serde_json::to_value(&hangs).expect("serializes");
    }
    let mut section = Section { data, findings, blind_spots, took_ms: started.elapsed().as_millis() as u64 };
    section.sort_findings();
    section
}
