//! Fast triage for malware and weakened defenses. Not an antivirus: it reads Defender's verdicts and
//! looks for the persistence and tampering traces malware leaves, then points at a real scan.

use std::time::Instant;

use agenticdisk_core::action::ps_literal;
use agenticdisk_core::{Area, Finding, Fix, Safety, Section, Severity, trace};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

use crate::sign::{self, Signature};
use crate::startup::{self, slug};
use crate::{apps, reg, suspicious};

#[derive(Deserialize)]
#[serde(rename = "MSFT_MpComputerStatus", rename_all = "PascalCase")]
struct MpStatus {
    antivirus_enabled: Option<bool>,
    real_time_protection_enabled: Option<bool>,
    antivirus_signature_age: Option<u32>,
    quick_scan_age: Option<u32>,
    is_tamper_protected: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename = "MSFT_MpThreat", rename_all = "PascalCase")]
struct MpThreat {
    threat_name: Option<String>,
    is_active: Option<bool>,
    did_threat_execute: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename = "AntiVirusProduct")]
struct AvProduct {
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    /// Bit 0x1000 = real-time protection on; 0x10 in the low byte = definitions out of date.
    #[serde(rename = "productState")]
    product_state: Option<u32>,
}

const QUICK_SCAN: &str = "Start-MpScan -ScanType QuickScan";

fn defender(findings: &mut Vec<Finding>, blind_spots: &mut Vec<String>) -> serde_json::Value {
    let others: Vec<String> = wmi::WMIConnection::with_namespace_path("ROOT\\SecurityCenter2")
        .and_then(|c| c.query::<AvProduct>())
        // Only products that are actually on count: an expired trial must not silence the alarm.
        .map(|list| {
            list.into_iter()
                .filter(|p| p.product_state.is_some_and(|s| s & 0x1000 != 0))
                .filter_map(|p| p.display_name)
                .filter(|n| !n.contains("Defender"))
                .collect()
        })
        .unwrap_or_default();

    let status = wmi::WMIConnection::with_namespace_path("ROOT\\Microsoft\\Windows\\Defender")
        .and_then(|c| c.query::<MpStatus>());
    let Some(s) = status.ok().and_then(|v| v.into_iter().next()) else {
        if others.is_empty() {
            findings.push(Finding::new(
                "security.no_antivirus",
                Area::Security,
                Severity::Critical,
                "No working antivirus detected (Defender status unavailable, no other product registered)",
            ));
        }
        blind_spots.push("Defender status unavailable".into());
        return serde_json::json!({ "defender": null, "other_antivirus": others });
    };

    let av_on = s.antivirus_enabled.unwrap_or(false);
    let rtp_on = s.real_time_protection_enabled.unwrap_or(false);
    if !av_on || !rtp_on {
        if others.is_empty() {
            findings.push(
                Finding::new("security.defender_disabled", Area::Security, Severity::Critical, "Microsoft Defender real-time protection is off and no other antivirus is active")
                    .detail("Malware commonly disables Defender. If the user did not turn it off, treat the PC as possibly compromised.")
                    .fix(Fix::command(Safety::Safe, "Set-MpPreference -DisableRealtimeMonitoring $false").admin()),
            );
        } else {
            findings.push(Finding::new(
                "security.third_party_av",
                Area::Security,
                Severity::Info,
                format!("Protection provided by: {}", others.join(", ")),
            ));
        }
    }
    if av_on && s.antivirus_signature_age.unwrap_or(0) > 7 {
        findings.push(
            Finding::new(
                "security.defender_signatures_old",
                Area::Security,
                Severity::Medium,
                format!("Defender signatures are {} days old", s.antivirus_signature_age.unwrap_or(0)),
            )
            .detail(
                "Updates normally arrive daily; a stale age can mean Windows Update or Defender updates are blocked.",
            )
            .fix(Fix::command(Safety::Safe, "Update-MpSignature")),
        );
    }
    if av_on && s.is_tamper_protected == Some(false) {
        findings.push(
            Finding::new(
                "security.tamper_protection_off",
                Area::Security,
                Severity::Medium,
                "Defender Tamper Protection is off",
            )
            .detail("Without it, any admin process (including malware) can silently disable Defender.")
            .fix(Fix::manual(
                "Windows Security > Virus & threat protection > Manage settings > Tamper Protection: On.",
            )),
        );
    }
    let scan_age = s.quick_scan_age.unwrap_or(u32::MAX);
    if av_on && scan_age > 14 {
        findings.push(
            Finding::new(
                "security.no_recent_scan",
                Area::Security,
                Severity::Low,
                if scan_age == u32::MAX {
                    "Defender has never run a scan".to_string()
                } else {
                    format!("Last Defender scan was {scan_age} days ago")
                },
            )
            .fix(Fix::command(Safety::Safe, QUICK_SCAN)),
        );
    }

    match wmi::WMIConnection::with_namespace_path("ROOT\\Microsoft\\Windows\\Defender")
        .and_then(|c| c.query::<MpThreat>())
    {
        Ok(threats) => {
            for t in threats.iter().filter(|t| t.is_active == Some(true)) {
                let name = t.threat_name.clone().unwrap_or_else(|| "unknown".into());
                findings.push(
                    Finding::new(
                        format!("security.active_threat.{}", slug(&name)),
                        Area::Security,
                        Severity::Critical,
                        format!("Defender reports an active threat: {name}"),
                    )
                    .detail(if t.did_threat_execute == Some(true) {
                        "The threat executed on this PC."
                    } else {
                        "Detected; not reported as executed."
                    })
                    .fix(Fix::command(Safety::Safe, "Start-MpScan -ScanType FullScan; Remove-MpThreat").admin()),
                );
            }
        }
        Err(_) => blind_spots.push("Defender threat history needs admin".into()),
    }

    if reg::readable(r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths") == Some(true) {
        let exclusions: Vec<String> = ["Paths", "Processes", "Extensions"]
            .iter()
            .flat_map(|k| {
                reg::values(&format!(r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\{k}"))
                    .into_iter()
                    .map(move |(n, _)| format!("{k}: {n}"))
            })
            .collect();
        let risky: Vec<&String> = exclusions
            .iter()
            .filter(|e| {
                let l = e.to_lowercase();
                l.ends_with(":\\")
                    || l.contains("\\temp")
                    || l.contains("\\appdata")
                    || l.contains("\\downloads")
                    || l.contains("\\users\\public")
                    || l.ends_with(".exe")
                    || l.contains("powershell")
            })
            .collect();
        if !risky.is_empty() {
            findings.push(
                Finding::new(
                    "security.defender_risky_exclusions",
                    Area::Security,
                    Severity::High,
                    "Defender excludes locations malware typically uses",
                )
                .evidence(risky.iter().map(|s| s.to_string()))
                .detail("Malware adds exclusions to hide from scans. Confirm with the user whether they added these."),
            );
        }
    } else {
        blind_spots.push("Defender exclusions need admin to read".into());
    }

    serde_json::json!({
        "defender": { "antivirus": av_on, "realtime": rtp_on, "signature_age_days": s.antivirus_signature_age, "quick_scan_age_days": s.quick_scan_age.filter(|a| *a != u32::MAX), "tamper_protection": s.is_tamper_protected },
        "other_antivirus": others,
    })
}

fn hijacks(findings: &mut Vec<Finding>) {
    let ifeo = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    for exe in reg::subkeys(ifeo) {
        if let Some(debugger) = reg::string(&format!("{ifeo}\\{exe}"), "Debugger") {
            // Process Explorer / System Informer legitimately replace Task Manager this way.
            let known = exe.eq_ignore_ascii_case("taskmgr.exe")
                && (debugger.to_lowercase().contains("procexp") || debugger.to_lowercase().contains("systeminformer"));
            findings.push(
                Finding::new(
                    format!("security.ifeo_debugger.{}", slug(&exe)),
                    Area::Security,
                    if known { Severity::Info } else { Severity::High },
                    format!("Launching {exe} is redirected to another program (IFEO Debugger)"),
                )
                .evidence([format!("{ifeo}\\{exe} Debugger = {debugger}")])
                .fix(
                    Fix::command(
                        Safety::Caution,
                        format!("reg delete {} /v Debugger /f", ps_literal(&format!("{ifeo}\\{exe}"))),
                    )
                    .admin(),
                ),
            );
        }
    }

    let winlogon = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    if let Some(shell) = reg::string(winlogon, "Shell").filter(|s| !s.trim().eq_ignore_ascii_case("explorer.exe")) {
        findings.push(
            Finding::new(
                "security.winlogon_shell",
                Area::Security,
                Severity::High,
                "Winlogon Shell is not explorer.exe",
            )
            .evidence([format!("{winlogon} Shell = {shell}")])
            .fix(
                Fix::command(Safety::Caution, format!("reg add \"{winlogon}\" /v Shell /t REG_SZ /d explorer.exe /f"))
                    .admin(),
            ),
        );
    }
    if let Some(userinit) = reg::string(winlogon, "Userinit") {
        let normal = userinit.trim().trim_end_matches(',').to_lowercase();
        if !normal.ends_with("\\system32\\userinit.exe") || normal.contains(',') {
            findings.push(
                Finding::new(
                    "security.winlogon_userinit",
                    Area::Security,
                    Severity::High,
                    "Winlogon Userinit launches extra programs at sign-in",
                )
                .evidence([format!("{winlogon} Userinit = {userinit}")]),
            );
        }
    }

    let windows = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
    if let Some(dlls) = reg::string(windows, "AppInit_DLLs").filter(|d| !d.trim().is_empty())
        && reg::dword(windows, "LoadAppInit_DLLs") == Some(1)
    {
        findings.push(
            Finding::new(
                "security.appinit_dlls",
                Area::Security,
                Severity::High,
                "AppInit_DLLs injects a DLL into every GUI process",
            )
            .evidence([dlls]),
        );
    }

    let policies = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    if reg::dword(policies, "EnableLUA") == Some(0) {
        findings.push(
            Finding::new("security.uac_disabled", Area::Security, Severity::High, "User Account Control is disabled")
                .detail("Every program runs with full admin rights without asking.")
                .fix(
                    Fix::command(Safety::Safe, format!("reg add \"{policies}\" /v EnableLUA /t REG_DWORD /d 1 /f"))
                        .admin()
                        .note("Requires a restart."),
                ),
        );
    } else if reg::dword(policies, "ConsentPromptBehaviorAdmin") == Some(0) {
        findings.push(
            Finding::new(
                "security.uac_no_prompt",
                Area::Security,
                Severity::Medium,
                "UAC elevates admin apps without asking",
            )
            .fix(
                Fix::command(
                    Safety::Safe,
                    format!("reg add \"{policies}\" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 5 /f"),
                )
                .admin(),
            ),
        );
    }

    if reg::dword(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen") == Some(0) {
        findings.push(Finding::new(
            "security.smartscreen_off",
            Area::Security,
            Severity::Medium,
            "SmartScreen is disabled by policy",
        ));
    }

    let fw = r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
    for (profile, severity) in
        [("PublicProfile", Severity::High), ("StandardProfile", Severity::Medium), ("DomainProfile", Severity::Low)]
    {
        if reg::dword(&format!("{fw}\\{profile}"), "EnableFirewall") == Some(0) {
            findings.push(
                Finding::new(
                    format!("security.firewall_off.{}", profile.to_lowercase()),
                    Area::Security,
                    severity,
                    format!("Windows Firewall is off for the {} profile", profile.trim_end_matches("Profile")),
                )
                .fix(
                    Fix::command(
                        Safety::Safe,
                        format!(
                            "Set-NetFirewallProfile -Profile {} -Enabled True",
                            profile.trim_end_matches("Profile").replace("Standard", "Private")
                        ),
                    )
                    .admin(),
                ),
            );
        }
    }

    let inet = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    let pac = reg::string(inet, "AutoConfigURL").filter(|s| !s.is_empty());
    let proxy =
        (reg::dword(inet, "ProxyEnable") == Some(1)).then(|| reg::string(inet, "ProxyServer").unwrap_or_default());
    if pac.is_some() || proxy.is_some() {
        let evidence: Vec<String> = pac
            .iter()
            .map(|p| format!("AutoConfigURL = {p}"))
            .chain(proxy.iter().map(|p| format!("ProxyServer = {p}")))
            .collect();
        let local = evidence.iter().all(|e| e.contains("127.0.0.1") || e.contains("localhost"));
        findings.push(
            Finding::new("security.proxy_configured", Area::Security, if local { Severity::Low } else { Severity::Medium }, "System proxy is configured for this user")
                .evidence(evidence)
                .detail("Normal on corporate networks or with dev tools (Fiddler, mitmproxy). Otherwise a classic way to intercept browsing."),
        );
    }
}

/// Domains malware blocks or redirects to keep a victim from updating or cleaning up.
const PROTECTED_DOMAINS: [&str; 16] = [
    "microsoft.com",
    "windowsupdate.com",
    "windows.com",
    "update.microsoft.com",
    "live.com",
    "office.com",
    "msftconnecttest.com",
    "google.com",
    "kaspersky.com",
    "avast.com",
    "avg.com",
    "eset.com",
    "malwarebytes.com",
    "virustotal.com",
    "bitdefender.com",
    "norton.com",
];

fn hosts_file(findings: &mut Vec<Finding>, blind_spots: &mut Vec<String>) -> usize {
    let path = std::path::PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()))
        .join(r"System32\drivers\etc\hosts");
    // Byte-tolerant: ANSI comments (accents) must not make the whole file "empty".
    let text = match std::fs::read(&path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(e) => {
            blind_spots.push(format!("hosts file unreadable: {e}"));
            return 0;
        }
    };
    let mut entries = 0;
    let mut tampered = Vec::new();
    let mut redirects = false;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut parts = line.split_whitespace();
        let Some(ip) = parts.next() else { continue };
        for host in parts.map(str::to_lowercase).filter(|h| h != "localhost") {
            entries += 1;
            let host = host.trim_end_matches('.');
            if PROTECTED_DOMAINS.iter().any(|d| host == *d || host.ends_with(&format!(".{d}"))) {
                let sinkhole = ip == "0.0.0.0" || ip.starts_with("127.") || ip == "::" || ip == "::1";
                redirects |= !sinkhole;
                tampered.push(format!("{ip} {host}"));
            }
        }
    }
    if !tampered.is_empty() {
        findings.push(
            Finding::new("security.hosts_tampered", Area::Security, if redirects { Severity::High } else { Severity::Medium }, "hosts file blocks or redirects security / Microsoft domains")
                .evidence(tampered.into_iter().take(10))
                .detail("Malware blocks antivirus and update sites this way (a redirect to another IP is worse than a block). Some privacy tools block telemetry domains too, and Defender flags that. Ask the user."),
        );
    }
    entries
}
#[derive(Serialize)]
struct Flagged {
    kind: &'static str,
    name: String,
    command: String,
    flags: Vec<&'static str>,
}

/// Unsigned/untrusted processes running from user-writable folders, plus how many processes' paths\n/// could not be read (protected or elevated processes, when not running as admin).
type FlaggedProcess = (String, std::path::PathBuf, Vec<&'static str>);

fn suspicious_processes() -> (Vec<FlaggedProcess>, usize) {
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet),
    );
    let unreadable = sys.processes().values().filter(|p| p.exe().is_none() && p.pid().as_u32() > 4).count();
    let mut candidates: Vec<(String, std::path::PathBuf)> = sys
        .processes()
        .values()
        .filter_map(|p| Some((p.name().to_string_lossy().into_owned(), p.exe()?.to_path_buf())))
        .filter(|(_, exe)| suspicious::user_writable(exe))
        .collect();
    candidates.sort();
    candidates.dedup();
    let flagged = candidates
        .into_par_iter()
        .filter_map(|(name, exe)| {
            let _t = trace::span_over(format!("security: slow signature {}", exe.display()), 250);
            let sig = sign::assess(&exe, true);
            let flags = suspicious::path_flags(&exe, Some(sig));
            (!matches!(sig, Signature::Valid)).then_some((name, exe, flags))
        })
        .collect();
    (flagged, unreadable)
}

pub fn collect(detail: bool) -> Section {
    let started = Instant::now();
    let mut findings = Vec::new();
    let mut blind_spots = Vec::new();

    let ((defender_data, def_findings, def_blind), ((procs, unreadable_procs), installed)) = rayon::join(
        || {
            let _t = trace::span("security: defender + security center (WMI)");
            let mut f = Vec::new();
            let mut b = Vec::new();
            let d = defender(&mut f, &mut b);
            (d, f, b)
        },
        || {
            rayon::join(
                || {
                    let _t = trace::span("security: processes + signatures");
                    suspicious_processes()
                },
                apps::installed,
            )
        },
    );
    findings.extend(def_findings);
    blind_spots.extend(def_blind);
    if unreadable_procs > 0 && !crate::elevated() {
        blind_spots.push(format!("{unreadable_procs} running processes could not be inspected without admin"));
    }
    hijacks(&mut findings);
    let hosts_entries = hosts_file(&mut findings, &mut blind_spots);
    findings.extend(apps::pup_findings(&installed));

    let inv = {
        let _t = trace::span("security: wait for startup inventory");
        startup::inventory()
    };
    let mut flagged = Vec::new();
    for item in &inv.items {
        if !item.enabled && item.kind != startup::Kind::Service {
            continue;
        }
        let Some(severity) = suspicious::severity(&item.flags) else { continue };
        findings.push(
            Finding::new(
                format!("security.autostart.{}", slug(&item.name)),
                Area::Security,
                severity,
                format!("Suspicious autostart ({:?}): {}", item.kind, item.name).replace("RunOnce", "run_once"),
            )
            .evidence([format!("flags: {}", item.flags.join(", ")), format!("{} -> {}", item.location, item.command)])
            .detail("Check the file with Defender before removing. Removing a legit entry only stops it auto-starting.")
            .fix(
                Fix::command(
                    Safety::Caution,
                    format!(
                        "Start-MpScan -ScanType CustomScan -ScanPath {}",
                        ps_literal(&item.image.as_ref().map(|p| p.display().to_string()).unwrap_or_default())
                    ),
                )
                .admin(),
            ),
        );
        flagged.push(Flagged {
            kind: "autostart",
            name: item.name.clone(),
            command: item.command.clone(),
            flags: item.flags.clone(),
        });
    }
    for (name, exe, flags) in &procs {
        let Some(severity) = suspicious::severity(flags) else { continue };
        findings.push(
            Finding::new(
                format!("security.process.{}", slug(name)),
                Area::Security,
                severity,
                format!("Running process from a user-writable folder without a valid signature: {name}"),
            )
            .evidence([exe.display().to_string(), format!("flags: {}", flags.join(", "))])
            .fix(
                Fix::command(
                    Safety::Safe,
                    format!("Start-MpScan -ScanType CustomScan -ScanPath {}", ps_literal(&exe.display().to_string())),
                )
                .admin(),
            ),
        );
        flagged.push(Flagged {
            kind: "process",
            name: name.clone(),
            command: exe.display().to_string(),
            flags: flags.clone(),
        });
    }

    let mut data = defender_data;
    data["hosts_entries"] = hosts_entries.into();
    data["flagged"] = flagged.len().into();
    if detail {
        data["flagged_items"] = serde_json::to_value(&flagged).expect("serializes");
    }
    let mut section = Section { data, findings, blind_spots, took_ms: started.elapsed().as_millis() as u64 };
    section.sort_findings();
    section
}
