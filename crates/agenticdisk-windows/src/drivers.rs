//! Driver health: devices with problems, superseded packages piling up in the DriverStore, kernel
//! drivers loaded from odd places and (with `full`) the third-party driver inventory.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use agenticdisk_core::action::ps_literal;
use agenticdisk_core::scan::{du, space_severity};
use agenticdisk_core::{Area, Bytes, Consent, Finding, Fix, Safety, Section, Severity};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{reg, suspicious};

#[derive(Deserialize)]
#[serde(rename = "Win32_PnPEntity", rename_all = "PascalCase")]
struct PnpEntity {
    name: Option<String>,
    #[serde(rename = "DeviceID")]
    device_id: Option<String>,
    config_manager_error_code: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename = "Win32_PnPSignedDriver", rename_all = "PascalCase")]
struct SignedDriver {
    device_name: Option<String>,
    driver_provider_name: Option<String>,
    driver_version: Option<String>,
    driver_date: Option<String>,
    device_class: Option<String>,
    inf_name: Option<String>,
}

fn problem_text(code: u32) -> (&'static str, Severity) {
    match code {
        1 | 18 | 19 => ("not configured correctly; reinstall the driver", Severity::Medium),
        3 | 39 => ("driver is corrupted or missing", Severity::High),
        10 => ("device cannot start", Severity::Medium),
        12 => ("not enough free resources", Severity::Medium),
        14 => ("needs a restart", Severity::Low),
        22 => ("disabled by the user", Severity::Info),
        // Mostly firmware-declared legacy devices (PS/2 keyboard/mouse on modern boards).
        24 => ("not present or not working", Severity::Info),
        28 => ("no driver installed", Severity::Medium),
        31 | 37 => ("driver failed to load", Severity::Medium),
        32 => ("driver service is disabled", Severity::Low),
        43 => ("stopped after reporting problems", Severity::Medium),
        52 => ("driver signature could not be verified", Severity::High),
        _ => ("device has a problem", Severity::Low),
    }
}

fn problem_devices(findings: &mut Vec<Finding>, blind_spots: &mut Vec<String>) -> usize {
    let query = "SELECT Name, DeviceID, ConfigManagerErrorCode FROM Win32_PnPEntity WHERE ConfigManagerErrorCode <> 0";
    let devices: Vec<PnpEntity> = match wmi::WMIConnection::new().and_then(|c| c.raw_query(query)) {
        Ok(d) => d,
        Err(e) => {
            blind_spots.push(format!("device problems unavailable (WMI): {e}"));
            return 0;
        }
    };
    for dev in &devices {
        let code = dev.config_manager_error_code.unwrap_or(0);
        let (text, severity) = problem_text(code);
        let name = dev.name.clone().unwrap_or_else(|| "Unknown device".into());
        let id = dev.device_id.clone().unwrap_or_default();
        let fix = match code {
            // Firmware-declared legacy devices: nothing to do, restarting them changes nothing.
            24 => None,
            22 => Some(
                Fix::command(Safety::Manual, format!("pnputil /enable-device {}", ps_literal(&id)))
                    .admin()
                    .note("Only if the user wants it back on."),
            ),
            28 | 1 | 18 => Some(Fix::manual(
                "Install the vendor driver (Windows Update > Advanced > Optional updates, or the manufacturer's site).",
            )),
            _ => Some(
                Fix::command(Safety::Caution, format!("pnputil /restart-device {}", ps_literal(&id)))
                    .admin()
                    .note("If it persists, reinstall or update the driver."),
            ),
        };
        let mut finding = Finding::new(
            format!("drivers.problem.{}", crate::startup::slug(&id)),
            Area::Drivers,
            severity,
            format!("{name}: {text} (code {code})"),
        )
        .evidence([id]);
        if let Some(fix) = fix {
            finding = finding.fix(fix);
        }
        findings.push(finding);
    }
    devices.len()
}

/// (provider, DriverVer date as yyyymmdd, version)
type InfVersion = (String, String, String);

/// Reads an INF (UTF-16 or ANSI) and returns its provider and DriverVer.
fn inf_version(path: &Path) -> Option<InfVersion> {
    let bytes = std::fs::read(path).ok()?;
    let text = if bytes.starts_with(&[0xFF, 0xFE]) {
        let (pairs, _) = bytes[2..].as_chunks::<2>();
        let wide: Vec<u16> = pairs.iter().map(|c| u16::from_le_bytes(*c)).collect();
        String::from_utf16_lossy(&wide)
    } else {
        String::from_utf8_lossy(&bytes).into_owned()
    };
    let mut section = String::new();
    let mut provider = String::new();
    let mut driver_ver = String::new();
    let mut strings: HashMap<String, String> = HashMap::new();
    for line in text.lines() {
        let line = line.split(';').next().unwrap_or("").trim();
        if line.starts_with('[') {
            section = line.trim_matches(['[', ']']).to_ascii_lowercase();
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim().trim_matches('"').to_string());
        match section.as_str() {
            "version" if k.eq_ignore_ascii_case("Provider") => provider = v,
            "version" if k.eq_ignore_ascii_case("DriverVer") => driver_ver = v,
            "strings" => {
                strings.insert(k.to_ascii_lowercase(), v);
            }
            _ => {}
        }
    }
    if let Some(token) = provider.strip_prefix('%').and_then(|p| p.strip_suffix('%')) {
        provider = strings.get(&token.to_ascii_lowercase()).cloned().unwrap_or(provider);
    }
    let (date, version) = driver_ver.split_once(',')?;
    let mut parts = date.trim().split('/');
    let (m, d, y) = (parts.next()?, parts.next()?, parts.next()?);
    let sortable = format!("{y:0>4}{m:0>2}{d:0>2}");
    Some((provider, sortable, version.trim().to_string()))
}

fn version_key(v: &str) -> Vec<u64> {
    v.split('.').map(|p| p.parse().unwrap_or(0)).collect()
}

fn fnv(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325, |h, b| (h ^ u64::from(*b)).wrapping_mul(0x100000001b3))
}

#[derive(Serialize)]
struct Superseded {
    oem_inf: String,
    package: String,
    provider: String,
    version: String,
    size: Bytes,
}

/// Packages for which a newer version of the same INF is also installed. Only oemNN.inf (third
/// party) packages can be removed; `pnputil` refuses ones still bound to a device.
fn superseded_packages(blind_spots: &mut Vec<String>) -> Vec<Superseded> {
    let root = PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()));
    let repo = root.join(r"System32\DriverStore\FileRepository");
    let Ok(read) = std::fs::read_dir(&repo) else {
        blind_spots.push("DriverStore not readable".into());
        return Vec::new();
    };
    let mut groups: HashMap<String, Vec<PathBuf>> = HashMap::new();
    for entry in read.flatten() {
        let name = entry.file_name().to_string_lossy().to_lowercase();
        let mut parts = name.rsplitn(3, '_');
        let (Some(_hash), Some(_arch), Some(inf)) = (parts.next(), parts.next(), parts.next()) else { continue };
        groups.entry(inf.to_string()).or_default().push(entry.path());
    }
    groups.retain(|_, dirs| dirs.len() > 1);
    if groups.is_empty() {
        return Vec::new();
    }

    let oem: HashMap<(usize, u64), String> = std::fs::read_dir(root.join("INF"))
        .map(|rd| {
            rd.flatten()
                .filter(|e| {
                    let n = e.file_name().to_string_lossy().to_lowercase();
                    n.starts_with("oem") && n.ends_with(".inf")
                })
                .filter_map(|e| {
                    let bytes = std::fs::read(e.path()).ok()?;
                    Some(((bytes.len(), fnv(&bytes)), e.file_name().to_string_lossy().into_owned()))
                })
                .collect()
        })
        .unwrap_or_default();

    let candidates: Vec<(String, PathBuf)> =
        groups.into_iter().flat_map(|(inf, dirs)| dirs.into_iter().map(move |d| (inf.clone(), d))).collect();
    let parsed: Vec<(String, PathBuf, Option<InfVersion>, Option<String>)> = candidates
        .into_par_iter()
        .map(|(inf, dir)| {
            let inf_path = dir.join(&inf);
            let version = inf_version(&inf_path);
            let oem_name = std::fs::read(&inf_path).ok().and_then(|b| oem.get(&(b.len(), fnv(&b))).cloned());
            (inf, dir, version, oem_name)
        })
        .collect();

    let mut by_inf: HashMap<String, Vec<(PathBuf, InfVersion, Option<String>)>> = HashMap::new();
    for (inf, dir, version, oem_name) in parsed {
        if let Some(v) = version {
            by_inf.entry(inf).or_default().push((dir, v, oem_name));
        }
    }
    // Packages bound to any device (present or not) are in use, whatever their date says.
    let in_use = bound_infs();
    let mut stale: Vec<(PathBuf, String, String, String)> = Vec::new();
    for (_, mut versions) in by_inf {
        versions.sort_by(|a, b| b.1.1.cmp(&a.1.1).then_with(|| version_key(&b.1.2).cmp(&version_key(&a.1.2))));
        // Keep the newest and the one before it: Device Manager's "Roll Back Driver" needs that one.
        for (dir, (provider, _, version), oem_name) in versions.into_iter().skip(2) {
            if let Some(oem_name) = oem_name.filter(|o| !in_use.contains(&o.to_ascii_lowercase())) {
                stale.push((dir, oem_name, provider, version));
            }
        }
    }
    let mut out: Vec<Superseded> = stale
        .into_par_iter()
        .map(|(dir, oem_inf, provider, version)| Superseded {
            size: Bytes(du(&dir).0),
            package: dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
            oem_inf,
            provider,
            version,
        })
        .collect();
    out.sort_unstable_by_key(|x| std::cmp::Reverse(x.size));
    out
}

/// oemNN.inf names bound to a device instance (Control\Class\{class}\NNNN\InfPath).
fn bound_infs() -> std::collections::HashSet<String> {
    let base = r"HKLM\SYSTEM\CurrentControlSet\Control\Class";
    reg::subkeys(base)
        .into_iter()
        .flat_map(|class| {
            let class_key = format!("{base}\\{class}");
            reg::subkeys(&class_key)
                .into_iter()
                .filter_map(move |inst| reg::string(&format!("{class_key}\\{inst}"), "InfPath"))
                .collect::<Vec<_>>()
        })
        .map(|inf| inf.to_ascii_lowercase())
        .collect()
}

/// Drivers with known exploitable flaws, abused to kill antivirus or gain kernel access
/// ("bring your own vulnerable driver"). Usually installed by hardware monitoring / RGB / OC tools.
const VULNERABLE_DRIVERS: [&str; 18] = [
    "winring0",
    "rtcore64",
    "rtcoremini64",
    "msio64",
    "msio32",
    "ntiolib",
    "gdrv",
    "asrdrv",
    "atillk64",
    "dbutil_2_3",
    "glckio2",
    "iqvw64e",
    "mhyprot2",
    "speedfan",
    "physmem",
    "winio64",
    "eneio64",
    "cpuz141",
];

fn vulnerable(image: &Path) -> bool {
    let file = image.file_stem().map(|s| s.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    VULNERABLE_DRIVERS.iter().any(|v| {
        file == *v
            || (file.starts_with(v) && file[v.len()..].chars().all(|c| c.is_ascii_digit() || c == '_' || c == 'x'))
    })
}

#[derive(Serialize)]
struct OddDriver {
    name: String,
    image: String,
    start: u32,
}

/// Kernel/file-system driver services: ones loading from outside the Windows folder, known
/// vulnerable drivers, and orphans whose file is gone (left by uninstalled tools such as CPU-Z).
fn kernel_services(findings: &mut Vec<Finding>) -> Vec<OddDriver> {
    let base = r"HKLM\SYSTEM\CurrentControlSet\Services";
    let mut out = Vec::new();
    for name in reg::subkeys(base) {
        let key = format!("{base}\\{name}");
        let Some(k) = reg::open(&key) else { continue };
        let kind: u32 = k.get_value("Type").unwrap_or(0);
        let start: u32 = k.get_value("Start").unwrap_or(4);
        if kind & 0x3 == 0 || start > 3 {
            continue;
        }
        let Ok(image_path) = k.get_value::<String, _>("ImagePath") else { continue };
        let Some(image) = suspicious::image_of(&image_path) else { continue };
        let slug = crate::startup::slug(&name);
        let exists = image.exists();
        if !exists && !suspicious::windows_dir(&image) {
            let in_temp = suspicious::user_writable(&image);
            findings.push(
                Finding::new(format!("drivers.orphan_service.{slug}"), Area::Drivers, if in_temp { Severity::Medium } else { Severity::Low }, format!("Driver service '{name}' points to a file that no longer exists"))
                    .evidence([format!("{key} ImagePath = {image_path}")])
                    .detail("Left behind by an uninstalled tool (hardware monitors extract drivers to %TEMP%). Harmless until something drops a file at that path, which is why it matters.")
                    .fix(Fix::command(Safety::Caution, format!("sc.exe delete {}", ps_literal(&name))).admin().consent(Consent::Software).note("Back up first: reg export the service key. Only for services whose file is really gone.")),
            );
        }
        if exists && vulnerable(&image) {
            findings.push(
                Finding::new(format!("drivers.vulnerable.{slug}"), Area::Security, if start <= 2 { Severity::High } else { Severity::Medium }, format!("Known-vulnerable kernel driver installed: {name}"))
                    .evidence([image.display().to_string()])
                    .detail("Malware abuses these drivers to disable antivirus or read kernel memory. They come with fan/RGB/overclocking tools; uninstall the tool or update it to a version without this driver.")
                    .fix(Fix::manual("Identify the tool that installed it (agenticdisk apps) and uninstall or update it.").consent(Consent::Software)),
            );
        }
        if suspicious::windows_dir(&image) {
            continue;
        }
        if suspicious::user_writable(&image) && exists {
            findings.push(
                Finding::new(format!("drivers.user_writable.{slug}"), Area::Security, Severity::High, format!("Kernel driver '{name}' loads from a user-writable folder"))
                    .evidence([image.display().to_string()])
                    .detail("Legitimate drivers live under the Windows folder. Check the file with Defender / VirusTotal before anything else."),
            );
        }
        out.push(OddDriver { name, image: image.display().to_string(), start });
    }

    let ci = r"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config";
    if reg::dword(ci, "VulnerableDriverBlocklistEnable") == Some(0) {
        findings.push(
            Finding::new("security.vulnerable_driver_blocklist_off", Area::Security, Severity::Medium, "Microsoft's vulnerable driver blocklist is turned off")
                .evidence([format!("{ci} VulnerableDriverBlocklistEnable = 0")])
                .fix(Fix::command(Safety::Caution, format!("reg add {} /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 1 /f", ps_literal(ci))).admin().note("Requires a restart. A driver on the blocklist will stop loading: check the 'vulnerable driver' findings first.")),
        );
    }
    let hvci = r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity";
    if reg::dword(hvci, "Enabled") == Some(0) {
        findings.push(
            Finding::new("security.memory_integrity_off", Area::Security, Severity::Low, "Memory integrity (HVCI) is off")
                .detail("Blocks kernel tampering by malicious drivers. Costs a few % in some games, and incompatible old drivers block turning it on (Windows Security > Device security lists them).")
                .fix(Fix::manual("Windows Security > Device security > Core isolation > Memory integrity.")),
        );
    }
    out
}
#[derive(Serialize)]
struct DriverRow {
    device: String,
    class: String,
    provider: String,
    version: String,
    date: String,
    inf: String,
}

fn third_party_inventory(findings: &mut Vec<Finding>, blind_spots: &mut Vec<String>) -> Vec<DriverRow> {
    let query = "SELECT DeviceName, DriverProviderName, DriverVersion, DriverDate, DeviceClass, InfName FROM Win32_PnPSignedDriver";
    let rows: Vec<SignedDriver> = match wmi::WMIConnection::new().and_then(|c| c.raw_query(query)) {
        Ok(r) => r,
        Err(e) => {
            blind_spots.push(format!("driver inventory unavailable (WMI): {e}"));
            return Vec::new();
        }
    };
    let mut out: Vec<DriverRow> = rows
        .into_iter()
        .filter(|r| r.driver_provider_name.as_deref().is_some_and(|p| !p.is_empty() && p != "Microsoft"))
        .map(|r| DriverRow {
            device: r.device_name.unwrap_or_default(),
            class: r.device_class.unwrap_or_default(),
            provider: r.driver_provider_name.unwrap_or_default(),
            version: r.driver_version.unwrap_or_default(),
            date: r
                .driver_date
                .as_deref()
                .and_then(|d| d.get(0..8))
                .map(|d| format!("{}-{}-{}", &d[0..4], &d[4..6], &d[6..8]))
                .unwrap_or_default(),
            inf: r.inf_name.unwrap_or_default(),
        })
        .collect();
    out.sort_by(|a, b| a.date.cmp(&b.date));
    let (year, _) = crate::system::now_year_month();
    let stale: Vec<&DriverRow> = out
        .iter()
        .filter(|r| matches!(r.class.as_str(), "NET" | "DISPLAY" | "MEDIA" | "BLUETOOTH" | "SCSIADAPTER" | "HDC"))
        .filter(|r| r.date.get(0..4).and_then(|y| y.parse::<i32>().ok()).is_some_and(|y| year - y >= 3))
        .collect();
    if !stale.is_empty() {
        findings.push(
            Finding::new("drivers.stale_core_drivers", Area::Drivers, Severity::Low, format!("{} network/display/audio/storage drivers are 3+ years old", stale.len()))
                .evidence(stale.iter().map(|r| format!("{} {} {} ({})", r.date, r.provider, r.device, r.version)))
                .fix(Fix::manual("Check the device or motherboard vendor for newer drivers; old network and storage drivers are a common cause of crashes and slow wake-up.")),
        );
    }
    out
}

pub fn collect(full: bool) -> Section {
    let started = Instant::now();
    let mut findings = Vec::new();
    let mut blind_spots = Vec::new();

    let (problems, (superseded, sup_blind)) = rayon::join(
        || {
            let mut f = Vec::new();
            let mut b = Vec::new();
            let _t = agenticdisk_core::trace::span("drivers: problem devices (WMI)");
            let n = problem_devices(&mut f, &mut b);
            (n, f, b)
        },
        || {
            let mut b = Vec::new();
            let _t = agenticdisk_core::trace::span("drivers: DriverStore superseded packages");
            (superseded_packages(&mut b), b)
        },
    );
    let (problem_count, problem_findings, problem_blind) = problems;
    findings.extend(problem_findings);
    blind_spots.extend(problem_blind);
    blind_spots.extend(sup_blind);

    let reclaim: u64 = superseded.iter().map(|s| s.size.0).sum();
    if reclaim >= 100 * 1024 * 1024 {
        // Export each package before deleting it, so any of them can be re-added with pnputil /add-driver.
        let backup = "$b = Join-Path $env:LOCALAPPDATA 'agenticdisk\\driver-backup'; New-Item -ItemType Directory -Force -Path $b | Out-Null";
        let steps = superseded.iter().map(|s| {
            format!("pnputil /export-driver {inf} $b; pnputil /delete-driver {inf}", inf = ps_literal(&s.oem_inf))
        });
        let cmd = std::iter::once(backup.to_string()).chain(steps).collect::<Vec<_>>().join("; ");
        findings.push(
            Finding::new("drivers.superseded_packages", Area::Cleanup, space_severity(reclaim), format!("{} old driver package versions kept in the DriverStore ({})", superseded.len(), Bytes(reclaim)))
                .evidence(superseded.iter().take(8).map(|s| format!("{} {} {} {} ({})", s.size, s.oem_inf, s.provider, s.version, s.package)))
                .reclaim(reclaim)
                .fix(Fix::command(Safety::Safe, cmd).admin().consent(Consent::Software).note("Packages bound to any device and the previous version of each driver are kept. Each one is exported to %LOCALAPPDATA%\\agenticdisk\\driver-backup first; pnputil also refuses (without /force) anything still in use.")),
        );
    }

    let odd = kernel_services(&mut findings);
    let inventory = if full { third_party_inventory(&mut findings, &mut blind_spots) } else { Vec::new() };

    let mut data = serde_json::json!({
        "problem_devices": problem_count,
        "superseded_packages": superseded.len(),
        "superseded_size": Bytes(reclaim),
        "drivers_outside_windows_dir": odd,
    });
    if full {
        data["superseded"] = serde_json::to_value(&superseded).expect("serializes");
        data["third_party"] = serde_json::to_value(&inventory).expect("serializes");
    }
    let mut section = Section { data, findings, blind_spots, took_ms: started.elapsed().as_millis() as u64 };
    section.sort_findings();
    section
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_ordering_is_numeric() {
        assert!(super::version_key("32.0.15.10") > super::version_key("32.0.15.9"));
    }
}
