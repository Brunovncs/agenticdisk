//! Machine identity and health: OS, hardware, volumes, memory, pending reboot, GPU driver age.

use std::time::Instant;

use agenticdisk_core::{Area, Bytes, Finding, Fix, Safety, Section, Severity};
use serde::{Deserialize, Serialize};
use sysinfo::{CpuRefreshKind, DiskKind, Disks, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

use crate::reg;

const NT: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
const GIB: u64 = 1024 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename = "Win32_VideoController", rename_all = "PascalCase")]
struct VideoController {
    name: Option<String>,
    driver_version: Option<String>,
    driver_date: Option<String>,
}

#[derive(Serialize)]
struct Volume {
    mount: String,
    fs: String,
    kind: &'static str,
    size: Bytes,
    free: Bytes,
    free_pct: u8,
}

#[derive(Serialize)]
struct Gpu {
    name: String,
    driver: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    driver_date: Option<String>,
}

/// Whether the volume holding `path` is a spinning disk (None when unknown).
pub fn is_rotational(path: &std::path::Path) -> Option<bool> {
    let disks = Disks::new_with_refreshed_list();
    let target = path.to_string_lossy().to_uppercase();
    disks
        .list()
        .iter()
        .filter(|d| target.starts_with(&d.mount_point().to_string_lossy().to_uppercase()))
        .max_by_key(|d| d.mount_point().as_os_str().len())
        .and_then(|d| match d.kind() {
            DiskKind::HDD => Some(true),
            DiskKind::SSD => Some(false),
            _ => None,
        })
}

pub fn os_name() -> String {
    let build: u32 = reg::string(NT, "CurrentBuild").and_then(|b| b.parse().ok()).unwrap_or(0);
    let mut product = reg::string(NT, "ProductName").unwrap_or_else(|| "Windows".into());
    // ProductName still says "Windows 10" on Windows 11.
    if build >= 22000 {
        product = product.replace("Windows 10", "Windows 11");
    }
    let display = reg::string(NT, "DisplayVersion").unwrap_or_default();
    let ubr = reg::dword(NT, "UBR").unwrap_or(0);
    format!("{product} {display} (build {build}.{ubr})")
}

/// "20240315000000.000000-000" -> (2024, 3)
fn cim_year_month(date: &str) -> Option<(i32, u32)> {
    Some((date.get(0..4)?.parse().ok()?, date.get(4..6)?.parse().ok()?))
}

fn months_since(year: i32, month: u32) -> i32 {
    let now = now_year_month();
    (now.0 - year) * 12 + now.1 as i32 - month as i32
}

pub fn now_year_month() -> (i32, u32) {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let days = (secs / 86_400) as i64;
    // Civil-from-days (Howard Hinnant), enough for month precision.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = (yoe + era * 400 + i64::from(month <= 2)) as i32;
    (year, month)
}

pub fn collect(detail: bool) -> Section {
    let started = Instant::now();
    let mut findings = Vec::new();
    let mut blind_spots = Vec::new();

    let mut sys = System::new();
    sys.refresh_memory();
    sys.refresh_cpu_list(CpuRefreshKind::nothing());
    let cpu = sys.cpus().first().map(|c| c.brand().trim().to_string()).unwrap_or_default();

    let disks = Disks::new_with_refreshed_list();
    let mut volumes = Vec::new();
    let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
    for disk in disks.list() {
        let size = disk.total_space();
        if size == 0 {
            continue;
        }
        let free = disk.available_space();
        let mount = disk.mount_point().display().to_string();
        let kind = match disk.kind() {
            DiskKind::SSD => "ssd",
            DiskKind::HDD => "hdd",
            _ => {
                if disk.is_removable() {
                    "removable"
                } else {
                    "unknown"
                }
            }
        };
        let free_pct = (free as f64 / size as f64 * 100.0).round() as u8;
        let is_system = mount.to_uppercase().starts_with(&system_drive.to_uppercase());
        if !disk.is_removable() && (free_pct < 10 || free < 15 * GIB) {
            let severity = if free_pct < 5 || free < 5 * GIB { Severity::High } else { Severity::Medium };
            findings.push(
                Finding::new(format!("system.low_space.{}", mount.trim_end_matches(['\\', ':']).to_lowercase()), Area::System, severity, format!("Volume {mount} is low on space: {} free of {} ({free_pct}%)", Bytes(free), Bytes(size)))
                    .detail("Plan the space goal for known reclaimable locations and build folders; a disk scan of the volume shows the full picture."),
            );
        }
        if is_system && kind == "hdd" {
            findings.push(
                Finding::new("system.hdd_system_drive", Area::System, Severity::Medium, "Windows runs from a spinning hard drive")
                    .detail("Boot, updates and app launches are several times slower than on an SSD; this is the single largest upgrade for this PC.")
                    .fix(Fix::manual("Hardware upgrade: clone the system drive to an SSD.")),
            );
        }
        volumes.push(Volume {
            mount,
            fs: disk.file_system().to_string_lossy().into_owned(),
            kind,
            size: Bytes(size),
            free: Bytes(free),
            free_pct,
        });
    }

    let total_mem = sys.total_memory();
    let used_mem = sys.used_memory();
    let mem_pct = if total_mem > 0 { (used_mem as f64 / total_mem as f64 * 100.0).round() as u8 } else { 0 };

    let mut top_memory: Vec<(String, u64)> = Vec::new();
    if detail || mem_pct >= 90 {
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing().with_memory().with_exe(UpdateKind::OnlyIfNotSet),
        );
        let mut by_name: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        for p in sys.processes().values() {
            *by_name.entry(p.name().to_string_lossy().into_owned()).or_default() += p.memory();
        }
        let mut list: Vec<_> = by_name.into_iter().collect();
        list.sort_unstable_by_key(|x| std::cmp::Reverse(x.1));
        top_memory = list.into_iter().take(8).collect();
    }
    if mem_pct >= 90 {
        findings.push(
            Finding::new(
                "system.memory_pressure",
                Area::System,
                Severity::Medium,
                format!("Memory is {mem_pct}% used ({} of {})", Bytes(used_mem), Bytes(total_mem)),
            )
            .evidence(top_memory.iter().map(|(name, mem)| format!("{} {name}", Bytes(*mem)))),
        );
    }

    let uptime_days = System::uptime() / 86_400;
    if uptime_days >= 14 {
        findings.push(
            Finding::new("system.long_uptime", Area::System, Severity::Low, format!("No restart in {uptime_days} days"))
                .detail("Pending updates, leaked memory and stuck drivers are only cleared by a restart (Fast Startup shutdowns do not count).")
                .fix(Fix::command(Safety::Caution, "Restart-Computer").note("Ask the user first: closes all apps.")),
        );
    }

    let reboot_keys = [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
    ];
    let pending: Vec<&str> = reboot_keys.into_iter().filter(|k| reg::open(k).is_some()).collect();
    if !pending.is_empty() {
        findings.push(
            Finding::new(
                "system.pending_reboot",
                Area::System,
                Severity::Medium,
                "Windows is waiting for a restart to finish installing updates",
            )
            .evidence(pending.iter().map(|k| k.to_string()))
            .fix(Fix::command(Safety::Caution, "Restart-Computer").note("Ask the user first: closes all apps.")),
        );
    }

    let mut gpus = Vec::new();
    let gpu_query = {
        let _t = agenticdisk_core::trace::span("system: GPU (WMI)");
        wmi::WMIConnection::new().and_then(|c| c.query::<VideoController>())
    };
    match gpu_query {
        Ok(list) => {
            for vc in list {
                let name = vc.name.unwrap_or_default();
                if name.contains("Basic Display") || name.contains("Remote") || name.contains("Virtual") {
                    continue;
                }
                let date = vc.driver_date.as_deref().and_then(cim_year_month);
                if let Some((y, m)) = date {
                    let age = months_since(y, m);
                    if age >= 12 {
                        findings.push(
                            Finding::new(format!("system.gpu_driver_age.{}", crate::startup::slug(&name)), Area::Drivers, Severity::Low, format!("{name} driver is {age} months old"))
                                .evidence([format!("version {} dated {y}-{m:02}", vc.driver_version.clone().unwrap_or_default())])
                                .fix(Fix::manual("Update from the GPU vendor (NVIDIA App / AMD Adrenalin / Intel Driver & Support Assistant), not Windows Update.")),
                        );
                    }
                }
                gpus.push(Gpu {
                    name,
                    driver: vc.driver_version.unwrap_or_default(),
                    driver_date: date.map(|(y, m)| format!("{y}-{m:02}")),
                });
            }
        }
        Err(e) => blind_spots.push(format!("GPU info unavailable (WMI): {e}")),
    }

    let mut data = serde_json::json!({
        "os": os_name(),
        "host": System::host_name().unwrap_or_default(),
        "elevated": crate::elevated(),
        "uptime_days": uptime_days,
        "cpu": cpu,
        "cores": System::physical_core_count(),
        "memory": { "total": Bytes(total_mem), "used_pct": mem_pct },
        "gpus": gpus,
        "volumes": volumes,
    });
    if detail {
        data["top_memory"] =
            top_memory.iter().map(|(n, m)| serde_json::json!({ "process": n, "memory": Bytes(*m) })).collect();
        data["hibernation"] =
            reg::dword(r"HKLM\SYSTEM\CurrentControlSet\Control\Power", "HibernateEnabled").map(|v| v == 1).into();
        data["fast_startup"] =
            reg::dword(r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power", "HiberbootEnabled")
                .map(|v| v == 1)
                .into();
    }

    let mut section = Section { data, findings, blind_spots, took_ms: started.elapsed().as_millis() as u64 };
    section.sort_findings();
    section
}
